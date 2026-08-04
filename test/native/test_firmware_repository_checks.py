from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from check_hot_paths import (
    check,
    inspect_server_sync_hot_paths,
    inspect_status_dependencies,
    inspect_status_handler,
    status_handler,
)
from report_build_memory import (
    create_report,
    parse_map,
    task_stacks,
)

BOUNDED_HANDLER = r"""
server_.on(
    "/api/v1/ui/status", HTTP_GET,
    [this](AsyncWebServerRequest *request) {
      auto lease = status_response_pool_.acquire();
      const CompactNetworkStatus network = network_.compactStatus();
      const auto result = serializeCompactUiStatus(snapshot, metadata,
                                                    lease.data(), lease.capacity());
      sendBoundedStatus(request, std::move(lease), result.bytes);
    });
"""


class HotPathLexerTests(unittest.TestCase):
    def test_nested_braces_comments_and_strings_do_not_end_handler(self) -> None:
        source = BOUNDED_HANDLER.replace(
            "auto lease",
            'const char *sample = "} // not a brace"; /* } */\n      auto lease',
        )
        handler = status_handler(source)
        self.assertIn("sendBoundedStatus", handler)
        self.assertEqual(inspect_status_handler(source), [])

    def test_dynamic_json_and_full_snapshots_are_rejected_in_route_only(self) -> None:
        source = BOUNDED_HANDLER + "\nJsonDocument allowed_elsewhere;\n"
        self.assertEqual(inspect_status_handler(source), [])
        unsafe = BOUNDED_HANDLER.replace(
            "auto lease = status_response_pool_.acquire();",
            "NetworkStatus full = network_.status(); JsonDocument document;",
        )
        details = " ".join(item.detail for item in inspect_status_handler(unsafe))
        self.assertIn("NetworkStatus", details)
        self.assertIn("JsonDocument", details)
        self.assertIn("full NetworkStatus", details)

    def test_missing_bounded_serializer_and_pool_are_rejected(self) -> None:
        unsafe = BOUNDED_HANDLER.replace("serializeCompactUiStatus", "writeStatus")
        unsafe = unsafe.replace("status_response_pool_.acquire()", "makeResponse()")
        rules = [item.rule for item in inspect_status_handler(unsafe)]
        self.assertEqual(rules.count("bounded-status-required"), 2)

    def test_transitive_authorization_rejects_snapshot_and_cookie_copies(self) -> None:
        source = (ROOT / "src" / "api" / "HttpApi.cpp").read_text(encoding="utf-8")
        self.assertEqual(inspect_status_dependencies(source), [])
        unsafe = source.replace(
            "if (network_.setupApActive()) {",
            "if (network_.status().setup_ap_active) {",
            1,
        ).replace(
            "const BoundedSessionCookie session_cookie = sessionCookie(request);",
            'const std::string session_cookie = cookieValue(request, "pm_session");',
            1,
        )
        details = " ".join(item.detail for item in inspect_status_dependencies(unsafe))
        self.assertIn("full NetworkStatus", details)
        self.assertIn("copying cookie parser", details)

    def test_transitive_response_requires_size_measurement_and_release(self) -> None:
        source = (ROOT / "src" / "api" / "HttpApi.cpp").read_text(encoding="utf-8")
        unsafe = source.replace("lease_.release();", "", 1).replace(
            "heap_after_response", "heap_after_construct"
        )
        details = " ".join(item.detail for item in inspect_status_dependencies(unsafe))
        self.assertIn("response-slot release", details)
        self.assertIn("heap measurement", details)

    def test_server_sync_recurring_paths_remain_bounded(self) -> None:
        self.assertEqual(inspect_server_sync_hot_paths(ROOT), [])

    def test_recurring_sync_documents_fail_closed_before_serialization(self) -> None:
        source = (ROOT / "src" / "network" / "ServerSync.cpp").read_text(
            encoding="utf-8"
        )
        paths = (
            (
                'metrics_.last_error = "reading_batch_json_document_overflow";',
                "const std::size_t written = serializeJson(document, body);",
            ),
            (
                'metrics_.last_error = "event_batch_json_document_overflow";',
                "const std::size_t written = serializeJson(document, body);",
            ),
            (
                "if (document.overflowed()) {\n    return false;\n  }",
                "const std::size_t written = serializeJson(document, output);",
            ),
        )
        cursor = 0
        for overflow_marker, serialization_marker in paths:
            overflow = source.find(overflow_marker, cursor)
            serialized = source.find(serialization_marker, overflow)
            self.assertGreaterEqual(overflow, 0)
            self.assertGreater(serialized, overflow)
            guard = source.rfind("if (document.overflowed())", cursor, serialized)
            self.assertGreaterEqual(guard, cursor)
            self.assertLess(guard, serialized)
            cursor = serialized + len(serialization_marker)

    def test_no_content_length_sentinel_uses_signed_guard(self) -> None:
        source = (ROOT / "src" / "network" / "ServerSync.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "const bool response_body_fits = sync_policy::responseBodyFitsBuffer(",
            source,
        )
        response_section = source[
            source.index("const int response_size = http.getSize();") :
        ]
        response_section = response_section[: response_section.index("return result;")]
        self.assertNotIn("static_cast<std::size_t>(response_size) >", response_section)

    def test_server_sync_guard_rejects_identity_and_event_string_churn(self) -> None:
        directory = ROOT / ".test-tmp" / "server-sync-hot-path-guard"
        shutil.rmtree(directory, ignore_errors=True)
        for relative in (
            "src/network/ServerSync.cpp",
            "src/network/ServerSync.h",
            "src/network/ServerSyncScratch.h",
            "src/storage/SdStorage.h",
        ):
            destination = directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = (ROOT / relative).read_text(encoding="utf-8")
            if relative.endswith("ServerSync.cpp"):
                source = source.replace(
                    "const CompactNetworkStatus network = network_.compactStatus();",
                    "const NetworkStatus network = network_.status();",
                ).replace(
                    'event["event_id"] = event_id.data();',
                    'event["event_id"] = boot_id + std::to_string(sequence);',
                    1,
                )
            destination.write_text(source, encoding="utf-8")
        try:
            details = " ".join(
                item.detail for item in inspect_server_sync_hot_paths(directory)
            )
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertIn("full NetworkStatus", details)
        self.assertIn("numeric event-ID allocation", details)


class BuildMemoryReportTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = ROOT / ".test-tmp"
        temporary_root.mkdir(exist_ok=True)
        self.directory = temporary_root / "firmware-repository-checks"
        shutil.rmtree(self.directory, ignore_errors=True)
        self.directory.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_map_totals_and_large_input_sections_are_deterministic(self) -> None:
        path = self.directory / "firmware.map"
        path.write_text(
            ".dram0.data 0x3fc80000 0x1000\n"
            " .bss.status_pool 0x3fc81000 0x800 object.o\n"
            ".dram0.bss 0x3fc82000 0x2000\n"
            ".iram0.text 0x40370000 0x3000\n"
            ".flash.text 0x42000020 0x4000\n"
            "                0x3d800000 _ext_ram_start = ABSOLUTE(.)\n",
            encoding="utf-8",
        )
        report = parse_map(path)
        self.assertIsNotNone(report)
        assert report is not None
        self.assertEqual(report.static_dram_bytes, 0x3000)
        self.assertEqual(report.iram_bytes, 0x3000)
        self.assertEqual(report.flash_bytes, 0x4000)
        self.assertEqual(report.large_sections[0]["section"], ".bss.status_pool")
        self.assertTrue(report.psram_related_lines)

    def test_task_expressions_and_report_are_json_serializable(self) -> None:
        (self.directory / "include" / "app").mkdir(parents=True)
        (self.directory / "include" / "app" / "TaskConfig.h").write_text(
            "inline constexpr std::uint32_t kOneStackBytes = 6U * 1024U;\n"
            "inline constexpr std::uint32_t kTwoStackBytes = 8192U;\n",
            encoding="utf-8",
        )
        (self.directory / "src" / "api").mkdir(parents=True)
        (self.directory / "src" / "network").mkdir(parents=True)
        (self.directory / "src" / "ui").mkdir(parents=True)
        (self.directory / "src" / "api" / "HttpApi.h").write_text(
            "StatusResponsePool<2U, 2048U> status_response_pool_;\n",
            encoding="utf-8",
        )
        (self.directory / "src" / "network" / "ServerSyncScratch.h").write_text(
            "kRequestCapacity = 20U * 1024U;\nkResponseCapacity = 24U * 1024U;\n",
            encoding="utf-8",
        )
        (self.directory / "src" / "ui" / "embedded_assets.h").write_text(
            "static const unsigned char asset[] = {0};\n", encoding="utf-8"
        )
        self.assertEqual(task_stacks(self.directory)["total_bytes"], 14336)
        encoded = json.dumps(create_report(self.directory, ("release",)))
        self.assertIn("compact_status_response_pool", encoded)
        self.assertIn("long_lived_psram_heap", encoded)


class RepositoryHotPathPolicyTests(unittest.TestCase):
    def test_compact_status_route_obeys_repository_policy(self) -> None:
        self.assertEqual(check(ROOT), [])

    def test_status_response_objects_use_bounded_storage(self) -> None:
        source = (ROOT / "src" / "api" / "HttpApi.cpp").read_text(encoding="utf-8")
        handler = status_handler(source)
        self.assertIn("ui_status_response_objects.acquire()", handler)
        self.assertIn("new (response_storage)", handler)
        self.assertNotIn("new (std::nothrow)", handler)
        self.assertIn("ui_status_response_objects.release(pointer)", source)

    def test_prebuilt_mbedtls_limit_and_bounded_alternative_are_explicit(self) -> None:
        document = (ROOT / "docs" / "MEMORY_AND_FRAGMENTATION.md").read_text(
            encoding="utf-8"
        )
        platform = (ROOT / "platformio.ini").read_text(encoding="utf-8")
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for directory in (ROOT / "src", ROOT / "include")
            for path in directory.rglob("*.*")
            if path.suffix in {".cpp", ".h"}
        )
        scratch = (ROOT / "src" / "network" / "ServerSyncScratch.h").read_text(
            encoding="utf-8"
        )
        policy = (ROOT / "src" / "network" / "ServerSyncPolicy.h").read_text(
            encoding="utf-8"
        )

        self.assertIn("prebuilt framework archives", document)
        self.assertIn("CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=16384", document)
        self.assertIn("CONFIG_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH is not set", document)
        self.assertIn("no `setBufferSizes` method", document)
        self.assertNotIn("CONFIG_MBEDTLS_DYNAMIC_BUFFER", platform)
        self.assertNotIn(".setBufferSizes(", sources)
        self.assertIn("kRequestCapacity = 20U * 1024U", scratch)
        self.assertIn("kResponseCapacity = 24U * 1024U", scratch)
        self.assertIn("kMaximumResponseBytes = 24U * 1024U", policy)


class RuntimeResourceRegressionTests(unittest.TestCase):
    def test_server_sync_stack_reclaims_dram_with_measured_margin(self) -> None:
        task_config = (ROOT / "include" / "app" / "TaskConfig.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("kServerSyncStackBytes = 20U * 1024U", task_config)
        # The physical 1.0.15 minimum was 14,612 unused bytes from 24 KiB.
        # Reclaiming 4 KiB therefore leaves 10,516 bytes (51%) on the same
        # measured path, well above the repository's mandatory 25% margin.
        measured_unused = 14_612
        reclaimed = 4 * 1024
        new_allocation = 20 * 1024
        projected_unused = measured_unused - reclaimed
        self.assertEqual(projected_unused, 10_516)
        self.assertGreaterEqual(
            projected_unused * 100 // new_allocation,
            25,
        )

    def test_tls_admission_guards_remain_64k_total_and_32k_contiguous(self) -> None:
        memory_policy = (
            ROOT / "include" / "core" / "MemoryPressurePolicy.h"
        ).read_text(encoding="utf-8")
        sync_policy = (ROOT / "src" / "network" / "ServerSyncPolicy.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("kTlsMinimumFreeInternalBytes = 64U * 1024U", memory_policy)
        self.assertIn(
            "kTlsMinimumLargestInternalBlockBytes =\n    32U * 1024U",
            memory_policy,
        )
        self.assertIn("kMinimumInternalHeapBytes = 64U * 1024U", sync_policy)
        self.assertIn("kMinimumLargestInternalBlockBytes = 32U * 1024U", sync_policy)

    def test_local_health_tls_ready_uses_its_current_heap_snapshot(self) -> None:
        source = (ROOT / "src" / "api" / "HttpApi.cpp").read_text(encoding="utf-8")
        start = source.index('"/api/local/health"')
        end = source.index('server_.on("/api/v1/info"', start)
        local_health = source[start:end]
        self.assertIn(
            "snapshot.tls_ready = memoryTlsReady(\n"
            "            heap.free_internal_bytes, heap.largest_internal_block_bytes,\n"
            "            heap.integrity_ok);",
            local_health,
        )
        self.assertNotIn("snapshot.tls_ready = pressure.tls_ready", local_health)

    def test_server_sync_runtime_metrics_report_the_created_core(self) -> None:
        source = (ROOT / "src" / "app" / "Application.cpp").read_text(encoding="utf-8")
        self.assertIn(
            '{"ServerSyncTask", sync_task_, task_config::kServerSyncStackBytes, 1,',
            source,
        )
        create_start = source.index(
            'xTaskCreatePinnedToCore(syncTaskEntry, "ServerSyncTask"'
        )
        create_end = source.index(";", create_start)
        self.assertIn("&sync_task_, 1)", source[create_start:create_end])


class StorageIntegrityRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "src" / "storage" / "SdStorage.cpp").read_text(
            encoding="utf-8"
        )
        rebuild_start = cls.source.index("bool SdStorage::rebuildIndexes()")
        rebuild_end = cls.source.index(
            "SegmentMetadata SdStorage::inspectSegment", rebuild_start
        )
        cls.rebuild = cls.source[rebuild_start:rebuild_end]
        recover_start = cls.source.index("bool SdStorage::recover()")
        recover_end = cls.source.index("bool SdStorage::recoverFile", recover_start)
        cls.recover = cls.source[recover_start:recover_end]

    def test_event_corruption_does_not_poison_reading_index_health(self) -> None:
        self.assertIn("bool reading_index_valid = true;", self.recover)
        self.assertIn("bool event_log_valid = true;", self.recover)
        self.assertIn("health_.index_healthy = reading_index_valid;", self.recover)
        self.assertIn("health_.event_log_healthy = event_log_valid;", self.recover)
        self.assertIn(
            "const SegmentMetadata inspected = inspectSegment(path);", self.recover
        )
        self.assertIn("inspected.index_valid", self.recover)
        event_failure = self.recover.index(
            'event_log_status = "event_record_corruption_detected";'
        )
        next_reading_assignment = self.recover.find(
            "reading_index_valid =", event_failure
        )
        self.assertEqual(next_reading_assignment, -1)

    def test_reading_index_rebuild_cannot_clear_event_fault(self) -> None:
        self.assertIn("health_.index_healthy = ok;", self.rebuild)
        self.assertNotIn("event_log_healthy =", self.rebuild)
        self.assertNotIn("event_log_integrity_status =", self.rebuild)
        self.assertIn("health_.event_log_integrity_status.c_str()", self.rebuild)

    def test_index_replacement_is_staged_verified_and_recoverable(self) -> None:
        for marker in (
            'index_path + ".rebuild"',
            'index_path + ".previous"',
            "const SegmentMetadata installed = inspectSegment(data_path);",
            '"INDEX_REBUILD_VERIFY_FAILED"',
            "action=restore_previous_index",
        ):
            self.assertIn(marker, self.rebuild)
        self.assertNotIn("SD.remove(data_path", self.rebuild)
        self.assertNotIn("/POWERMON/events", self.rebuild)
        self.assertNotIn("format", self.rebuild.lower())

    def test_interrupted_index_swap_restores_only_derived_artifacts(self) -> None:
        cleanup_start = self.source.index("bool SdStorage::recoverCleanupJournal()")
        cleanup_end = self.source.index(
            "bool SdStorage::removeSegmentTransactionally", cleanup_start
        )
        cleanup = self.source[cleanup_start:cleanup_end]
        index_artifact_start = cleanup.index("std::vector<std::string> index_backups;")
        index_artifact_end = cleanup.index(
            "if (!temporary_recovery_ok)", index_artifact_start
        )
        index_artifacts = cleanup[index_artifact_start:index_artifact_end]
        self.assertIn('collectFiles("/POWERMON/indexes", ".previous"', cleanup)
        self.assertIn('collectFiles("/POWERMON/indexes", ".rebuild"', cleanup)
        self.assertIn("SD.rename(backup.c_str(), target.c_str())", cleanup)
        self.assertNotIn("/POWERMON/events", index_artifacts)
        self.assertNotIn("/POWERMON/records", index_artifacts)

    def test_mount_never_formats_a_failed_card(self) -> None:
        self.assertIn(
            'SD.begin(pins::SD_CS, spi_, candidate_hz, "/sd", 8, false)',
            self.source,
        )
        self.assertIn('"format_on_failure=false"', self.source)


if __name__ == "__main__":
    unittest.main()

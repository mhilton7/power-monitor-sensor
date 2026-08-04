from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shutil
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
TEST_TEMP = ROOT / ".test-tmp" / "ota-v2"


def case_directory(name: str) -> Path:
    path = TEST_TEMP / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


from firmware_image import (
    ESP_APP_DESC_MAGIC,
    ESP_CHECKSUM_MAGIC,
    FirmwareImageError,
    inspect_firmware,
    patch_firmware_descriptor,
)


def hkdf_sha256(secret: bytes, salt: bytes, info: bytes) -> bytes:
    pseudorandom_key = hmac.new(salt, secret, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, info + b"\x01", hashlib.sha256).digest()


def synthetic_image() -> bytes:
    descriptor = bytearray(256)
    struct.pack_into("<I", descriptor, 0, ESP_APP_DESC_MAGIC)
    descriptor[16:48] = b"old-version\0" + bytes(20)
    descriptor[48:80] = b"arduino-lib-builder\0" + bytes(12)
    descriptor[80:96] = b"00:00:00\0" + bytes(7)
    descriptor[96:112] = b"Jan  1 2024\0" + bytes(4)
    descriptor[112:144] = b"idf-test\0" + bytes(23)
    segment_data = descriptor + bytearray(b"pm-protocol/1.0.0\0")
    segment_data.extend(bytes((-len(segment_data)) % 4))
    header = bytearray(24)
    struct.pack_into("<BBBBI", header, 0, 0xE9, 1, 0, 0, 0x40370000)
    struct.pack_into("<H", header, 12, 9)
    header[23] = 1
    image = header + struct.pack("<II", 0x3C000020, len(segment_data)) + segment_data
    checksum = ESP_CHECKSUM_MAGIC
    for byte in segment_data:
        checksum ^= byte
    checksum_offset = len(image) + (15 - (len(image) % 16))
    image.extend(bytes(checksum_offset - len(image)))
    image.append(checksum)
    image.extend(hashlib.sha256(image).digest())
    return bytes(image)


class OtaManifestVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = json.loads(
            (ROOT / "shared/auth-test-vectors/ota-manifest-v2.json").read_text(
                encoding="utf-8"
            )
        )

    def test_normative_hkdf_and_hmac_vector(self) -> None:
        key = hkdf_sha256(
            bytes.fromhex(self.vector["secret_hex"]),
            self.vector["hkdf_salt_utf8"].encode(),
            self.vector["hkdf_info_utf8"].encode(),
        )
        self.assertEqual(key.hex(), self.vector["derived_key_hex"])
        canonical = json.dumps(
            self.vector["manifest_without_hmac"],
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(canonical, self.vector["canonical_json_utf8"])
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(key, canonical.encode(), hashlib.sha256).digest()
            )
            .decode()
            .rstrip("=")
        )
        self.assertEqual(signature, self.vector["manifest_hmac_base64url"])

    def test_wrong_hmac_secret_device_and_manifest_tampering_fail(self) -> None:
        vector = self.vector
        canonical = vector["canonical_json_utf8"].encode()
        expected = vector["manifest_hmac_base64url"]

        def signature(secret: bytes, device_id: str, body: bytes) -> str:
            key = hkdf_sha256(
                secret,
                device_id.encode(),
                vector["hkdf_info_utf8"].encode(),
            )
            return (
                base64.urlsafe_b64encode(hmac.new(key, body, hashlib.sha256).digest())
                .decode()
                .rstrip("=")
            )

        secret = bytes.fromhex(vector["secret_hex"])
        self.assertNotEqual(
            signature(bytes(reversed(secret)), vector["device_id"], canonical),
            expected,
        )
        self.assertNotEqual(
            signature(secret, "123e4567-e89b-12d3-a456-426614174999", canonical),
            expected,
        )
        self.assertNotEqual(
            signature(
                secret,
                vector["device_id"],
                canonical.replace(b"1.0.11", b"1.0.12"),
            ),
            expected,
        )

    def test_bad_hmac_cannot_poison_recovery_before_authentication(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        flow = service[
            service.index("bool OtaService::applyFromManifestUrl") : service.index(
                "bool OtaService::parseManifest"
            )
        ]
        authentication = flow.index("if (!verifyManifest(manifest, error))")
        replay_check = flow.index("const ota_v2::RecoveryRecord prior = recovery_")
        recovery_commit = flow.index("recovery_ = {}")
        self.assertLess(authentication, replay_check)
        self.assertLess(replay_check, recovery_commit)
        rejection = flow[
            authentication : flow.index(
                "const ota_v2::RecoveryRecord prior = recovery_"
            )
        ]
        self.assertNotIn("persistState(", rejection)
        self.assertNotIn("postReport(", rejection)
        self.assertNotIn("recovery_ =", rejection)

    def test_post_boot_failure_defers_terminal_report_until_rollback(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        begin = service[
            service.index("bool OtaService::begin()") : service.index(
                "bool OtaService::runningImagePendingVerification"
            )
        ]
        validation = service[
            service.index(
                "ota_v2::RunningImageCheckResult OtaService::checkRunningImage"
            ) : service.index("bool OtaService::applyFromManifestUrl")
        ]
        deferred = re.compile(
            r"setState\(ota_v2::State::PostBootValidation,\s*"
            r'"post_boot_validation", \{\},\s*true, false\);'
        )
        self.assertRegex(begin, deferred)
        self.assertIn(
            'ota_v2::State::PostBootValidation, "post_boot_validation", {}, true,',
            validation,
        )
        self.assertIn("false);", validation)
        self.assertIn("return initiatePostBootRollback(failure_code);", validation)
        self.assertNotIn("ESP.restart()", validation)

    def test_local_initialization_has_a_bounded_non_rebooting_blocker(self) -> None:
        policy = (ROOT / "src/ota/OtaUpdatePolicy.cpp").read_text(encoding="utf-8")
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        classifier = policy[
            policy.index("classifyPostBootHealth") : policy.index(
                "const char *postBootHealthClassName"
            )
        ]
        self.assertIn("!evidence.storage_available", classifier)
        self.assertIn("!evidence.meter_hardware_available", classifier)
        self.assertIn("!evidence.network_initialized", classifier)
        self.assertIn("PostBootHealthClass::LocalInitializationBlocked", classifier)
        external = classifier[classifier.index("const bool external_degraded") :]
        self.assertNotIn("storage_available", external)
        self.assertNotIn("meter_hardware_available", external)
        self.assertNotIn("network_initialized", external)
        self.assertIn("!evidence.wifi_connected", external)
        self.assertIn("!evidence.time_trusted", external)
        self.assertIn("!evidence.server_reachable", external)

        validation = service[
            service.index(
                "ota_v2::RunningImageCheckResult OtaService::checkRunningImage"
            ) : service.index("bool OtaService::applyFromManifestUrl")
        ]
        blocker = validation[
            validation.index("PostBootAction::Block") : validation.index(
                "if (action != ota_v2::PostBootAction::Validate)"
            )
        ]
        self.assertIn("ota_post_boot_local_initialization_blocked", blocker)
        self.assertIn("ValidationBlocked", blocker)
        self.assertIn("reboot=false", blocker)
        self.assertIn("rollback=false", blocker)
        self.assertNotIn("initiatePostBootRollback", blocker)
        self.assertNotIn("ESP.restart", blocker)

        self.assertIn("kMinimumObservationMs = 30'000U", application)
        self.assertIn("kMaximumObservationMs = 60'000U", application)
        self.assertIn("meter_health.successes > 0U", application)
        self.assertIn("storage_coordinator_.queueRemount()", application)
        self.assertIn("network_initialization=%s", application)
        self.assertNotIn(
            'evidence.storage_available ? "available" : "external_degraded"',
            application,
        )

    def test_transient_manifest_failure_cannot_redirect_pending_report(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        self.assertGreaterEqual(
            service.count("reportMilestoneForState(recovery_.state)"), 2
        )
        self.assertNotIn("reportMilestoneForState(status().state)", service)
        self.assertIn(
            "const std::string &failure_code = recovery_.failure_code;", service
        )

    def test_ota_uses_one_bounded_tls_lease_per_transaction(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        workflow = service[
            service.index("bool OtaService::applyFromManifestUrl") : service.index(
                "bool OtaService::parseManifest"
            )
        ]
        self.assertNotIn("OtaMemoryLease", service)
        self.assertNotIn("OtaTransactionLease", workflow)
        for function in ("fetchText", "downloadAndApply", "postReport"):
            start = service.index(f"bool OtaService::{function}")
            section = service[start : service.find("\nbool OtaService::", start + 1)]
            self.assertIn("OtaTransactionLease lease", section)
            self.assertIn("lease.activate", section)
        flush = service[
            service.index(
                "bool OtaService::flushPendingReportWithLease"
            ) : service.index("void OtaService::markPendingReportDelivered")
        ]
        self.assertNotIn("for (", flush)
        self.assertEqual(flush.count("postReport("), 1)

    def test_binary_transport_is_destroyed_before_update_finalization(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        section = service[
            service.index("bool OtaService::downloadAndApply") : service.index(
                "bool OtaService::postReport"
            )
        ]
        destroyed = section.index("Stage::HttpTransportDestroyed")
        finalize = section.index("Update.end(true)")
        self.assertLess(destroyed, finalize)
        self.assertIn(
            "flash finalization never\n  // competes with a retained HTTP/TLS object graph",
            section,
        )

    def test_ota_stream_buffer_is_scoped_internal_memory_not_task_stack(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        task_config = (ROOT / "include/app/TaskConfig.h").read_text(encoding="utf-8")
        section = service[
            service.index("bool OtaService::downloadAndApply") : service.index(
                "bool OtaService::postReport"
            )
        ]
        self.assertIn("kOtaStreamBufferBytes = 4096U", service)
        self.assertIn("MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT", service)
        self.assertIn("heap_caps_free(data_)", service)
        self.assertIn('error = "ota_internal_stream_buffer_unavailable"', section)
        self.assertNotIn("std::array<std::uint8_t, 4096U> buffer", section)
        self.assertIn("kMaintenanceStackBytes = 16U * 1024U", task_config)

    def test_fault_injection_covers_each_major_ota_stream_boundary(self) -> None:
        policy = (ROOT / "src/ota/OtaFaultInjection.h").read_text(encoding="utf-8")
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        for point in (
            "BeforeFirstByte",
            "AfterMetadata",
            "AfterUpdateBegin",
            "HalfwayThroughDownload",
            "AfterCompleteDownload",
            "BeforeUpdateEnd",
            "AfterUpdateEnd",
            "BeforeReboot",
            "BeforeRecoveryPersist",
            "AfterRecoveryPersist",
            "BeforeRecoveryReadback",
            "RecoveryReadbackMismatch",
            "AfterBootPartitionSelect",
            "BeforePostBootValidation",
            "BeforeMarkValid",
            "MarkValidFailure",
            "BeforeRollbackMark",
            "RollbackMarkFailure",
        ):
            self.assertIn(point, policy)
            self.assertIn(f"Point::{point}", service)

    def test_recovery_is_read_back_and_partition_is_verified_before_reboot(
        self,
    ) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        recovery = (ROOT / "src/ota/OtaRecoveryStore.cpp").read_text(encoding="utf-8")
        workflow = service[
            service.index("bool OtaService::applyFromManifestUrl") : service.index(
                "bool OtaService::parseManifest"
            )
        ]
        self.assertIn("saveAndVerify", recovery)
        self.assertIn("recoveryRecordsEqual(record, readback)", recovery)
        self.assertLess(
            workflow.index("verifyRecoveryBeforeReboot(error)"),
            workflow.index("ESP.restart()"),
        )
        download = service[
            service.index("bool OtaService::downloadAndApply") : service.index(
                "bool OtaService::verifySelectedBootPartition"
            )
        ]
        self.assertLess(
            download.index("verifySelectedBootPartition"),
            download.index("Stage::BootPartitionSelected"),
        )
        verifier = service[
            service.index(
                "bool OtaService::verifySelectedBootPartition"
            ) : service.index("bool OtaService::verifyRecoveryBeforeReboot")
        ]
        for evidence in (
            "expected_address",
            "expected_label",
            "expected_subtype",
            "expected_size",
            "selected_not_running",
            "selected_state_new",
            "descriptorHash",
        ):
            self.assertIn(evidence, verifier)

    def test_fail_closed_restores_running_partition_and_never_blind_restarts(
        self,
    ) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        restoration = service[
            service.index(
                "bool OtaService::restoreRunningBootPartition"
            ) : service.index(
                "ota_v2::RunningImageCheckResult OtaService::initiatePostBootRollback"
            )
        ]
        self.assertIn("esp_ota_set_boot_partition(running)", restoration)
        self.assertIn("ota_boot_partition_restore_mismatch", restoration)
        self.assertNotIn("ESP.restart()", restoration)
        rollback = service[
            service.index(
                "ota_v2::RunningImageCheckResult OtaService::initiatePostBootRollback"
            ) : service.index("bool OtaService::postReport")
        ]
        self.assertIn("esp_ota_mark_app_invalid_rollback_and_reboot()", rollback)
        self.assertIn("RollbackMarkFailed", rollback)
        self.assertNotIn("ESP.restart()", rollback)

        manual_rollback = service[
            service.index(
                "ota_v2::RollbackResult OtaService::rollbackAndReboot"
            ) : service.index("bool OtaService::pendingReport")
        ]
        mark_call = manual_rollback.index("const esp_err_t result")
        self.assertNotIn("State::RolledBack", manual_rollback)
        self.assertIn("State::Rebooting", manual_rollback[:mark_call])
        self.assertIn("manual_rollback_pending", manual_rollback[:mark_call])
        self.assertIn("State::Failed", manual_rollback)
        self.assertIn("manual_rollback_mark_failed", manual_rollback)
        self.assertIn("rollback_confirmed=false", manual_rollback)
        self.assertNotIn("flushPendingReport", manual_rollback[:mark_call])
        self.assertNotIn("ESP.restart()", manual_rollback)

    def test_ota_report_has_a_fixed_allocation_bound(self) -> None:
        header = (ROOT / "src/ota/OtaService.h").read_text(encoding="utf-8")
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        report = service[service.index("bool OtaService::reportJson") :]
        self.assertIn("kOtaReportMaximumBytes = 2048U", header)
        self.assertIn("BoundedJsonWriter writer", report)
        self.assertNotIn("DynamicJsonDocument", report)

    def test_ota_recovery_state_is_serialized_across_workflow_and_reporting(
        self,
    ) -> None:
        header = (ROOT / "src/ota/OtaService.h").read_text(encoding="utf-8")
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        self.assertIn("xSemaphoreCreateRecursiveMutex()", service)
        self.assertIn("workflow_mutex_ -> mutex_", header)
        for signature in (
            "bool OtaService::begin()",
            "ota_v2::RunningImageCheckResult OtaService::checkRunningImage(",
            "bool OtaService::applyFromManifestUrl(",
            "ota_v2::RollbackResult OtaService::rollbackAndReboot()",
            "bool OtaService::pendingReport(std::string &body) const",
            "bool OtaService::flushPendingReport()",
            "void OtaService::markPendingReportDelivered()",
        ):
            start = service.index(signature)
            guarded_prefix = service[start : start + 900]
            self.assertIn(
                "OtaWorkflowLock workflow_lock(workflow_mutex_",
                guarded_prefix,
                msg=f"{signature} must serialize recovery_ access",
            )

    def test_pending_candidate_rolls_back_before_production_bootstrap(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        begin = service[
            service.index("bool OtaService::begin()") : service.index(
                "bool OtaService::runningImagePendingVerification"
            )
        ]
        self.assertIn("if (pending_image) {", begin)
        self.assertIn("initiatePostBootRollback(failure_code)", begin)
        self.assertIn("running_pending && !recovered.pending_reboot", begin)
        self.assertIn('failure_code = "ota_post_boot_recovery_missing"', begin)
        self.assertIn("PRE_SERVICE_IDENTITY_ROLLBACK", begin)
        self.assertIn("return false;", begin)
        self.assertIn("classifyPreServiceRecovery(rollback_result)", begin)
        self.assertIn("persistRestrictedIncident(failure_code", begin)
        self.assertIn("enterRestrictedRecovery(failure_code", begin)
        self.assertLess(
            application.index("ota_.begin()"), application.index("storage_.begin(")
        )
        self.assertLess(
            application.index("ota_.begin()"), application.index("network_.begin()")
        )

    def test_automatic_rollback_uses_only_durable_authenticated_report_state(
        self,
    ) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        rollback = service[
            service.index(
                "ota_v2::RunningImageCheckResult OtaService::initiatePostBootRollback"
            ) : service.index("bool OtaService::postReport")
        ]
        self.assertIn("report_pending_.store(recoverySaved(persisted)", rollback)
        self.assertIn(
            'State::Failed, "post_boot_failed", failure_code, true, true', rollback
        )

    def test_unverifiable_pending_image_starts_only_restricted_recovery(
        self,
    ) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        store = (ROOT / "src/ota/OtaRecoveryStore.cpp").read_text(encoding="utf-8")
        policy = (ROOT / "src/ota/OtaUpdatePolicy.cpp").read_text(encoding="utf-8")
        http_api = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        restricted = application[
            application.index(
                "bool Application::beginRestrictedRecovery()"
            ) : application.index("void Application::meterTaskEntry")
        ]
        self.assertIn("RestrictedLocalRecovery", policy)
        self.assertIn("kOtaRestrictedIncidentSlots", store)
        self.assertIn("saveRestrictedIncidentAndVerify", store)
        self.assertIn("loadActive(store, kOtaRestrictedIncidentSlots", store)
        self.assertIn("restricted_recovery_mode_.store(true", service)
        self.assertIn("restricted_incident_durable", service)
        self.assertIn("restricted_failure_code", service)
        self.assertIn("createRestrictedRecoveryTasks()", restricted)
        self.assertNotIn("storage_.begin(", restricted)
        self.assertNotIn("storage_coordinator_.begin(", restricted)
        self.assertNotIn("meter_->begin(", restricted)
        self.assertNotIn("ServerSync", restricted)
        self.assertNotIn("sync_ =", restricted)
        self.assertIn("http_->begin()", restricted)
        task_set = application[
            application.index("bool Application::createRestrictedRecoveryTasks()") :
        ]
        self.assertIn('"NetworkTask"', task_set)
        self.assertIn('"OtaMaintenanceTask"', task_set)
        self.assertIn('"SerialCommandTask"', task_set)
        for forbidden in (
            '"MeterTask"',
            '"AggregationTask"',
            '"StorageTask"',
            '"ServerSyncTask"',
            '"HealthTask"',
        ):
            self.assertNotIn(forbidden, task_set)
        self.assertIn("ota_.restrictedRecoveryMode()", http_api)
        self.assertIn('request_path == "/api/v1/actions/rollback-ota"', http_api)
        self.assertIn('request_path == "/api/v1/ota/apply"', http_api)
        self.assertIn('"ota_restricted_recovery_active"', http_api)
        self.assertIn(
            "restrictedRecoveryMode() && esp_ota_check_rollback_is_possible()",
            service,
        )
        self.assertIn("ota_restricted_rollback_must_be_resolved", service)
        self.assertIn("rollback_image_must_be_preserved", service)
        self.assertNotIn("degraded_local_ap_available", restricted)

    def test_report_ack_preserves_remaining_replay_and_evidence_order(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        manifest = (ROOT / "src/ota/OtaManifestV2.cpp").read_text(encoding="utf-8")
        header = (ROOT / "src/ota/OtaManifestV2.h").read_text(encoding="utf-8")
        heartbeat = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        post_report = service[
            service.index("bool OtaService::postReport") : service.index(
                "bool OtaService::configureTls"
            )
        ]
        persist = service[
            service.index(
                "OtaRecoveryStoreResult OtaService::persistState"
            ) : service.index("OtaRecoveryStoreResult OtaService::setState")
        ]
        self.assertIn(
            "nextReportMilestone(recovery_.last_report_state, desired)", post_report
        )
        self.assertNotIn(
            "recovery_ = candidate;\n  report_pending_.store(false", post_report
        )
        self.assertIn("std::uint64_t evidence_sequence", header)
        self.assertIn('document["evidence_sequence"]', manifest)
        self.assertIn("++candidate.evidence_sequence", persist)
        self.assertIn("EvidenceSequenceExhausted", persist)
        self.assertLess(
            persist.index("++candidate.evidence_sequence"),
            persist.index("recovery_store_.saveAndVerify(candidate)"),
        )
        self.assertIn('writer.literal(",\\"evidence_sequence\\":")', service)
        self.assertIn('ota_recovery["deployment_id"]', heartbeat)
        self.assertIn('ota_recovery["attempt"]', heartbeat)
        self.assertIn('ota_recovery["evidence_sequence"]', heartbeat)
        self.assertIn("ota_stage::currentEvidenceSequence()", heartbeat)

    def test_waiting_for_schedule_is_a_distinct_optional_report(self) -> None:
        policy = (ROOT / "src/ota/OtaUpdatePolicy.cpp").read_text(encoding="utf-8")
        contract = (ROOT / "shared/openapi/server-ingest-api.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'case State::WaitingForSchedule: return "waiting_for_schedule";', policy
        )
        self.assertIn('desired == "waiting_for_schedule"', policy)
        self.assertIn(
            "manifest_authenticated, waiting_for_schedule, download_started", contract
        )

    def test_index_rebuild_readback_checks_every_authoritative_row(self) -> None:
        storage = (ROOT / "src/storage/SdStorage.cpp").read_text(encoding="utf-8")
        rebuild = storage[
            storage.index("bool SdStorage::rebuildIndexes()") : storage.index(
                "SegmentMetadata SdStorage::inspectSegment"
            )
        ]
        self.assertIn("File authoritative", rebuild)
        self.assertIn("record::decodeEnvelope(source_line", rebuild)
        self.assertIn('document["start_utc_ms"]', rebuild)
        self.assertIn("verified_offset", rebuild)
        self.assertIn("source_checksum", rebuild)
        self.assertIn("staged_line.compare", rebuild)
        self.assertIn("staged_has_extra", rebuild)
        self.assertLess(
            rebuild.index("staged_line.compare"),
            rebuild.index("SD.rename(staged_path.c_str(), index_path.c_str())"),
        )


class FirmwareDescriptorTests(unittest.TestCase):
    def test_patch_recomputes_descriptor_checksum_and_appended_sha(self) -> None:
        root = case_directory("descriptor-patch")
        try:
            firmware = root / "firmware.bin"
            elf = root / "firmware.elf"
            firmware.write_bytes(synthetic_image())
            elf.write_bytes(b"deterministic synthetic ELF")
            metadata = patch_firmware_descriptor(
                firmware,
                elf,
                version="1.0.11",
                build_time="20:00:00",
                build_date="Aug  2 2026",
            )
            self.assertEqual(metadata.project_name, "power-monitor-sensor")
            self.assertEqual(metadata.version, "1.0.11")
            self.assertEqual(
                metadata.build_hash, hashlib.sha256(elf.read_bytes()).hexdigest()
            )
            self.assertEqual(inspect_firmware(firmware), metadata)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_strict_gate_rejects_corruption_truncation_and_extra_bytes(self) -> None:
        root = case_directory("strict-corruption-gate")
        try:
            firmware = root / "firmware.bin"
            elf = root / "firmware.elf"
            firmware.write_bytes(synthetic_image())
            elf.write_bytes(b"ELF")
            patch_firmware_descriptor(
                firmware,
                elf,
                version="1.0.11",
                build_time="20:00:00",
                build_date="Aug  2 2026",
            )
            valid = firmware.read_bytes()
            cases = {
                "firmware_image_invalid": bytes([0]) + valid[1:],
                "firmware_wrong_target": valid[:12] + b"\x05\x00" + valid[14:],
                "firmware_image_truncated": valid[:-40],
                "firmware_image_extra_bytes": valid + b"x",
                "firmware_checksum_invalid": (
                    valid[:40] + bytes([valid[40] ^ 1]) + valid[41:]
                ),
            }
            for expected, damaged in cases.items():
                firmware.write_bytes(damaged)
                with (
                    self.subTest(expected=expected),
                    self.assertRaisesRegex(FirmwareImageError, expected),
                ):
                    inspect_firmware(firmware)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_ota_sources_preserve_configuration_sequence_and_storage(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        recovery = (ROOT / "src/ota/OtaRecoveryStore.cpp").read_text(encoding="utf-8")
        for forbidden in (
            "factoryReset(",
            "networkReset(",
            "setServerAckSequence(",
            "setServerMaximumSeenSequence(",
            "SdStorage",
            "microSD",
        ):
            self.assertNotIn(forbidden, service)
        self.assertIn('kPersistentPartition[] = "pmconfig"', recovery)
        self.assertIn('kOtaRecoverySlots{"ota_a", "ota_b",', recovery)


if __name__ == "__main__":
    unittest.main()

import hashlib
import hmac
import json
import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def hkdf_sha256(secret: bytes, salt: bytes, info: bytes) -> bytes:
    salt_value = salt or bytes(32)
    pseudorandom_key = hmac.new(salt_value, secret, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, info + b"\x01", hashlib.sha256).digest()


class DataResetReceiptContractTests(unittest.TestCase):
    def test_shared_receipt_vector_and_firmware_context_match(self) -> None:
        vector = json.loads(
            (ROOT / "shared/auth-test-vectors/data-reset-receipt-v1.json").read_text(
                encoding="utf-8"
            )
        )
        secret = bytes.fromhex(vector["secret_hex"])
        directional = hkdf_sha256(
            secret, b"", vector["directional_hkdf_info_utf8"].encode()
        )
        self.assertEqual(directional.hex(), vector["directional_key_hex"])
        receipt_key = hkdf_sha256(
            directional,
            vector["receipt_hkdf_salt_utf8"].encode(),
            vector["receipt_hkdf_info_utf8"].encode(),
        )
        self.assertEqual(receipt_key.hex(), vector["receipt_key_hex"])
        canonical = json.dumps(
            vector["receipt_without_digest"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        self.assertEqual(canonical, vector["canonical_json_utf8"])
        self.assertEqual(
            hmac.new(receipt_key, canonical.encode(), hashlib.sha256).hexdigest(),
            vector["receipt_digest_hex"],
        )
        completion = vector["completion_receipt_without_digest"]
        completion_canonical = json.dumps(
            completion,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        self.assertEqual(
            completion_canonical, vector["completion_canonical_json_utf8"]
        )
        self.assertEqual(
            hmac.new(
                receipt_key, completion_canonical.encode(), hashlib.sha256
            ).hexdigest(),
            vector["completion_receipt_digest_hex"],
        )
        self.assertEqual(completion["local_records_after"], 0)
        self.assertEqual(completion["backlog_after"], 0)
        self.assertIs(completion["queues_cleared"], True)
        self.assertIs(completion["exports_cleared"], True)
        self.assertIs(completion["indexes_rebuilt"], True)
        self.assertIsInstance(completion["records_deleted"], int)

        for field in (
            "newest_stored_sequence",
            "newest_syncable_sequence",
            "prepared_pzem_energy_wh",
            "software_energy_baseline_before_wh",
        ):
            self.assertIn(field, vector["receipt_without_digest"])
            self.assertIsInstance(vector["receipt_without_digest"][field], int)
        self.assertIsInstance(vector["receipt_without_digest"]["sd_status"], str)
        self.assertRegex(
            vector["receipt_without_digest"][
                "configuration_preservation_digest_before"
            ],
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(
            completion["configuration_preservation_digest_before"],
            completion["configuration_preservation_digest_after"],
        )
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('"pm-data-reset-receipt-v1"', coordinator)
        self.assertIn('"pm-device-to-server-v1"', (
            ROOT / "src/config/ConfigService.cpp"
        ).read_text(encoding="utf-8"))

    def test_receipts_are_redacted(self) -> None:
        builder = (ROOT / "src/reset/DataResetReceipt.cpp").read_text(
            encoding="utf-8"
        )
        prepared_source = builder[
            builder.index("buildPreparedReceiptCanonical(") : builder.index(
                "buildCommitReceiptCanonical("
            )
        ]
        completion_source = builder[builder.index("buildCommitReceiptCanonical(") :]
        vector = json.loads(
            (ROOT / "shared/auth-test-vectors/data-reset-receipt-v1.json").read_text(
                encoding="utf-8"
            )
        )
        prepared_keys = re.findall(r'receipt\["([a-z_]+)"\]', prepared_source)
        completion_keys = re.findall(
            r'receipt\["([a-z_]+)"\]', completion_source
        )
        prepared_unique_keys = list(dict.fromkeys(prepared_keys))
        completion_unique_keys = list(dict.fromkeys(completion_keys))
        self.assertEqual(prepared_unique_keys, sorted(prepared_unique_keys))
        self.assertEqual(completion_unique_keys, sorted(completion_unique_keys))
        self.assertEqual(
            set(prepared_unique_keys), set(vector["receipt_without_digest"])
        )
        self.assertEqual(
            set(completion_unique_keys),
            set(vector["completion_receipt_without_digest"]),
        )

    def test_device_routes_are_exactly_hmac_only(self) -> None:
        contract = yaml.safe_load(
            (ROOT / "shared/openapi/device-api.yaml").read_text(encoding="utf-8")
        )
        expected = {
            "/api/v1/data-reset/prepare": "post",
            "/api/v1/data-reset/commit": "post",
            "/api/v1/data-reset/status": "get",
            "/api/v1/data-reset/cancel": "post",
        }
        for route, method in expected.items():
            self.assertEqual(
                contract["paths"][route][method]["security"],
                [{"deviceHmac": []}],
            )
        prepare = contract["components"]["schemas"]["DataResetPrepareRequest"]
        self.assertFalse(prepare["additionalProperties"])
        self.assertEqual(
            set(prepare["required"]),
            {
                "protocol",
                "operation_id",
                "device_id",
                "target_generation",
                "reset_timestamp",
                "plan_revision",
                "plan_digest",
                "categories",
                "expected_boundary",
                "server_highest_contiguous",
                "server_maximum_seen",
                "expected_firmware_version",
                "expected_build_hash",
                "expected_card_generation",
            },
        )
        maximum_boundary = 9_223_372_036_854_775_805
        self.assertEqual(
            prepare["properties"]["reset_timestamp"]["pattern"], "Z$"
        )
        for field in (
            "expected_boundary",
            "server_highest_contiguous",
            "server_maximum_seen",
        ):
            self.assertEqual(
                prepare["properties"][field]["maximum"], maximum_boundary
            )
        commit = contract["components"]["schemas"]["DataResetCommitRequest"]
        self.assertEqual(
            commit["properties"]["approved_boundary"]["maximum"],
            maximum_boundary,
        )
        receipt = contract["components"]["schemas"]["DataResetReceipt"]
        self.assertEqual(
            receipt["properties"]["failure_code"],
            {
                "type": ["string", "null"],
                "maxLength": 80,
                "pattern": "^[a-z0-9][a-z0-9_]{0,79}$",
            },
        )
        self.assertNotIn("none", receipt["properties"]["state"]["enum"])
        server_contract_path = ROOT.parent / "power-monitor/shared/openapi/device-api.yaml"
        if server_contract_path.exists():
            server_contract = yaml.safe_load(
                server_contract_path.read_text(encoding="utf-8")
            )
            for schema_name in (
                "DataResetPrepareRequest",
                "DataResetCommitRequest",
                "DataResetCancelRequest",
                "DataResetReceipt",
            ):
                self.assertEqual(
                    contract["components"]["schemas"][schema_name],
                    server_contract["components"]["schemas"][schema_name],
                    f"cross-repo reset schema drift: {schema_name}",
                )

        api_source = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        for route in expected:
            route_source = api_source[api_source.index(f'"{route}"') :]
            self.assertRegex(
                route_source[:900],
                r"authorize\(request, (?:body|\"\"), (?:true|false), false\)",
            )

    def test_checkpoint_and_generation_wiring(self) -> None:
        policy = (ROOT / "src/reset/DataResetPolicy.cpp").read_text(
            encoding="utf-8"
        )
        checkpoint_block = policy[
            policy.index("kCheckpointNames") : policy.index(
                "bool boundedPrintable", policy.index("kCheckpointNames")
            )
        ]
        self.assertEqual(
            re.findall(r'\{Checkpoint::\w+, "([a-z_]+)"\}', checkpoint_block),
            [
                "none",
                "commit_authorized",
                "sequence_advanced",
                "cursors_advanced",
                "readings_cleared",
                "baseline_installed",
                "verified",
                "completed",
            ],
        )
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("factoryReset(", coordinator)
        for path, marker in (
            ("src/storage/SdStorage.cpp", 'document["data_generation"]'),
            ("src/network/ReadingWireFormat.cpp", 'record["data_generation"]'),
            ("src/network/ServerSync.cpp", 'document["data_generation"]'),
        ):
            self.assertIn(marker, (ROOT / path).read_text(encoding="utf-8"))

    def test_prepare_replay_precedes_generation_validation(self) -> None:
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        prepare = coordinator[
            coordinator.index("DataResetCoordinator::requestPrepare(") :
            coordinator.index("DataResetCoordinator::requestCommit(")
        ]
        self.assertLess(
            prepare.index("prepareRequestsEqual"),
            prepare.index("request.target_generation != config_.dataGeneration() + 1U"),
        )
        self.assertIn("terminalState(record_.state)", coordinator)

    def test_prepare_admission_and_latest_freshness_are_race_closed(self) -> None:
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        prepare = coordinator[
            coordinator.index("DataResetCoordinator::requestPrepare(") :
            coordinator.index("DataResetCoordinator::requestCommit(")
        ]
        self.assertLess(prepare.index("applyGates(true)"), prepare.rindex("return {202"))
        gates = coordinator[
            coordinator.index("bool DataResetCoordinator::applyGates(") :
            coordinator.index("DataResetApiResult DataResetCoordinator::problem(")
        ]
        self.assertIn("admission_newly_acquired", gates)
        self.assertIn("if (admission_newly_acquired)", gates)
        tick = coordinator[
            coordinator.index("void DataResetCoordinator::tick()") :
            coordinator.index("void DataResetCoordinator::processPendingPrepare()")
        ]
        self.assertLess(tick.index("processPendingPrepare()"), tick.index("applyGates(false)"))
        self.assertIn("markLatestBaselineInstalled", coordinator)
        self.assertIn("resumeLatestForGeneration", coordinator)
        self.assertIn(
            "config_.energyBaselineAbsoluteWh(),\n"
            "            record_.application_energy_baseline_wh",
            coordinator,
        )

        ota = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        self.assertIn("claimDisruptiveAdmission()", ota)
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        maintenance = application[
            application.index("void Application::executeMaintenance(") :
            application.index("bool Application::createTasks()")
        ]
        self.assertIn("claimDisruptiveAdmission()", maintenance)
        self.assertNotIn(
            "message.action == MaintenanceAction::Reboot;",
            maintenance[maintenance.index("const bool safe_during_reset") :
                        maintenance.index("const bool service_owns_admission")],
        )

        sync = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        heartbeat = sync[sync.index("bool ServerSync::heartbeatBody(") :]
        self.assertIn("heartbeatLatestAllowed", heartbeat)
        self.assertIn("latest.data_generation", heartbeat)

        readings = sync[
            sync.index("bool ServerSync::pushReadings()") :
            sync.index("bool ServerSync::pushEvents()")
        ]
        self.assertIn("ReadingSyncLease", readings)
        self.assertLess(
            readings.index("phase=before_post"),
            readings.index('request("POST", "/api/v1/device-readings/batch"'),
        )
        self.assertLess(
            readings.index("phase=before_ack_persist"),
            readings.index("config_.setServerAckSequence(acknowledgement)"),
        )
        preparing = coordinator[
            coordinator.index("void DataResetCoordinator::progressPreparing()") :
            coordinator.index("void DataResetCoordinator::processPendingCommit()")
        ]
        self.assertLess(
            preparing.index("readingSyncInFlight()"),
            preparing.index("queueDataResetBarrier"),
        )

    def test_commit_cancel_and_sample_generation_races_are_linearized(self) -> None:
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        cancel = coordinator[
            coordinator.index("DataResetCoordinator::requestCancel(") :
            coordinator.index("DataResetCoordinator::status(")
        ]
        self.assertLess(
            cancel.index("pending_commit_ && durable_match"),
            cancel.index("saveRecord(cancelled)"),
        )

        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        meter = application[
            application.index("void Application::meterTask()") :
            application.index("void Application::aggregationTask()")
        ]
        self.assertLess(
            meter.index("sampled_generation = config_.dataGeneration()"),
            meter.index("meter_->poll("),
        )
        self.assertGreater(
            meter.index("sample.data_generation = sampled_generation"),
            meter.index("meter_->poll("),
        )
        aggregation = application[
            application.index("void Application::aggregationTask()") :
            application.index("void Application::networkTask()")
        ]
        self.assertIn("sampleForGenerationAllowed", aggregation)

        config = (ROOT / "src/config/ConfigService.cpp").read_text(encoding="utf-8")
        offset = config[
            config.index("bool ConfigService::setEnergyOffsetWh(") :
            config.index("std::uint64_t ConfigService::energyBaselineAbsoluteWh()")
        ]
        self.assertLess(offset.index("RecursiveMutexGuard mutation"),
                        offset.index("dataResetFrozen()"))

    def test_terminal_results_wait_for_observed_gate_release(self) -> None:
        coordinator = (ROOT / "src/reset/DataResetCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        progress = coordinator[
            coordinator.index("void DataResetCoordinator::progressCommit()") :
            coordinator.index("bool DataResetCoordinator::captureMeterEnergy(")
        ]
        completed = progress[progress.index("Checkpoint::Verified") :]
        self.assertLess(
            completed.index("saveRecord(completed)"),
            completed.index("applyGates(false)"),
        )
        self.assertIn("return gatesReleased();", coordinator)

        status_json = coordinator[
            coordinator.index("DataResetCoordinator::statusJson(") :
            coordinator.index("void DataResetCoordinator::failBeforeCommit(")
        ]
        self.assertIn("completion_pending_release", status_json)
        self.assertIn("cancellation_pending_release", status_json)
        self.assertIn('"verified"', status_json)
        self.assertIn('"attention_required"', status_json)
        self.assertIn("!completion_pending_release", status_json)
        self.assertIn('response["failure_code"]', status_json)
        self.assertIn("record.failure_code", status_json)
        self.assertIn("data_reset_gate_release_pending", status_json)

        status = coordinator[
            coordinator.index("DataResetCoordinator::status(") :
            coordinator.index("bool DataResetCoordinator::saveRecord(")
        ]
        self.assertIn("terminalReleasePending(record_)", status)
        self.assertIn("? 202", status)

        cancel = coordinator[
            coordinator.index("DataResetCoordinator::requestCancel(") :
            coordinator.index("DataResetCoordinator::status(")
        ]
        self.assertEqual(cancel.count("if (!applyGates(false))"), 2)
        self.assertIn("if (record_.state == data_reset::State::Cancelled)", cancel)
        self.assertIn("if (!persistMeasurementPauseEvidence(cancelled))", cancel)
        self.assertLess(
            cancel.rindex("saveRecord(cancelled)"),
            cancel.rindex("if (!applyGates(false))"),
        )
        self.assertIn("return {202, {}, {}, body};", cancel)

        heartbeat = coordinator[
            coordinator.index("DataResetHeartbeatSnapshot ") :
        ]
        self.assertIn("!gatesReleased()", heartbeat)
        self.assertIn("result.reset_required = true", heartbeat)
        self.assertIn("result.failure_code", heartbeat)
        self.assertIn("data_reset_state_lock_timeout", heartbeat)
        self.assertIn("data_reset_gate_state_invalid", heartbeat)

        server_sync = (ROOT / "src/network/ServerSync.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('data_reset["failure_code"]', server_sync)

        policy = (ROOT / "src/reset/DataResetPolicy.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("completionExternallyVisible", policy)
        self.assertIn("cancellationExternallyVisible", policy)

        pending_commit = coordinator[
            coordinator.index("void DataResetCoordinator::processPendingCommit()") :
            coordinator.index("void DataResetCoordinator::progressCommit()")
        ]
        self.assertIn("attention.state = data_reset::State::AttentionRequired", pending_commit)
        self.assertIn("data_reset_prepare_evidence_changed", pending_commit)
        self.assertIn("data_reset_pzem_commit_capture_failed", pending_commit)
        self.assertIn("classifyCommitRequest(record_, commit_request_)", pending_commit)

        cleanup_checkpoint = coordinator[
            coordinator.index("case data_reset::Checkpoint::CursorsAdvanced") :
            coordinator.index("case data_reset::Checkpoint::ReadingsCleared")
        ]
        self.assertIn(
            "counted.indexes_deleted = result.cleanup.index_files_removed",
            cleanup_checkpoint,
        )
        self.assertIn(
            "counted.exports_deleted = result.cleanup.export_files_removed",
            cleanup_checkpoint,
        )
        self.assertIn(
            "counted.backlog_entries_deleted =\n"
            "          result.cleanup.metadata_files_removed",
            cleanup_checkpoint,
        )
        self.assertIn("saveRecord(counted)", cleanup_checkpoint)
        self.assertLess(
            cleanup_checkpoint.index("saveRecord(counted)"),
            cleanup_checkpoint.index("if (!result.ok)"),
        )

    def test_prepare_preserves_records_and_commit_purges_gap_state(self) -> None:
        storage = (ROOT / "src/storage/StorageCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        barrier = storage[
            storage.index("message.type == Type::DataResetBarrier") :
            storage.index("const std::uint64_t now = millis()")
        ]
        self.assertIn("data_reset_prepare_capacity_blocked", barrier)
        self.assertGreaterEqual(barrier.count("storage_.append(*pending_record,"), 2)
        self.assertGreaterEqual(
            barrier.count("request->expected_card_generation"), 2
        )
        self.assertGreaterEqual(
            barrier.count("request->expected_card_device_id"), 2
        )
        self.assertIn("record->materialize(pending_record_storage)", barrier)
        self.assertIn("if (request->cleanup)", barrier)
        cleanup = barrier[barrier.index("if (request->cleanup)") :]
        self.assertIn("pending_gap_count = 0U", cleanup)
        self.assertIn("dropped_record_intervals_.store(0U", cleanup)
        self.assertNotIn('phase=%s', barrier)
        self.assertIn("pending_reset_event_count", storage)
        self.assertIn("data_reset_barrier_queued_.load", storage)
        self.assertIn("events_preserved && retained && request->cleanup", barrier)
        cache_purge = storage[
            storage.index("bool StorageCoordinator::clearReadingHistoryResults()") :
            storage.index("std::string StorageCoordinator::queueHistory(")
        ]
        self.assertIn("xSemaphoreTake(history_mutex_", cache_purge)
        self.assertIn("return false;", cache_purge)
        self.assertIn("return true;", cache_purge)
        self.assertLess(
            barrier.index("!clearReadingHistoryResults()"),
            barrier.index("clearReadingDataForReset"),
        )
        self.assertIn("data_reset_history_cache_clear_failed", barrier)
        self.assertIn("scrubCompletedPayloadCopies", barrier)
        self.assertIn("data_reset_event_payload_scrub_failed", barrier)
        self.assertLess(
            barrier.index("clearReadingDataForReset"),
            barrier.index(
                "for (std::size_t index = 0U;\n"
                "                   result.ok && index < event_journal.event_count"
            ),
        )
        sd_storage = (ROOT / "src/storage/SdStorage.cpp").read_text(
            encoding="utf-8"
        )
        cleanup = sd_storage[
            sd_storage.index("SdStorage::clearReadingDataForReset(") :
            sd_storage.index("struct PlannedRemoval", sd_storage.index(
                "SdStorage::clearReadingDataForReset("
            ))
        ]
        self.assertLess(
            cleanup.index("resetCardBindingMatches"),
            cleanup.index("struct PlannedRemoval") if "struct PlannedRemoval" in cleanup else len(cleanup),
        )
        self.assertIn("expected_card_generation", cleanup)
        self.assertIn("expected_card_device_id", cleanup)
        self.assertIn("currentCardManifestMatchesReset", cleanup)
        cleanup_full = sd_storage[
            sd_storage.index("SdStorage::clearReadingDataForReset(") :
            sd_storage.index("SdStorage::clearPreEnrollmentReadingData(")
        ]
        self.assertIn("scrubCompletedPayloadCopies", cleanup_full)
        self.assertIn("data_reset_cleanup_payload_scrub_failed", cleanup_full)
        live_manifest = sd_storage[
            sd_storage.index("SdStorage::currentCardManifestMatchesReset(") :
            sd_storage.index("SdStorage::clearReadingDataForReset(")
        ]
        self.assertIn('SD.open(kManifestPath, FILE_READ)', live_manifest)
        self.assertNotIn("writeManifest", live_manifest)

        cleanup_full = sd_storage[
            sd_storage.index("SdStorage::clearReadingDataForReset(") :
            sd_storage.index("bool SdStorage::clearPreEnrollmentReadingData(")
        ]
        first_delete = cleanup_full.rindex("for (const auto &item : plan)")
        second_binding_check = cleanup_full.rfind(
            "currentCardManifestMatchesReset", 0, first_delete
        )
        self.assertGreater(second_binding_check, 0)
        recovery_scan = cleanup_full.index("if (!recover())")
        for field in (
            "health_.current_file.clear()",
            "health_.last_write_utc_ms = 0U",
            "health_.last_write_latency_ms = 0U",
            "health_.reclaimable_bytes = 0U",
            "health_.protected_unacknowledged_bytes = 0U",
            "health_.protected_untrusted_bytes = 0U",
            "health_.dropped_interval_count = 0U",
            "health_.first_dropped_interval_utc_ms = 0U",
            "health_.last_dropped_interval_utc_ms = 0U",
            "health_.segment_count = health_.event_segment_count",
            "health_.eligible_segment_count = 0U",
            "health_.protected_segment_count = 0U",
            "health_.open_segment_count = 0U",
            "health_.closed_segment_count = 0U",
            "health_.untrusted_segment_count = 0U",
            "health_.export_count = 0U",
            "health_.repair_artifact_count = 0U",
            "health_.temporary_artifact_count = 0U",
        ):
            reset_position = cleanup_full.index(field)
            self.assertGreater(reset_position, second_binding_check)
            self.assertLess(reset_position, first_delete)
            self.assertLess(reset_position, recovery_scan)

        strict_inventory = sd_storage[
            sd_storage.index("bool SdStorage::collectFilesStrict(") :
            sd_storage.index("void SdStorage::cleanupTemporaryArtifacts(")
        ]
        self.assertIn("return false;", strict_inventory)
        for marker in (
            "opendir(physical_directory.c_str())",
            "errno = 0",
            "readdir(root)",
            "stat(physical_path.c_str(), &metadata)",
            "self(self, logical_path)",
            "closedir(root)",
        ):
            self.assertIn(marker, strict_inventory)
        self.assertGreaterEqual(
            cleanup_full.count("collectFilesStrict("), 6
        )
        self.assertIn("require_empty_tree", cleanup_full)
        self.assertIn("data_reset_storage_verification_failed", cleanup_full)
        post_delete_manifest = cleanup_full.find(
            "currentCardManifestMatchesReset", first_delete
        )
        self.assertGreater(post_delete_manifest, first_delete)
        self.assertLess(post_delete_manifest, recovery_scan)

        ordinary_event = storage[storage.rindex("case Type::Event:") :]
        self.assertIn("const bool appended = storage_.appendEvent", ordinary_event)
        self.assertIn("!record_writes_enabled_.load", ordinary_event)
        self.assertIn(
            "pending_reset_events[pending_reset_event_count++] = message",
            ordinary_event,
        )

        recovery = sd_storage[
            sd_storage.index("bool SdStorage::recover()") :
            sd_storage.index("bool SdStorage::recoverFile(")
        ]
        self.assertIn("health_.event_segment_count =", recovery)
        self.assertIn("health_.segment_count =", recovery)
        self.assertIn("files.size()", recovery)
        self.assertIn("event_files.size()", recovery)

    def test_authenticated_storage_plan_evidence_is_exact(self) -> None:
        api = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        storage = api[
            api.index('server_.on("/api/v1/storage"') :
            api.index('"/api/v1/sync-status"')
        ]
        for field in (
            "local_record_count",
            "card_generation",
            "card_identity_status",
            "data_generation",
            "sequence_floor",
            "next_sequence",
            "prepare_projection_consistent",
            "prepare_projection_local_record_count",
            "prepare_projection_next_sequence",
            "prepare_projection_newest_sequence",
            "prepare_projection_newest_syncable_sequence",
            "prepare_drain_records_projected",
            "prepare_drain_first_sequence_projected",
            "prepare_drain_last_sequence_projected",
            "prepare_drain_syncable_records_projected",
        ):
            self.assertIn(f'document["{field}"]', storage)
        coordinator = (
            ROOT / "src/storage/StorageCoordinator.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn("data_reset_projection_version_", coordinator)
        self.assertIn("projection_version_before == projection_version_after", coordinator)
        self.assertIn("projected_meter_epoch == meter_epoch_before", coordinator)
        self.assertIn("meter_epoch_before == meter_epoch_after", coordinator)

    def test_fresh_enrollment_installs_generation_before_network_start(self) -> None:
        sync = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        enroll = sync[
            sync.index("bool ServerSync::enroll") :
            sync.index("bool ServerSync::heartbeat")
        ]
        for marker in (
            'result["sync_policy"]["data_generation"]',
            'result["sync_policy"]["reset_boundary"]',
            "config_.stageEnrollmentActivation(",
            "queueEnrollmentActivationReboot()",
            'credentials_active=false',
        ):
            self.assertIn(marker, enroll)
        self.assertNotIn("return heartbeat(retry_after_ms)", enroll)

        config = (ROOT / "src/config/ConfigService.cpp").read_text(
            encoding="utf-8"
        )
        stage = config[
            config.index("ConfigService::stageEnrollmentActivation(") :
            config.index("ConfigService::pendingEnrollmentActivation()")
        ]
        self.assertLess(
            stage.index("commitEnrollmentActivationRecord("),
            stage.index("publishEnrollment("),
        )
        activation = config[
            config.index("ConfigService::activatePendingEnrollment(") :
            config.index("bool ConfigService::directionalKeys")
        ]
        self.assertNotIn("publishEnrollment(", activation)
        for marker in (
            "identity_ = activated_identity",
            "data_generation_ = activation.target_data_generation",
            "data_reset_boundary_ = activation.reset_boundary",
            "server_ack_sequence_ = sequence_floor",
            "pending_enrollment_activation_ = {}",
        ):
            self.assertIn(marker, activation)

        application = (ROOT / "src/app/Application.cpp").read_text(
            encoding="utf-8"
        )
        boot_conflict = application[
            application.index("const EnrollmentActivationInfo enrollment_activation") :
            application.index("DeviceIdentity storage_identity")
        ]
        self.assertIn(
            "enrollment_activation.pending && boot_reset_present &&",
            boot_conflict,
        )
        self.assertIn("data_reset::readingGateRequired(", boot_conflict)
        handoff = application[
            application.index("if (enrollment_activation.pending)") :
            application.index("std::uint64_t orphan_energy_offset_wh")
        ]
        ordered = (
            "setDataResetFreeze(true)",
            "clearPreEnrollmentReadingData(",
            "advanceSequenceFloor(",
            "rebindCardForEnrollment(",
            "activatePendingEnrollment(",
            "setDataResetFreeze(false)",
            "setRecordWritesEnabled(true)",
        )
        positions = [handoff.index(marker) for marker in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(
            application.index("activatePendingEnrollment("),
            application.index("network_.begin()"),
        )

        storage = (ROOT / "src/storage/SdStorage.cpp").read_text(
            encoding="utf-8"
        )
        cleanup = storage[
            storage.index("SdStorage::clearPreEnrollmentReadingData(") :
            storage.index("bool SdStorage::rebindCardForEnrollment(")
        ]
        for marker in (
            "currentCardManifestMatchesReset",
            "collectFilesStrict",
            "enrollment_unknown_storage_artifact",
            "enrollment_reading_inventory_not_empty",
        ):
            self.assertIn(marker, cleanup)
        rebind = storage[
            storage.index("bool SdStorage::rebindCardForEnrollment(") :
            storage.index("bool SdStorage::initializeLayout()")
        ]
        for marker in (
            '"/POWERMON/manifest.enrollment.tmp"',
            '"/POWERMON/manifest.enrollment.bak"',
            "SD.rename(target, backup)",
            "SD.rename(temporary, target)",
        ):
            self.assertIn(marker, rebind)


if __name__ == "__main__":
    unittest.main()

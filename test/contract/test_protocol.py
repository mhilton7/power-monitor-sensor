from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from check_repo import (
    RECOVERY_FIRMWARE_IDENTIFIERS,
    embedded_recovery_identifier,
    production_firmware_artifact_paths,
    recovery_identifier_in_contents,
)

from simulator.protocol import (
    body_sha256,
    canonical_path_query,
    canonical_string,
    hkdf_sha256,
    sign,
    verify,
)


class ProtocolContractTests(unittest.TestCase):
    def test_shared_hkdf_and_hmac_vectors(self) -> None:
        vectors = json.loads((ROOT / "shared/fixtures/auth-vectors.json").read_text())
        hkdf = vectors["hkdf"]
        secret = bytes.fromhex(hkdf["enrollment_secret_hex"])
        self.assertEqual(
            hkdf_sha256(secret, hkdf["device_to_server_info"].encode()).hex(),
            hkdf["device_to_server_key_hex"],
        )
        self.assertEqual(
            hkdf_sha256(secret, hkdf["server_to_device_info"].encode()).hex(),
            hkdf["server_to_device_key_hex"],
        )
        request = vectors["requests"][0]
        target = request["path"] + "?tag=z&tag=a"
        body = request["body_utf8"].encode()
        self.assertEqual(canonical_path_query(target), request["canonical_path_query"])
        self.assertEqual(body_sha256(body), request["content_sha256"])
        self.assertEqual(
            canonical_string(
                request["method"],
                target,
                request["timestamp"],
                request["nonce"],
                request["content_sha256"],
            ),
            request["canonical"],
        )
        headers = sign(
            bytes.fromhex(request["key_hex"]),
            request["method"],
            target,
            request["timestamp"],
            request["nonce"],
            body,
        )
        self.assertEqual(headers["X-PM-Signature"], request["signature"])

    def test_replay_timestamp_hash_and_protocol_rejections(self) -> None:
        key = bytes(range(32))
        body = b'{"ok":true}'
        now = 1_700_000_000
        headers = sign(key, "POST", "/path?b=2&a=1", str(now), "ab" * 16, body)
        seen: set[str] = set()

        def nonce_seen(nonce: str, _timestamp: int) -> bool:
            existed = nonce in seen
            seen.add(nonce)
            return existed

        self.assertEqual(
            verify(key, "POST", "/path?b=2&a=1", headers, body, now, nonce_seen),
            (True, "ok"),
        )
        self.assertEqual(
            verify(key, "POST", "/path?b=2&a=1", headers, body, now, nonce_seen),
            (False, "nonce_replayed"),
        )
        changed = dict(headers)
        changed["X-PM-Nonce"] = "cd" * 16
        self.assertEqual(
            verify(key, "POST", "/path?b=2&a=1", changed, body, now, lambda *_: False)[
                1
            ],
            "signature_invalid",
        )
        changed = sign(key, "POST", "/path", str(now - 301), "ef" * 16, body)
        self.assertEqual(
            verify(key, "POST", "/path", changed, body, now, lambda *_: False)[1],
            "timestamp_outside_window",
        )
        changed = sign(key, "POST", "/path", str(now), "01" * 16, body)
        changed["X-PM-Protocol"] = "pm-protocol/2.0.0"
        self.assertEqual(
            verify(key, "POST", "/path", changed, body, now, lambda *_: False)[1],
            "protocol_mismatch",
        )

    def test_json_schema_fixtures(self) -> None:
        pairs = [
            ("reading.schema.json", "valid-reading.json", "invalid-reading.json"),
            ("heartbeat.schema.json", "valid-heartbeat.json", "invalid-heartbeat.json"),
            (
                "ota-manifest.schema.json",
                "valid-ota-manifest.json",
                "invalid-ota-manifest.json",
            ),
        ]
        for schema_name, valid_name, invalid_name in pairs:
            schema = json.loads((ROOT / "shared/schemas" / schema_name).read_text())
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            valid = json.loads((ROOT / "shared/fixtures" / valid_name).read_text())
            invalid = json.loads((ROOT / "shared/fixtures" / invalid_name).read_text())
            self.assertEqual(list(validator.iter_errors(valid)), [], valid_name)
            self.assertNotEqual(list(validator.iter_errors(invalid)), [], invalid_name)

    def test_openapi_documents_and_path_item_references(self) -> None:
        for path in (ROOT / "shared/openapi").glob("*.yaml"):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(document["openapi"], "3.1.0")
            self.assertTrue(document["paths"])
            for route, item in document["paths"].items():
                self.assertTrue(
                    "$ref" in item
                    or any(
                        method in item for method in ("get", "post", "put", "delete")
                    ),
                    route,
                )
        device = yaml.safe_load((ROOT / "shared/openapi/device-api.yaml").read_text())
        self.assertIn("post", device["components"]["pathItems"]["QueuedAction"])
        local_health = device["paths"]["/api/local/health"]["get"]
        self.assertEqual(local_health["security"], [])
        self.assertIn("no central-server request", local_health["description"])
        self.assertEqual(
            local_health["responses"]["200"]["content"]["application/json"]["schema"][
                "$ref"
            ],
            "#/components/schemas/LocalHealth",
        )

    def test_v1_modes_are_compatible_but_runtime_is_push_only(self) -> None:
        config_schema = json.loads(
            (ROOT / "shared/schemas/config.schema.json").read_text(encoding="utf-8")
        )
        mode = config_schema["properties"]["connection_mode"]
        self.assertEqual(mode["enum"], ["pull", "push", "hybrid"])
        self.assertIn("only in push mode", mode["description"])
        self.assertEqual(
            config_schema["properties"]["voltage_maximum_v"]["maximum"], 400
        )
        self.assertEqual(
            config_schema["properties"]["frequency_minimum_hz"]["minimum"], 40
        )
        self.assertEqual(
            config_schema["properties"]["frequency_maximum_hz"]["maximum"], 70
        )

        device = yaml.safe_load(
            (ROOT / "shared/openapi/device-api.yaml").read_text(encoding="utf-8")
        )
        for schema_name in ("Config", "NetworkSettingsUpdate", "FirstRunSetup"):
            connection_mode = device["components"]["schemas"][schema_name][
                "properties"
            ]["connection_mode"]
            self.assertEqual(connection_mode["enum"], ["pull", "push", "hybrid"])
            self.assertIn("push", connection_mode["description"])
        live = device["components"]["schemas"]["Live"]["properties"]
        self.assertEqual(live["voltage_v"]["maximum"], 400)
        self.assertEqual(
            (live["frequency_hz"]["minimum"], live["frequency_hz"]["maximum"]),
            (40, 70),
        )
        self.assertEqual(live["power_factor"]["maximum"], 1)
        server_reading = yaml.safe_load(
            (ROOT / "shared/openapi/server-ingest-api.yaml").read_text(encoding="utf-8")
        )["components"]["schemas"]["Reading"]["properties"]
        self.assertEqual(server_reading["voltage_avg"]["maximum"], 400)
        self.assertEqual(server_reading["current_avg"]["maximum"], 5000)
        self.assertEqual(server_reading["power_avg"]["maximum"], 10_000_000)
        self.assertEqual(server_reading["power_factor"]["maximum"], 1)
        self.assertEqual(
            (
                server_reading["frequency_hz"]["minimum"],
                server_reading["frequency_hz"]["maximum"],
            ),
            (40, 70),
        )

        http_api = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        provisioning = (ROOT / "src/provisioning/ProvisioningService.cpp").read_text(
            encoding="utf-8"
        )
        server_sync = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        self.assertIn('"connection_mode_unsupported"', http_api)
        self.assertIn('capabilities["connection_modes"] = "push"', http_api)
        self.assertIn('"connection_mode_unsupported"', provisioning)
        self.assertIn('"CONNECTION_MODE_REJECTED"', server_sync)
        self.assertIn('"remote_connection_mode_unsupported"', server_sync)

    def test_device_api_async_responses_are_explicitly_opt_in(self) -> None:
        contract = yaml.safe_load(
            (ROOT / "shared/openapi/device-api.yaml").read_text(encoding="utf-8")
        )
        operations = (
            ("/api/v1/readings", "get"),
            ("/api/v1/events", "get"),
            ("/api/v1/config", "put"),
            ("/api/v1/network-settings", "put"),
            ("/api/v1/setup/apply", "post"),
            ("/api/v1/sync/ack", "post"),
            ("/api/v1/enrollment/reenroll", "post"),
        )
        prefer_reference = "#/components/parameters/PreferRespondAsync"
        for route, method in operations:
            operation = contract["paths"][route][method]
            self.assertIn("200", operation["responses"], route)
            self.assertIn("202", operation["responses"], route)
            self.assertIn(
                {"$ref": prefer_reference},
                operation["parameters"],
                route,
            )

        preference = contract["components"]["parameters"]["PreferRespondAsync"]
        self.assertEqual(preference["name"], "Prefer")
        self.assertEqual(preference["schema"]["const"], "respond-async")
        self.assertIn("final response", preference["description"])

        acknowledgement = contract["paths"]["/api/v1/sync/ack"]["post"]
        self.assertEqual(acknowledgement["security"], [{"deviceHmac": []}])
        acknowledgement_schema = contract["components"]["schemas"][
            "AcknowledgementRequest"
        ]
        validator = Draft202012Validator(acknowledgement_schema)
        self.assertTrue(validator.is_valid({"ack_sequence": 10}))
        self.assertTrue(validator.is_valid({"highest_contiguous_sequence": 10}))
        self.assertFalse(validator.is_valid({}))
        self.assertFalse(
            validator.is_valid(
                {
                    "ack_sequence": 10,
                    "highest_contiguous_sequence": 10,
                }
            )
        )

        reenrollment = contract["paths"]["/api/v1/enrollment/reenroll"]["post"]
        confirmation = next(
            parameter
            for parameter in reenrollment["parameters"]
            if parameter.get("name") == "X-PM-Action-Token"
        )
        self.assertTrue(confirmation["required"])
        self.assertEqual(confirmation["schema"]["const"], "REENROLL")
        self.assertIn("local browser session", reenrollment["description"])
        self.assertTrue(
            reenrollment["requestBody"]["content"]["application/json"]["schema"][
                "properties"
            ]["enrollment_token"]["writeOnly"]
        )
        self.assertEqual(
            reenrollment["requestBody"]["content"]["application/json"]["schema"][
                "properties"
            ]["enrollment_token"]["minLength"],
            32,
        )
        self.assertEqual(
            contract["components"]["schemas"]["FirstRunSetup"]["properties"][
                "enrollment_token"
            ]["minLength"],
            32,
        )

        password_jobs = contract["paths"]["/api/v1/auth/password-jobs"]["get"]
        self.assertIn({"deviceHmac": []}, password_jobs["security"])
        self.assertIn({"localSession": []}, password_jobs["security"])
        for phrase in (
            "login job",
            "Synchronization acknowledgement",
            "HMAC reenrollment",
        ):
            self.assertIn(phrase, password_jobs["description"])

        page_properties = contract["components"]["schemas"]["Page"]["properties"]
        for name in (
            "protocol_version",
            "records",
            "readings",
            "events",
            "oldest_sequence",
            "newest_sequence",
        ):
            self.assertIn(name, page_properties)
        self.assertEqual(
            contract["components"]["schemas"]["ReadingPage"]["allOf"][1]["required"],
            ["readings"],
        )
        self.assertEqual(
            page_properties["readings"]["items"]["$ref"],
            "./server-ingest-api.yaml#/components/schemas/Reading",
        )

        firmware_source = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        for marker in (
            "prefersAsync(request)",
            "sendPasswordJobAccepted(request",
            "sendHistoryJobAccepted(request",
            'document["highest_contiguous_sequence"]',
            'authorize(request, "", false, false)',
            '"async_reenrollment_requires_local_session"',
            "reading_wire::append(readings, encoded)",
            "createLocalSession(request, false)",
            "createLocalSession(request, true)",
            "require_elevated_local",
            '"origin_required"',
            "creator_session_digest",
            '"login_session_required"',
        ):
            self.assertIn(marker, firmware_source)

        auth_source = (ROOT / "src/security/AuthService.cpp").read_text(
            encoding="utf-8"
        )
        for marker in (
            "auth_policy::parseTimestamp",
            "auth_policy::timestampWithinWindow",
            "ReplayRememberResult::CapacityExceeded",
            '"elevated_session_required"',
        ):
            self.assertIn(marker, auth_source)

        powershell = (ROOT / "tools/diagnostics/Test-SensorProvisioning.ps1").read_text(
            encoding="utf-8"
        )
        python_provisioner = (ROOT / "tools/provision_device.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('Headers["Origin"]', powershell)
        self.assertIn('"Origin": origin', python_provisioner)

    def test_setup_ap_password_is_input_only_on_physical_usb(self) -> None:
        production = "\n".join(
            path.read_text(encoding="utf-8")
            for source_root in (ROOT / "include", ROOT / "src")
            for path in source_root.rglob("*")
            if path.is_file() and path.suffix in {".h", ".cpp"}
        )
        for disclosure_marker in (
            "printSetupCredential",
            "SETUP_AP_CREDENTIAL",
            "scope=physical_serial_only",
            "local_secret",
        ):
            self.assertNotIn(disclosure_marker, production)
        for safe_marker in (
            "SETUP_AP_READY",
            "SETUP_AP_PASSWORD_APPLIED",
            "SETUP_AP_PASSWORD_REJECTED",
            "setup-password_<request_id>_<redacted>",
            "secret_logged=false",
            "writeSetupPasswordResult",
        ):
            self.assertIn(safe_marker, production)

        config_source = (ROOT / "src/config/ConfigService.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('"setup_next"', config_source)
        self.assertIn("readSetupPassword", config_source)
        self.assertIn("crypto::constantTimeEqual(readback, password)", config_source)
        self.assertIn(
            "RecursiveMutexGuard mutation(mutation_mutex_, pdMS_TO_TICKS(250))",
            config_source,
        )
        self.assertIn(
            "return legacy_config_removed && setup_credentials_removed",
            config_source,
        )
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        self.assertIn("std::fill(line.begin(), line.end(), '\\0')", application)
        self.assertIn("kRequestIdLength = 16U", application)
        network = (ROOT / "src/network/NetworkService.cpp").read_text(encoding="utf-8")
        setup_start = network.index("bool NetworkService::startSetupAp()")
        password_read = network.index("config_.ensureSetupPassword()", setup_start)
        existing_ap_stop = network.index(
            "if (status_.setup_ap_active) {\n    stopSetupAp();", setup_start
        )
        self.assertLess(password_read, existing_ap_stop)
        self.assertIn("next_setup_ap_start_ms_", network)
        self.assertIn("setup_ap_restart_pending_ = true", network)
        self.assertIn(
            "setup_ap_restart_pending_ ||\n"
            "       (!status_.setup_ap_active && !status_.station_connected)",
            network,
        )
        self.assertIn("setup_ap_restart_pending_ = false", network)
        self.assertIn("writeSetupReady", network)
        password_commit = application.index("config_.setSetupPassword(password)")
        restart_schedule = application.index(
            "network_.requestSetupApRestart()", password_commit
        )
        success_reply = application.index("writeSetupPasswordResult(", password_commit)
        self.assertLess(restart_schedule, success_reply)
        logger = (ROOT / "src/diagnostics/SerialLogger.cpp").read_text(encoding="utf-8")
        dump_start = logger.index("void SerialLogger::dumpRecentErrors()")
        dump_end = logger.index(
            "std::string SerialLogger::recentErrorsJson()", dump_start
        )
        dump_source = logger[dump_start:dump_end]
        self.assertIn("xSemaphoreTake(dump_mutex_", dump_source)
        self.assertIn("dump_snapshot_[index]", dump_source)
        self.assertIn("xSemaphoreTake(output_mutex_", dump_source)
        helper = (ROOT / "tools/diagnostics/Set-SensorSetupPassword.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[string]$Port", helper)
        self.assertNotIn("[string]$Password", helper)
        self.assertIn("Read-Host", helper)
        self.assertIn("-AsSecureString", helper)
        self.assertIn("$serial.Write($commandCharacters", helper)
        self.assertIn("$serial.DiscardInBuffer()", helper)
        self.assertIn("RandomNumberGenerator", helper)
        self.assertIn("request_id=$requestId", helper)
        self.assertIn("ZeroFreeBSTR", helper)
        self.assertIn("SETUP_AP_PASSWORD_APPLIED", helper)
        self.assertIn("SETUP_AP_PASSWORD_REJECTED", helper)

    def test_arduino_bootstrap_has_a_bounded_stack_reserve(self) -> None:
        main_source = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
        self.assertIn(
            "SET_LOOP_TASK_STACK_SIZE(16 * 1024);",
            main_source,
            "the full production bootstrap exceeds the Arduino core's 8 KiB default",
        )

    def test_sntp_server_names_have_stable_lifetime(self) -> None:
        header = (ROOT / "src/network/NetworkService.h").read_text(encoding="utf-8")
        source = (ROOT / "src/network/NetworkService.cpp").read_text(encoding="utf-8")
        self.assertIn(
            "std::array<std::string, 3> active_ntp_servers_",
            header,
            "lwIP retains NTP hostname pointers after configTzTime returns",
        )
        self.assertIn("active_ntp_servers_ = servers;", source)
        self.assertIn(
            'configTzTime("UTC0", active_ntp_servers_[0].c_str(),',
            source,
        )
        self.assertEqual(
            source.count("configTzTime("),
            2,
            "NTP setup must remain centralized (implementation plus its comment)",
        )
        self.assertNotIn(
            'configTzTime("UTC0", ntp[0].c_str()',
            source,
            "temporary configuration snapshots must never back lwIP hostname pointers",
        )

    def test_physical_admin_recovery_is_temporary_and_secret_safe(self) -> None:
        platformio = (ROOT / "platformio.ini").read_text(encoding="utf-8")
        release = platformio[
            platformio.index("[env:esp32-s3-release]") : platformio.index(
                "[env:esp32-s3-debug]"
            )
        ]
        recovery = platformio[
            platformio.index("[env:esp32-s3-admin-recovery]") : platformio.index(
                "[env:native-tests]"
            )
        ]
        self.assertIn("-DPM_PHYSICAL_ADMIN_RECOVERY=0", release)
        self.assertIn("-DPM_RELEASE_BUILD=1", release)
        self.assertNotIn("-DPM_PHYSICAL_ADMIN_RECOVERY=1", release)
        self.assertIn("-DPM_PHYSICAL_ADMIN_RECOVERY=1", recovery)
        self.assertIn("-DPM_RELEASE_BUILD=0", recovery)
        self.assertIn("-DPM_SIMULATED_METER=0", recovery)
        self.assertNotIn("-DPM_PHYSICAL_ADMIN_RECOVERY=0", recovery)
        self.assertIn("-DARDUINO_USB_MODE=1", platformio)
        self.assertIn("-DARDUINO_USB_CDC_ON_BOOT=1", platformio)

        build_config = (ROOT / "include/build_config.h").read_text(encoding="utf-8")
        self.assertIn("!PM_RELEASE_BUILD || !PM_PHYSICAL_ADMIN_RECOVERY", build_config)

        config_header = (ROOT / "src/config/ConfigService.h").read_text(
            encoding="utf-8"
        )
        result_start = config_header.index("enum class AdminPasswordRecoveryResult")
        result_gate = config_header.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, result_start
        )
        result_gate_end = config_header.index("#endif", result_start)
        self.assertLess(result_gate, result_start)
        self.assertLess(result_start, result_gate_end)
        for result in ("Applied", "RejectedPreserved", "FailedUncertain"):
            self.assertIn(result, config_header[result_start:result_gate_end])

        replacement_declaration = config_header.index(
            "replaceAdminPasswordForPhysicalRecovery"
        )
        replacement_gate = config_header.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, replacement_declaration
        )
        replacement_gate_end = config_header.index("#endif", replacement_declaration)
        self.assertLess(replacement_gate, replacement_declaration)
        self.assertLess(replacement_declaration, replacement_gate_end)
        private_start = config_header.index("private:")
        verifier_declaration = config_header.index("persistAdminVerifier(")
        self.assertLess(private_start, verifier_declaration)
        self.assertEqual(config_header.count("persistAdminVerifier("), 1)

        application_header = (ROOT / "src/app/Application.h").read_text(
            encoding="utf-8"
        )
        recovery_state = application_header.index("admin_recovery_request_id_")
        state_gate = application_header.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, recovery_state
        )
        state_gate_end = application_header.index("#endif", recovery_state)
        self.assertLess(state_gate, recovery_state)
        self.assertLess(recovery_state, state_gate_end)
        for marker in (
            "admin_recovery_request_id_",
            "admin_recovery_deadline_ms_",
            "admin_recovery_complete_{false}",
        ):
            self.assertIn(marker, application_header[state_gate:state_gate_end])

        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        begin_start = application.index("bool Application::begin()")
        begin_end = application.index("void Application::meterTaskEntry", begin_start)
        begin_source = application[begin_start:begin_end]
        config_begin = begin_source.index("config_.begin()")
        offline_gate = begin_source.index(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", config_begin
        )
        offline_gate_end = begin_source.index("#endif", offline_gate)
        offline_recovery = begin_source[offline_gate:offline_gate_end]
        production_boot = begin_source[offline_gate_end:]
        self.assertIn(
            'xTaskCreatePinnedToCore(serialCommandTaskEntry, "AdminRecoveryTask", 8192',
            offline_recovery,
        )
        for marker in (
            "ADMIN_RECOVERY_OFFLINE_READY",
            "wifi=disabled",
            "http=disabled",
            "server_sync=disabled",
            "sd=disabled",
            "meter=disabled",
            "transport=physical_usb",
            "return true;",
        ):
            self.assertIn(marker, offline_recovery)
        for forbidden_boot_call in (
            "clock_.begin(",
            "storage_.begin(",
            "storage_coordinator_.begin(",
            "meter_->begin(",
            "network_.begin(",
            "http_->begin(",
        ):
            self.assertNotIn(forbidden_boot_call, offline_recovery)
        self.assertIn("config_.recordBootStarted()", production_boot)
        self.assertIn("network_.begin()", production_boot)
        self.assertIn("http_->begin()", production_boot)

        handler_start = application.index(
            "void Application::handleSerialCommand(std::string &command)"
        )
        handler_end = application.index(
            "void Application::reportStatus() const", handler_start
        )
        handler = application[handler_start:handler_end]
        recovery_gate = handler.index("#if PM_PHYSICAL_ADMIN_RECOVERY")
        recovery_gate_end = handler.index("#endif", recovery_gate)
        recovery_handler = handler[recovery_gate:recovery_gate_end]
        begin_command = recovery_handler.index(
            'constexpr char kAdminRecoveryBeginPrefix[] = "admin-recovery-begin "'
        )
        ready_reply = recovery_handler.index(
            "writeAdminPasswordRecoveryReady", begin_command
        )
        command_branch = recovery_handler.index(
            'constexpr char kAdminRecoveryPrefix[] = "admin-password "', ready_reply
        )
        self.assertLess(begin_command, ready_reply)
        self.assertLess(ready_reply, command_branch)
        arm_source = recovery_handler[begin_command:command_branch]
        for marker in (
            "kAdminRecoveryWindowMs",
            "admin_recovery_request_id_ = request_id",
            "admin_recovery_deadline_ms_ =",
            "recoveryMonotonicMs() + kAdminRecoveryWindowMs",
            "writeAdminPasswordRecoveryReady",
            "return;",
        ):
            self.assertIn(marker, arm_source)
        secret_source = recovery_handler[command_branch:]
        for marker in (
            "!admin_recovery_complete_",
            "recoveryMonotonicMs() <= admin_recovery_deadline_ms_",
            "crypto::constantTimeEqual(request_id, admin_recovery_request_id_)",
            "admin_recovery_complete_ = true",
            "one_shot_locked=true",
        ):
            self.assertIn(marker, secret_source)
        recovery_boundary = recovery_handler.index(
            '"ADMIN_RECOVERY_COMMAND_REJECTED"', command_branch
        )
        recovery_boundary_source = recovery_handler[recovery_boundary:]
        self.assertIn("permitted=admin_recovery_handshake", recovery_boundary_source)
        self.assertTrue(recovery_boundary_source.rstrip().endswith("return;"))

        password_copy = secret_source.index(
            "std::string password = command.substr(separator + 1U)"
        )
        command_wipe = secret_source.index("wipeString(command)", password_copy)
        generic_command_logging = handler.index(
            "std::string normalized = command", recovery_gate_end
        )
        password_commit = secret_source.index(
            "config_.replaceAdminPasswordForPhysicalRecovery(password)",
        )
        password_wipe = secret_source.index("wipeString(password)", password_commit)
        self.assertLess(password_copy, command_wipe)
        self.assertLess(command_wipe, password_commit)
        self.assertLess(recovery_gate + command_branch, generic_command_logging)
        self.assertLess(password_commit, password_wipe)
        self.assertIn(
            "mbedtls_platform_zeroize(value.data(), value.size())", application
        )
        self.assertIn(
            "const AdminPasswordRecoveryResult recovery_result",
            secret_source,
        )
        self.assertIn(
            "recovery_result != AdminPasswordRecoveryResult::FailedUncertain",
            secret_source,
        )
        self.assertIn(
            "writeAdminPasswordRecoveryResult(\n"
            "              request_id.c_str(), persisted, configuration_preserved)",
            secret_source,
        )
        self.assertNotIn("ESP.restart()", recovery_handler)
        self.assertEqual(len("admin-password ") + 16 + 1 + 63, 95)
        for marker in (
            "PHYSICAL_ADMIN_RECOVERY_BUILD",
            "temporary_firmware=true",
            "restore_esp32_s3_release=true",
            "secret_logged=false",
        ):
            self.assertIn(marker, application)

        config = (ROOT / "src/config/ConfigService.cpp").read_text(encoding="utf-8")
        replacement_start = config.index(
            "ConfigService::replaceAdminPasswordForPhysicalRecovery"
        )
        replacement_end = config.index("#endif", replacement_start)
        replacement_gate = config.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, replacement_start
        )
        self.assertLess(replacement_gate, replacement_start)
        self.assertLess(replacement_start, replacement_end)
        replacement = config[replacement_start:replacement_end]
        for marker in (
            "prepareProvisioningTransaction(journal)",
            "persistAdminVerifier(password)",
            "verifyAdminPassword(password)",
            "clearProvisioningTransaction()",
            "recoverIncompleteProvisioning()",
            "publishRecoveredProvisioningState()",
            "configuration_preserved=true",
            "AdminPasswordRecoveryResult::Applied",
            "AdminPasswordRecoveryResult::RejectedPreserved",
            "AdminPasswordRecoveryResult::FailedUncertain",
        ):
            self.assertIn(marker, replacement)
        for forbidden_recovery_call in (
            "commitPersistentConfig(",
            "commitEnrollmentRecord(",
            "beginReenrollment(",
            "networkReset(",
            "factoryReset(",
        ):
            self.assertNotIn(forbidden_recovery_call, replacement)

        logger_header = (ROOT / "src/diagnostics/SerialLogger.h").read_text(
            encoding="utf-8"
        )
        logger_recovery_declaration = logger_header.index(
            "writeAdminPasswordRecoveryReady"
        )
        logger_gate = logger_header.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, logger_recovery_declaration
        )
        logger_gate_end = logger_header.index("#endif", logger_recovery_declaration)
        self.assertLess(logger_gate, logger_recovery_declaration)
        self.assertLess(logger_recovery_declaration, logger_gate_end)
        logger = (ROOT / "src/diagnostics/SerialLogger.cpp").read_text(encoding="utf-8")
        logger_recovery_start = logger.index("writeAdminPasswordRecoveryReady")
        logger_source_gate = logger.rindex(
            "#if PM_PHYSICAL_ADMIN_RECOVERY", 0, logger_recovery_start
        )
        logger_source_gate_end = logger.index("#endif", logger_recovery_start)
        logger_recovery = logger[logger_source_gate:logger_source_gate_end]
        for marker in (
            "ADMIN_PASSWORD_RECOVERY_READY",
            "ADMIN_PASSWORD_RECOVERY_APPLIED",
            "ADMIN_PASSWORD_RECOVERY_REJECTED",
            "writeAdminPasswordRecoveryResult",
            "configuration_preserved",
            "production_restore_required=true",
        ):
            self.assertIn(marker, logger_recovery)
        self.assertNotIn("reboot_scheduled=true", logger_recovery)

        helper_path = ROOT / "tools/diagnostics/Set-SensorAdminPassword.ps1"
        helper = helper_path.read_text(encoding="utf-8")
        self.assertIn("[string]$Port", helper)
        self.assertNotIn("[string]$Password", helper)
        for marker in (
            "Read-Host",
            "-AsSecureString",
            "admin-recovery-begin",
            "Wait-ForAdminRecoveryReady",
            "ADMIN_PASSWORD_RECOVERY_READY",
            "$serial.Write($commandCharacters",
            "RandomNumberGenerator",
            "ZeroFreeBSTR",
            "Clear-CharacterArray",
            "ADMIN_PASSWORD_RECOVERY_APPLIED",
            "ADMIN_PASSWORD_RECOVERY_REJECTED",
        ):
            self.assertIn(marker, helper)
        helper_main_start = helper.index("$serial = $null")
        helper_main = helper[helper_main_start:]
        begin_write = helper_main.index("admin-recovery-begin")
        ready_wait = helper_main.index("Wait-ForAdminRecoveryReady", begin_write)
        password_prompt = helper_main.index("Read-Host", ready_wait)
        password_command = helper_main.index("admin-password", password_prompt)
        self.assertLess(begin_write, ready_wait)
        self.assertLess(ready_wait, password_prompt)
        self.assertLess(password_prompt, password_command)
        result_timeout = re.search(r"\$resultTimeoutSeconds\s*=\s*(\d+)", helper)
        self.assertIsNotNone(result_timeout)
        assert result_timeout is not None
        self.assertGreaterEqual(int(result_timeout.group(1)), 90)
        self.assertNotIn("rebooted", helper.lower())
        for disclosure in (
            "Write-Host $password",
            "Write-Output $password",
            "Write-Verbose $password",
            "Write-Debug $password",
        ):
            self.assertNotIn(disclosure, helper)

        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if powershell:
            escaped_path = str(helper_path).replace("'", "''")
            parser = (
                "$tokens=$null;$errors=$null;"
                f"[System.Management.Automation.Language.Parser]::ParseFile("
                f"'{escaped_path}',[ref]$tokens,[ref]$errors)|Out-Null;"
                "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 1}"
            )
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command", parser],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_artifact_recovery_identifier_scan(self) -> None:
        production_firmware, production_elf = production_firmware_artifact_paths()
        self.assertEqual(production_firmware.name, "firmware.bin")
        self.assertEqual(production_elf.name, "firmware.elf")
        self.assertIsNone(embedded_recovery_identifier(ROOT / "does-not-exist.bin"))
        self.assertIsNone(recovery_identifier_in_contents(b"production firmware"))
        self.assertEqual(
            recovery_identifier_in_contents(
                b"prefix\x00"
                + RECOVERY_FIRMWARE_IDENTIFIERS[0].encode("ascii")
                + b"\x00suffix"
            ),
            RECOVERY_FIRMWARE_IDENTIFIERS[0],
        )
        self.assertEqual(
            recovery_identifier_in_contents(
                b"prefix\x00"
                + RECOVERY_FIRMWARE_IDENTIFIERS[-1].encode("ascii")
                + b"\x00suffix"
            ),
            RECOVERY_FIRMWARE_IDENTIFIERS[-1],
        )

    def test_negotiation_and_pagination_fixtures_are_unambiguous(self) -> None:
        negotiation = json.loads(
            (ROOT / "shared/fixtures/protocol-negotiation.json").read_text()
        )
        self.assertEqual(negotiation["supported"], ["pm-protocol/1.0.0"])
        self.assertEqual(
            [case["status"] for case in negotiation["cases"]], [200, 409, 400]
        )
        page = json.loads((ROOT / "shared/fixtures/pagination.json").read_text())
        self.assertEqual(
            page["response"]["next_after_sequence"], page["response"]["last_sequence"]
        )
        self.assertEqual(page["gone_problem"]["status"], 410)

    def test_current_power_monitor_server_wire_contract_is_used(self) -> None:
        contract = yaml.safe_load(
            (ROOT / "shared/openapi/server-ingest-api.yaml").read_text(encoding="utf-8")
        )
        claim = contract["components"]["schemas"]["EnrollmentClaim"]
        self.assertEqual(
            set(claim["required"]),
            {"token", "protocol_version", "hardware_id", "capabilities"},
        )
        self.assertIn(
            "201",
            contract["paths"]["/api/v1/device-enrollment/claim"]["post"]["responses"],
        )
        heartbeat = contract["components"]["schemas"]["Heartbeat"]
        self.assertEqual(
            heartbeat["properties"]["schema_version"]["const"],
            "heartbeat/1.0.0",
        )
        self.assertIn("oldest_syncable_sequence", heartbeat["properties"])
        batch = contract["components"]["schemas"]["ReadingBatch"]
        self.assertEqual(
            batch["properties"]["schema_version"]["const"],
            "reading-batch/1.0.0",
        )
        self.assertIn("readings", batch["required"])
        self.assertIn("unavailable_sequence_ranges", batch["properties"])

        firmware_manifest = contract["components"]["schemas"]["FirmwareManifest"]
        available_release = firmware_manifest["oneOf"][1]
        self.assertEqual(
            set(available_release["required"]),
            {
                "deployment_id",
                "version",
                "channel",
                "hardware_target",
                "protocol_min",
                "protocol_max",
                "size_bytes",
                "sha256",
                "signature",
                "signing_key_id",
                "release_notes",
                "download_path",
            },
        )
        self.assertEqual(
            contract["paths"]["/api/v1/device-firmware/{release_id}/download"]["get"][
                "security"
            ],
            [{"deviceHmac": []}],
        )

        firmware_source = (ROOT / "src/network/ServerSync.cpp").read_text(
            encoding="utf-8"
        )
        for marker in (
            'document["token"]',
            'document["protocol_version"]',
            '"heartbeat/1.0.0"',
            '"reading-batch/1.0.0"',
            'document["readings"]',
            'document["unavailable_sequence_ranges"]',
            'result["highest_contiguous_accepted_sequence"]',
            'report["version"]',
            "single_flight_.consumePending()",
            "next_retry_ms_ = 0;",
            "response.status != 201",
            "crypto::canonicalTarget(endpoint",
            "requestConfigurationApply(0)",
            "http.header(retry_after_header)",
            "MDNS.queryHost",
            '"TLS", "TLS_SUCCESS"',
            "reason=heartbeat_failed remaining_operations=deferred",
            '"response_length_required"',
            '"READ_BATCH_REJECTED"',
            '"EVENT_BATCH_REJECTED"',
            '"READ_BATCH_NO_PROGRESS"',
            "retryDelayMs(retry_after_ms)",
            '"RETRY_BYPASS_DEFERRED"',
            '"REMOTE_NETWORK_UPDATE_SUPERSEDED"',
            "config_.rollbackToPrevious(\n          pending_config_generation_",
            "config_.rollbackToPrevious(applied_generation)",
            '"ASSIGNMENT_SAVE_DEFERRED"',
            "base = retry_after_ms;",
            "sync_policy::kReadingBatchPayloadBytes",
            "sync_policy::kEventBatchPayloadBytes",
            "sync_policy::classifyTlsMemory",
            "endpoint_address_cache_.lookup",
            "endpoint_address_cache_.recordTransportFailure",
            "readBoundedResponseBody",
            '"TRANSACTION_START"',
            '"TRANSACTION_COMPLETE"',
            '"TRANSACTION_FAILED"',
        ):
            self.assertIn(marker, firmware_source)
        for forbidden in (
            "setInsecure(",
            "portMAX_DELAY",
            "static constexpr int max_response_bytes = 128 * 1024",
            "http.getString()",
        ):
            self.assertNotIn(forbidden, firmware_source)

        sync_policy_header = (ROOT / "src/network/ServerSyncPolicy.h").read_text(
            encoding="utf-8"
        )
        contiguous_guard = re.search(
            r"kMinimumLargestInternalBlockBytes\s*=\s*(\d+)U\s*\*\s*1024U",
            sync_policy_header,
        )
        self.assertIsNotNone(contiguous_guard)
        assert contiguous_guard is not None
        self.assertGreaterEqual(int(contiguous_guard.group(1)), 32)

        network_source = (ROOT / "src/network/NetworkService.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("WiFi.setSleep(false)", network_source)
        self.assertNotIn("WiFi.setSleep(true)", network_source)

        local_api_source = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        for marker in (
            "classifyAuthMode(request, session_cookie)",
            "RequestAuthMode::LocalBrowserSession",
            "RequestAuthMode::ServerToDeviceHmac",
            "RequestAuthMode::MalformedMixedAuthentication",
            '"BROWSER_HMAC_FALLBACK_PREVENTED"',
            '"EVT_LOCAL_SESSION_REJECTED"',
            '"EVT_SERVER_HMAC_REJECTED"',
        ):
            self.assertIn(marker, local_api_source)
        auth_header = (ROOT / "src/security/AuthService.h").read_text(encoding="utf-8")
        self.assertIn("static constexpr std::size_t kCapacity = 6U", auth_header)
        self.assertIn("std::array<Entry, kCapacity>", auth_header)
        sync_source = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        self.assertIn(
            'http.addHeader("X-Request-ID", correlation_id.data())', sync_source
        )
        self.assertIn('"pm-%s-%lu"', sync_source)
        self.assertIn("transport_boot_id_.c_str()", sync_source)
        self.assertNotIn('"pm-" + config_.identity().boot_id', sync_source)
        self.assertGreaterEqual(
            local_api_source.count('addHeader("Connection", "close", false)'),
            8,
            "local UI/API responses must bound AsyncTCP connection lifetime",
        )
        local_health_start = local_api_source.index('"/api/local/health"')
        local_health_end = local_api_source.index(
            'server_.on("/api/v1/info"', local_health_start
        )
        local_health_source = local_api_source[local_health_start:local_health_end]
        self.assertNotIn("authorize(request", local_health_source)
        self.assertNotIn("readPage(", local_health_source)
        self.assertNotIn("requestImmediateSync", local_health_source)
        for field in (
            '"heartbeat_successes"',
            '"heartbeat_failures"',
            '"stack_margin_percent"',
            '"free_internal_heap_bytes"',
            '"largest_internal_block_bytes"',
        ):
            self.assertIn(field, local_health_source)

        ota_source = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        for marker in (
            "crypto_sign_ed25519_verify_detached",
            "addDeviceAuthentication",
            "ResolvedTlsClient",
            "resolveHttpsTarget",
            "MDNS.queryHost",
            "setResolvedEndpoint",
            '"release_notes"',
            '"ota_public_key_unavailable"',
            '"ota_server_origin_required"',
        ):
            self.assertIn(marker, ota_source)
        config_source = (ROOT / "src/config/ConfigService.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('"ota_trust_local_route_required"', config_source)

        tick_start = firmware_source.index("void ServerSync::tick()")
        pending_validation = firmware_source.index(
            "if (pending_config_validation_)", tick_start
        )
        offline_gate = firmware_source.index(
            "if (!network.station_connected || !clock_.synchronized()",
            tick_start,
        )
        self.assertLess(
            pending_validation,
            offline_gate,
            "offline remote Wi-Fi changes must still reach the rollback timer",
        )

        enrollment_start = firmware_source.index("bool ServerSync::enroll")
        enrollment_credentials = firmware_source.index(
            "config_.saveEnrollment(", enrollment_start
        )
        enrollment_metadata = firmware_source.index(
            "config_.commitCandidate(assigned", enrollment_start
        )
        self.assertLess(
            enrollment_credentials,
            enrollment_metadata,
            "consumed one-time enrollment tokens require credentials to become durable first",
        )

        readings_start = firmware_source.index("bool ServerSync::pushReadings")
        readings_rejected = firmware_source.index(
            '"READ_BATCH_REJECTED"', readings_start
        )
        readings_cursor_commit = firmware_source.index(
            "config_.setServerAckSequence(acknowledgement)", readings_start
        )
        self.assertLess(readings_rejected, readings_cursor_commit)

        events_start = firmware_source.index("bool ServerSync::pushEvents")
        events_rejected = firmware_source.index('"EVENT_BATCH_REJECTED"', events_start)
        events_cursor_commit = firmware_source.index(
            "event_cursor_ = acknowledged_event_sequence", events_start
        )
        self.assertLess(events_rejected, events_cursor_commit)

        crypto_source = (ROOT / "src/security/Crypto.cpp").read_text(encoding="utf-8")
        for marker in (
            "esp_timer_get_time() - started_us >= budget_us",
            "output.fill(0);",
            "vTaskDelay(pdMS_TO_TICKS(1));",
        ):
            self.assertIn(marker, crypto_source)
        config_source = (ROOT / "src/config/ConfigService.cpp").read_text(
            encoding="utf-8"
        )
        self.assertRegex(config_source, r"actual,\s*15'000U")
        self.assertRegex(config_source, r"hash,\s*15'000U")
        self.assertIn("network_settings_route_required", config_source)
        clock_source = (ROOT / "src/network/ClockService.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("trust_state=revoked", clock_source)
        self.assertIn("sntp_confirmed_ = false", clock_source)

        server_protocol = ROOT.parent / "power-monitor/shared/protocol-version.txt"
        if server_protocol.is_file():
            self.assertEqual(
                server_protocol.read_text(encoding="utf-8").strip(),
                "pm-protocol/1.0.0",
            )

    def test_sd_remount_recovers_an_interrupted_spi_transaction_safely(self) -> None:
        source = (ROOT / "src/storage/SdStorage.cpp").read_text(encoding="utf-8")
        for marker in (
            "kSdIdleClockBytes = 10U",
            "digitalWrite(pins::SD_CS, HIGH)",
            "spi.transfer(0xFFU)",
            "const std::array<std::uint32_t, 4> attempt_hz",
            "for (const std::uint32_t candidate_hz : attempt_hz)",
            "delay(static_cast<std::uint32_t>(attempt) * 25U)",
            "format_on_failure=false",
            "format_attempted=false",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("candidate_hz == previous_hz", source)
        for marker in (
            "publishHealthSnapshot(health_);",
            "publishHealthSnapshot(copy);",
            "last_health_snapshot_",
            "storage_health_snapshot_busy",
            "lock(pdMS_TO_TICKS(100))",
            "snapshot = last_health_snapshot_",
            "A heartbeat must not interpret that temporary",
            "acknowledged_sequence <= current_floor",
            "reason=current_floor_satisfies_required",
            "std::size_t scanned_records = 0;",
            "std::size_t scanned_bytes = 0;",
            "std::size_t copied_chunks = 0;",
            "scanned_records % kCooperativeScanRecords == 0U",
            "scanned_bytes % kCooperativeScanBytes == 0U",
            "copied_chunks % kCooperativeScanRecords == 0U",
            "index_count % kCooperativeScanRecords == 0U",
            "scanned_event_records % kCooperativeScanRecords == 0U",
        ):
            self.assertIn(marker, source)
        coordinator = (ROOT / "src/storage/StorageCoordinator.cpp").read_text(
            encoding="utf-8"
        )
        for marker in (
            "bool StorageCoordinator::remountStorage()",
            "HighMemoryLease memory_lease(diagnostics_);",
            "return storage_.remountPreferred();",
            "HISTORY_DEFERRED_AT_RECOVERY_SPEED",
            "request->events || !request->primary_sync",
        ):
            self.assertIn(marker, coordinator)
        self.assertNotIn("storage_.remount(storage_.health().spi_hz)", coordinator)
        task_config = (ROOT / "include/app/TaskConfig.h").read_text(encoding="utf-8")
        application = (ROOT / "src/app/Application.cpp").read_text(encoding="utf-8")
        self.assertIn("kAggregationPriority = 3U", task_config)
        self.assertIn("kStoragePriority = 0U", task_config)
        self.assertIn("time-slices recovery with IDLE0", task_config)
        self.assertIn("kStorageStackBytes = 12288U", task_config)
        self.assertIn("kHealthStackBytes = 12288U", task_config)
        self.assertIn("task_config::kAggregationPriority", application)
        self.assertIn("task_config::kStoragePriority", application)
        self.assertIn("&storage_task_, 0);", application)
        self.assertIn("&network_task_, 1);", application)
        self.assertIn("&sync_task_, 1);", application)
        self.assertIn("ScopedFatDirectoryWatchdogGuard", source)
        self.assertIn("esp_task_wdt_delete(idle_task_)", source)
        self.assertIn("esp_task_wdt_add(idle_task_)", source)
        self.assertIn('"BOOT_MOUNT_RETRY"', application)
        self.assertIn("last_retention_ms = clock_.monotonicMs()", application)
        self.assertIn(
            "last_storage_cleanup_ack_sequence_ = config_.serverAckSequence()",
            application,
        )
        self.assertIn(
            "startup_measurement_config.storage_cleanup_request_id", application
        )
        header = (ROOT / "src/storage/SdStorage.h").read_text(encoding="utf-8")
        self.assertIn("bool remountPreferred();", header)
        self.assertIn("preferred_spi_hz_{0}", header)
        self.assertIn("health_snapshot_mutex_", header)
        self.assertIn("last_health_snapshot_", header)
        self.assertIn("return remountPreferred();", source)
        server_sync = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        self.assertIn("kHeartbeatStorageWaitMs = 20'000U", server_sync)
        self.assertIn('endpoint == "/api/v1/device-heartbeats"', server_sync)

    def test_sd_history_pages_are_globally_sequence_ordered(self) -> None:
        source = (ROOT / "src/storage/SdStorage.cpp").read_text(encoding="utf-8")
        for marker in (
            "std::lower_bound(",
            "health_.newest_sequence > page.last_sequence",
            'page.error_code = "record_exceeds_page_limit"',
            "query.require_syncable && !syncableDocument(document)",
            "health_.oldest_syncable_sequence",
            "vTaskDelay(pdMS_TO_TICKS(1));",
            "page.unavailable_sequence_ranges",
            "HISTORY_SEGMENT_SKIPPED",
            "segment.last_sequence <= query.after_sequence",
            "segment.first_sequence > scan_ceiling",
            "segment.closed &&",
            "segment.complete &&",
            "RECOVERY_SEGMENT_METADATA_ACCEPTED",
            "reason=index_range_empty",
            "indexed_start_offset",
        ):
            self.assertIn(marker, source)
        self.assertIn(
            "Active segments and any segment with missing/incomplete metadata",
            source,
        )
        server_sync = (ROOT / "src/network/ServerSync.cpp").read_text(encoding="utf-8")
        self.assertIn("query.require_syncable = true", server_sync)
        self.assertIn("sequence_state.storage_mounted &&", server_sync)
        self.assertIn('"SEQUENCE_RECONCILIATION_DEFERRED"', server_sync)
        self.assertIn('document["oldest_syncable_sequence"]', server_sync)
        self.assertIn(
            'SD.begin(pins::SD_CS, spi_, candidate_hz, "/sd", 8, false)', source
        )
        self.assertNotIn(
            'SD.begin(pins::SD_CS, spi_, candidate_hz, "/sd", 8, true)', source
        )

    def test_physical_heartbeat_soak_fails_closed(self) -> None:
        source = (ROOT / "tools/diagnostics/Test-SensorHeartbeatSoak.ps1").read_text(
            encoding="utf-8"
        )
        for marker in (
            "$handler.UseProxy = $false",
            "[System.Net.NetworkInformation.Ping]::new()",
            "[int]$PingAttempts = 3",
            "$pingAttempt -le $PingAttempts",
            "$pingProbe.Send($Address, 400)",
            "$pingFailures -eq 0",
            "$webFailures -eq 0",
            "$healthFailures -eq 0",
            "$wifiFailures -eq 0",
            "$storageFailures -eq 0",
            "$minimumStackMargin -ge 25",
        ):
            self.assertIn(marker, source)

    def test_two_sensor_monitor_respects_local_session_limits(self) -> None:
        source = (ROOT / "tools/diagnostics/Monitor-TwoSensors.ps1").read_text(
            encoding="utf-8"
        )
        for marker in (
            "-Headers @{ Origin = $Client.Url }",
            "NextSessionAttempt",
            "AddSeconds(60)",
            '"$($client.Url)/api/local/health"',
            "session_degraded = $true",
            "heartbeat_successes = $health.heartbeat_successes",
            "acknowledged_sequence = $health.server_ack_sequence",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("pm_session=", source)
        self.assertNotIn("pm_csrf=", source)

    def test_local_session_response_preserves_both_set_cookie_headers(self) -> None:
        source = (ROOT / "src/api/HttpApi.cpp").read_text(encoding="utf-8")
        self.assertIn(
            'response->addHeader("Set-Cookie", csrf_cookie.c_str(), false);',
            source,
        )
        self.assertEqual(
            2,
            len(re.findall(r'"pm_csrf=;[^\"]*",\s*false\)', source)),
        )

    def test_current_server_hmac_vector_matches_sensor_signer(self) -> None:
        vector_path = (
            ROOT.parent / "power-monitor/shared/auth-test-vectors/hmac-sha256-v1.json"
        )
        if not vector_path.is_file():
            self.skipTest("sibling Power Monitor Server repository is not available")
        document = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(document["protocol"], "pm-protocol/1.0.0")
        vector = document["vectors"][0]
        secret = bytes.fromhex(vector["secret"])
        info = (
            b"pm-device-to-server-v1"
            if vector["direction"] == "device-to-server"
            else b"pm-server-to-device-v1"
        )
        key = hkdf_sha256(secret, info)
        self.assertEqual(key.hex(), vector["derived_key_hex"])
        body = vector["body_utf8"].encode()
        self.assertEqual(body_sha256(body), vector["content_sha256"])
        self.assertEqual(
            canonical_path_query(vector["target_input"]),
            vector["canonical_target"],
        )
        self.assertEqual(
            canonical_string(
                vector["method"],
                vector["target_input"],
                vector["timestamp"],
                vector["nonce"],
                vector["content_sha256"],
            ),
            vector["canonical_string"],
        )
        headers = sign(
            key,
            vector["method"],
            vector["target_input"],
            vector["timestamp"],
            vector["nonce"],
            body,
        )
        self.assertEqual(headers["X-PM-Signature"], vector["signature"])


if __name__ == "__main__":
    unittest.main()

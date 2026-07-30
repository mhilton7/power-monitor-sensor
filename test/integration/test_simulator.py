from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from simulator import server as server_module
from simulator.protocol import PROTOCOL, hkdf_sha256, sign
from simulator.server import (
    DEFAULT_ENROLLMENT_TOKEN_ENV,
    ENROLLMENT_ENDPOINT,
    HEARTBEAT_ENDPOINT,
    ServerState,
    load_enrollment_token,
    serve,
)


def derive_test_token(label: str) -> str:
    """Derive a non-production test value without committing an enrollment token."""

    return hashlib.sha256(f"pm-simulator-test:{label}".encode()).hexdigest()


class SimulatorIntegrationTests(unittest.TestCase):
    now_seconds = 1_800_000_000

    def setUp(self) -> None:
        self.enrollment_token = derive_test_token("primary")
        self.state = ServerState(
            enrollment_token=self.enrollment_token,
            enrollment_token_expires_at=self.now_seconds + 300,
            clock=lambda: self.now_seconds,
        )
        self.server = serve("127.0.0.1", 0, self.state, None, None)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request_bytes(
        self,
        method: str,
        path: str,
        body: bytes,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                payload = json.loads(response.read() or b"{}")
                return response.status, payload, dict(response.headers.items())
        except urllib.error.HTTPError as error:
            payload = json.loads(error.read() or b"{}")
            return error.code, payload, dict(error.headers.items())

    def request(
        self,
        method: str,
        path: str,
        payload: object,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        return self.request_bytes(method, path, body, headers)

    def claim_payload(
        self,
        *,
        token: str | None = None,
        hardware_id: str = "esp32s3-test-0001",
    ) -> dict:
        return {
            "protocol_version": PROTOCOL,
            "token": self.enrollment_token if token is None else token,
            "hardware_id": hardware_id,
            "requested_name": "Simulator sensor",
            "capabilities": {
                "hardware_target": "esp32-s3-devkitc-1",
                "pzem_model": "PZEM-004T V4.0",
                "sd_present": True,
                "sd_required": True,
                "supported_endpoints": [
                    "/api/v1/health",
                    "/api/v1/readings",
                ],
            },
        }

    def enroll(self, *, hardware_id: str = "esp32s3-test-0001") -> tuple[str, bytes]:
        status, result, _headers = self.request(
            "POST",
            "/api/v1/device-enrollment/claim",
            self.claim_payload(hardware_id=hardware_id),
        )
        self.assertEqual(status, 201)
        self.assertEqual(result["protocol_version"], PROTOCOL)
        return result["device_id"], result["enrollment_secret"].encode("ascii")

    def heartbeat_payload(self, device_id: str) -> dict:
        return {
            "schema_version": "heartbeat/1.0.0",
            "protocol_version": PROTOCOL,
            "device_id": device_id,
            "boot_id": "44f16f01-46c9-4ea4-9bf7-f194269dd048",
            "firmware_version": "1.0.0",
            "firmware_build_hash": "test",
            "uptime_seconds": 60,
            "reboot_reason": "power_on",
            "current_ip": "192.168.1.50",
            "hostname": "power-monitor-test",
            "rssi_dbm": -50,
            "connection_mode": "push",
            "latest": None,
            "pzem": {
                "ok": True,
                "status": "healthy",
                "error_count": 0,
                "details": {},
            },
            "sd": {
                "ok": True,
                "status": "healthy",
                "error_count": 0,
                "details": {},
            },
            "oldest_stored_sequence": 0,
            "newest_stored_sequence": 0,
            "server_ack_sequence": 0,
            "backlog_estimate": 0,
            "configuration_version": 0,
            "time": {"trusted": True, "source": "sntp", "offset_ms": 0},
            "resources": {},
            "queue": {},
        }

    def authenticated(
        self,
        device_id: str,
        secret: bytes,
        path: str,
        payload: dict,
        nonce: str,
        *,
        signing_secret: bytes | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        key = hkdf_sha256(
            secret if signing_secret is None else signing_secret,
            b"pm-device-to-server-v1",
        )
        headers = sign(
            key,
            "POST",
            path,
            str(self.now_seconds),
            nonce,
            body,
        )
        headers["X-PM-Device-ID"] = device_id
        return self.request_bytes("POST", path, body, headers)

    def authenticated_get(
        self,
        device_id: str,
        secret: bytes,
        path: str,
        nonce: str,
    ) -> tuple[int, dict, dict[str, str]]:
        key = hkdf_sha256(secret, b"pm-device-to-server-v1")
        headers = sign(
            key,
            "GET",
            path,
            str(self.now_seconds),
            nonce,
            b"",
        )
        headers["X-PM-Device-ID"] = device_id
        return self.request_bytes("GET", path, b"", headers)

    def authenticated_get_bytes(
        self,
        device_id: str,
        secret: bytes,
        path: str,
        nonce: str,
    ) -> tuple[int, bytes, dict[str, str]]:
        key = hkdf_sha256(secret, b"pm-device-to-server-v1")
        headers = sign(
            key,
            "GET",
            path,
            str(self.now_seconds),
            nonce,
            b"",
        )
        headers["X-PM-Device-ID"] = device_id
        request = urllib.request.Request(
            self.base + path,
            method="GET",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, response.read(), dict(response.headers.items())
        except urllib.error.HTTPError as error:
            return error.code, error.read(), dict(error.headers.items())

    @staticmethod
    def reading(sequence: int, value: float = 10.0) -> dict:
        return {
            "sequence": sequence,
            "boot_id": "44f16f01-46c9-4ea4-9bf7-f194269dd048",
            "interval_start": "2026-07-28T10:00:00Z",
            "interval_end": "2026-07-28T10:01:00Z",
            "time_trusted": True,
            "voltage_avg": 120.0,
            "voltage_min": 119.5,
            "voltage_max": 120.5,
            "current_avg": 1.0,
            "current_min": 0.9,
            "current_max": 1.1,
            "power_avg": value,
            "power_min": value,
            "power_max": value,
            "power_factor": 0.98,
            "frequency_hz": 60.0,
            "pzem_energy_start_wh": 1000,
            "pzem_energy_end_wh": 1010,
            "device_lifetime_energy_wh": 1010,
            "interval_energy_wh": 10,
            "energy_method": "pzem_delta",
            "ct_rating_amps": 100,
            "quality_flags": [],
            "firmware_version": "1.0.0",
        }

    @staticmethod
    def batch(device_id: str, *records: dict) -> dict:
        return {
            "protocol_version": PROTOCOL,
            "schema_version": "reading-batch/1.0.0",
            "device_id": device_id,
            "readings": list(records),
        }

    def test_successful_enrollment_heartbeat_readings_replay_and_rejection(
        self,
    ) -> None:
        device_id, secret = self.enroll()
        heartbeat = self.heartbeat_payload(device_id)
        heartbeat_path = "/api/v1/device-heartbeats"
        nonce = "10" * 16

        status, result, _headers = self.authenticated(
            device_id, secret, heartbeat_path, heartbeat, nonce
        )
        self.assertEqual(
            (status, result["highest_contiguous_accepted_sequence"]),
            (200, 0),
        )
        status, result, _headers = self.authenticated(
            device_id, secret, heartbeat_path, heartbeat, nonce
        )
        self.assertEqual((status, result["code"]), (401, "nonce_replayed"))

        readings_path = "/api/v1/device-readings/batch"
        status, result, _headers = self.authenticated(
            device_id,
            secret,
            readings_path,
            self.batch(device_id, self.reading(2)),
            "20" * 16,
        )
        self.assertEqual(
            (
                status,
                result["highest_contiguous_accepted_sequence"],
                result["missing_ranges"],
            ),
            (200, 0, [[1, 1]]),
        )

        status, result, _headers = self.authenticated(
            device_id,
            secret,
            readings_path,
            self.batch(device_id, self.reading(1), self.reading(2)),
            "30" * 16,
        )
        self.assertEqual(
            (
                status,
                result["accepted"],
                result["duplicates"],
                result["highest_contiguous_accepted_sequence"],
            ),
            (200, [1], [2], 2),
        )

        status, result, _headers = self.authenticated(
            device_id,
            secret,
            readings_path,
            self.batch(device_id, self.reading(1)),
            "40" * 16,
        )
        self.assertEqual((status, result["duplicates"]), (200, [1]))

        status, result, _headers = self.authenticated(
            device_id,
            secret,
            readings_path,
            self.batch(device_id, self.reading(1, 11.0), self.reading(3)),
            "50" * 16,
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["accepted"], [3])
        self.assertEqual(result["highest_contiguous_accepted_sequence"], 3)
        self.assertEqual(
            result["rejected"],
            [
                {
                    "sequence": 1,
                    "code": "conflicting_duplicate",
                    "detail": "Sequence already exists with different content.",
                }
            ],
        )
        self.assertEqual(self.state.devices[device_id].records[1], self.reading(1))

    def test_authenticated_firmware_manifest_and_binary_download(self) -> None:
        binary = b"simulated-esp32-application-image"
        digest = hashlib.sha256(binary).hexdigest()
        release_id = self.state.configure_firmware(
            {
                "version": "1.0.1",
                "channel": "stable",
                "hardware_target": "esp32-s3-n16r8",
                "protocol_min": PROTOCOL,
                "protocol_max": PROTOCOL,
                "sha256": digest,
                "signature": base64.b64encode(bytes(64)).decode("ascii"),
                "signing_key_id": "simulator-ed25519",
                "release_notes": "Offline simulator contract fixture.",
            },
            binary,
            release_id="3a25ac40-5cd2-4cc8-9c8a-c8e607b6344c",
        )
        device_id, secret = self.enroll()
        manifest_path = "/api/v1/device-firmware/manifest"
        status, manifest, _headers = self.authenticated_get(
            device_id,
            secret,
            manifest_path,
            "60" * 16,
        )
        self.assertEqual(status, 200)
        self.assertTrue(manifest["available"])
        self.assertEqual(
            manifest["release_notes"], "Offline simulator contract fixture."
        )
        self.assertEqual(manifest["size_bytes"], len(binary))
        download_path = f"/api/v1/device-firmware/{release_id}/download"
        self.assertEqual(manifest["download_path"], download_path)

        status, downloaded, headers = self.authenticated_get_bytes(
            device_id,
            secret,
            download_path,
            "61" * 16,
        )
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, binary)
        self.assertEqual(
            headers["Digest"],
            "SHA-256="
            + base64.b64encode(hashlib.sha256(binary).digest()).decode("ascii"),
        )

    def test_enrollment_fault_matrix_expiry_validation_and_single_use(
        self,
    ) -> None:
        path = "/api/v1/device-enrollment/claim"

        status, result, _headers = self.request_bytes("POST", path, b"{")
        self.assertEqual((status, result["code"]), (400, "json_invalid"))
        status, result, _headers = self.request("POST", path, [])
        self.assertEqual((status, result["code"]), (400, "json_object_required"))

        for status_code in (400, 403, 409, 422):
            with self.subTest(injected_status=status_code):
                code = f"injected_enrollment_{status_code}"
                self.state.queue_fault(
                    ENROLLMENT_ENDPOINT,
                    status_code,
                    code,
                    "Deterministic enrollment test fault.",
                )
                status, result, _headers = self.request(
                    "POST", path, self.claim_payload()
                )
                self.assertEqual((status, result["code"]), (status_code, code))
                self.assertFalse(self.state.token_used)
                self.assertEqual(self.state.devices, {})

        mismatched = self.claim_payload()
        mismatched["protocol_version"] = "pm-protocol/0.0.0"
        status, result, _headers = self.request("POST", path, mismatched)
        self.assertEqual((status, result["code"]), (409, "protocol_mismatch"))
        self.assertFalse(self.state.token_used)

        invalid = self.claim_payload()
        invalid["capabilities"]["sd_present"] = False
        status, result, _headers = self.request("POST", path, invalid)
        self.assertEqual((status, result["code"]), (422, "claim_invalid"))
        self.assertFalse(self.state.token_used)

        self.state.enrollment_token_expires_at = self.now_seconds
        status, result, _headers = self.request("POST", path, self.claim_payload())
        self.assertEqual(
            (status, result["code"]),
            (401, "enrollment_token_expired"),
        )
        self.assertFalse(self.state.token_used)

        self.state.enrollment_token_expires_at = self.now_seconds + 300
        device_id, _secret = self.enroll()
        status, result, _headers = self.request(
            "POST",
            path,
            self.claim_payload(hardware_id="esp32s3-test-0002"),
        )
        self.assertEqual(
            (status, result["code"]),
            (401, "invalid_enrollment_token"),
        )
        self.assertEqual(list(self.state.devices), [device_id])

        replacement = derive_test_token("replacement")
        self.enrollment_token = replacement
        self.state.issue_enrollment_token(
            replacement, expires_at=self.now_seconds + 300
        )
        status, result, _headers = self.request(
            "POST",
            path,
            self.claim_payload(token=replacement, hardware_id="esp32s3-test-0001"),
        )
        self.assertEqual((status, result["code"]), (409, "hardware_exists"))
        self.assertFalse(self.state.token_used)

    def test_heartbeat_auth_and_deterministic_fault_matrix(self) -> None:
        device_id, secret = self.enroll()
        heartbeat = self.heartbeat_payload(device_id)
        path = "/api/v1/device-heartbeats"

        status, result, _headers = self.authenticated(
            device_id,
            secret,
            path,
            heartbeat,
            "60" * 16,
            signing_secret=b"not-the-enrolled-secret",
        )
        self.assertEqual((status, result["code"]), (401, "signature_invalid"))

        for index, status_code in enumerate((401, 403, 409, 429, 503), start=1):
            with self.subTest(injected_status=status_code):
                code = f"injected_heartbeat_{status_code}"
                retry_after = 7 if status_code in {429, 503} else None
                self.state.queue_fault(
                    HEARTBEAT_ENDPOINT,
                    status_code,
                    code,
                    "Deterministic heartbeat test fault.",
                    retry_after,
                )
                status, result, headers = self.authenticated(
                    device_id,
                    secret,
                    path,
                    heartbeat,
                    f"{index + 6:02x}" * 16,
                )
                self.assertEqual((status, result["code"]), (status_code, code))
                if retry_after is not None:
                    self.assertEqual(headers["Retry-After"], str(retry_after))
                self.assertIsNone(self.state.devices[device_id].last_heartbeat)

        mismatched = self.heartbeat_payload("8f29ce3e-7554-4e14-980d-70d60aef5500")
        status, result, _headers = self.authenticated(
            device_id, secret, path, mismatched, "70" * 16
        )
        self.assertEqual((status, result["code"]), (403, "device_id_mismatch"))

        status, _result, _headers = self.authenticated(
            device_id, secret, path, heartbeat, "80" * 16
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.state.devices[device_id].last_heartbeat, heartbeat)

    def test_concurrent_claims_cannot_reuse_one_time_token(self) -> None:
        path = "/api/v1/device-enrollment/claim"
        start = threading.Barrier(3)
        statuses: list[int] = []
        results_lock = threading.Lock()

        def claim(hardware_id: str) -> None:
            start.wait(timeout=2)
            status, _result, _headers = self.request(
                "POST", path, self.claim_payload(hardware_id=hardware_id)
            )
            with results_lock:
                statuses.append(status)

        workers = [
            threading.Thread(target=claim, args=("esp32s3-race-0001",)),
            threading.Thread(target=claim, args=("esp32s3-race-0002",)),
        ]
        for worker in workers:
            worker.start()
        start.wait(timeout=2)
        for worker in workers:
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())

        self.assertEqual(sorted(statuses), [201, 401])
        self.assertEqual(len(self.state.devices), 1)
        self.assertTrue(self.state.token_used)


class SimulatorTokenInputTests(unittest.TestCase):
    def test_token_loads_from_environment_or_external_file(self) -> None:
        from_environment = derive_test_token("environment")
        self.assertEqual(
            load_enrollment_token(
                None,
                DEFAULT_ENROLLMENT_TOKEN_ENV,
                {DEFAULT_ENROLLMENT_TOKEN_ENV: from_environment},
            ),
            from_environment,
        )

        from_file = derive_test_token("file")
        token_path = Path("external-enrollment-token.txt")
        with patch.object(Path, "read_text", return_value=from_file + "\n"):
            self.assertEqual(
                load_enrollment_token(token_path, DEFAULT_ENROLLMENT_TOKEN_ENV, {}),
                from_file,
            )

        with self.assertRaisesRegex(ValueError, "32 through 256"):
            load_enrollment_token(
                None,
                DEFAULT_ENROLLMENT_TOKEN_ENV,
                {DEFAULT_ENROLLMENT_TOKEN_ENV: "too-short"},
            )

    def test_cli_does_not_display_or_persist_token(self) -> None:
        token = derive_test_token("cli")

        class FakeServer:
            server_port = 8088

            def serve_forever(self) -> None:
                raise KeyboardInterrupt

            def server_close(self) -> None:
                return

        output = io.StringIO()
        with (
            patch.dict(
                "os.environ",
                {DEFAULT_ENROLLMENT_TOKEN_ENV: token},
                clear=True,
            ),
            patch("simulator.server.serve", return_value=FakeServer()),
            contextlib.redirect_stdout(output),
        ):
            server_module.main(["--port", "0"])

        rendered = output.getvalue()
        self.assertFalse(token in rendered)
        self.assertFalse("One-time enrollment token:" in rendered)
        self.assertIn("will not display or persist it", rendered)


if __name__ == "__main__":
    unittest.main()

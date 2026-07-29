from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request

from simulator.protocol import PROTOCOL, hkdf_sha256, sign
from simulator.server import ServerState, serve


class SimulatorIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = ServerState(enrollment_token="single-use-local-enrollment-token")
        self.server = serve("127.0.0.1", 0, self.state, None, None)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, payload: dict, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def enroll(self) -> tuple[str, bytes]:
        status, result = self.request("POST", "/api/v1/device-enrollment/claim", {
            "protocol_version": PROTOCOL,
            "token": self.state.enrollment_token,
            "hardware_id": "esp32s3-test",
            "requested_name": "Simulator sensor",
            "capabilities": {
                "hardware_target": "esp32-s3-devkitc-1",
                "pzem_model": "PZEM-004T V4",
                "sd_present": True,
                "sd_required": True,
                "supported_endpoints": ["/api/v1/health", "/api/v1/readings"],
            },
        })
        self.assertEqual(status, 201)
        self.assertEqual(result["protocol_version"], PROTOCOL)
        return result["device_id"], result["enrollment_secret"].encode("ascii")

    def authenticated(self, device_id: str, secret: bytes, path: str, payload: dict, nonce: str) -> tuple[int, dict]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = sign(hkdf_sha256(secret, b"pm-device-to-server-v1"), "POST", path,
                       str(int(time.time())), nonce, body)
        headers["X-PM-Device-ID"] = device_id
        request = urllib.request.Request(self.base + path, data=body, method="POST",
                                         headers={"Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_enrollment_heartbeat_replay_backfill_dedupe_and_conflict(self) -> None:
        device_id, secret = self.enroll()
        status, problem = self.request("POST", "/api/v1/device-enrollment/claim", {
            "protocol_version": PROTOCOL,
            "token": self.state.enrollment_token,
            "hardware_id": "other-device",
            "capabilities": {
                "hardware_target": "esp32-s3-devkitc-1",
                "pzem_model": "PZEM-004T V4",
                "sd_present": True,
                "sd_required": True,
                "supported_endpoints": [],
            },
        })
        self.assertEqual((status, problem["code"]), (401, "enrollment_rejected"))

        heartbeat = {
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
            "connection_mode": "hybrid",
            "latest": None,
            "pzem": {"ok": True, "status": "healthy", "error_count": 0, "details": {}},
            "sd": {"ok": True, "status": "healthy", "error_count": 0, "details": {}},
            "oldest_stored_sequence": 0,
            "newest_stored_sequence": 0,
            "server_ack_sequence": 0,
            "backlog_estimate": 0,
            "configuration_version": 0,
            "time": {"trusted": True, "source": "sntp", "offset_ms": 0},
            "resources": {},
            "queue": {},
        }
        nonce = "10" * 16
        status, result = self.authenticated(device_id, secret, "/api/v1/device-heartbeats", heartbeat, nonce)
        self.assertEqual((status, result["highest_contiguous_accepted_sequence"]), (200, 0))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-heartbeats", heartbeat, nonce)
        self.assertEqual((status, result["code"]), (401, "nonce_replayed"))

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

        def batch(*records: dict) -> dict:
            return {
                "protocol_version": PROTOCOL,
                "schema_version": "reading-batch/1.0.0",
                "device_id": device_id,
                "readings": list(records),
            }

        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            batch(reading(2)), "20" * 16)
        self.assertEqual((status, result["highest_contiguous_accepted_sequence"]), (200, 0))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            batch(reading(1), reading(2)), "30" * 16)
        self.assertEqual((status, result["highest_contiguous_accepted_sequence"]), (200, 2))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            batch(reading(1)), "40" * 16)
        self.assertEqual((status, result["highest_contiguous_accepted_sequence"]), (200, 2))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            batch(reading(1, 11.0)), "50" * 16)
        self.assertEqual((status, result["code"]), (409, "idempotency_conflict"))


if __name__ == "__main__":
    unittest.main()

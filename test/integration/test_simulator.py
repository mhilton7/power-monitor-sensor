from __future__ import annotations

import base64
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
        self.state = ServerState(enrollment_token="single-use-local-token")
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
            "schema_version": 1, "protocol": PROTOCOL,
            "enrollment_token": self.state.enrollment_token,
            "local_instance_id": "local-1", "hardware_id": "esp32s3-test",
            "friendly_name": "Simulator sensor",
        })
        self.assertEqual(status, 200)
        return result["device_id"], base64.b64decode(result["enrollment_secret"])

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
            "protocol": PROTOCOL, "enrollment_token": self.state.enrollment_token,
            "local_instance_id": "local-2", "hardware_id": "other",
        })
        self.assertEqual((status, problem["code"]), (401, "enrollment_rejected"))

        heartbeat = {"schema_version": 1, "protocol": PROTOCOL, "device_id": device_id}
        nonce = "10" * 16
        status, result = self.authenticated(device_id, secret, "/api/v1/device-heartbeats", heartbeat, nonce)
        self.assertEqual((status, result["ack_sequence"]), (200, 0))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-heartbeats", heartbeat, nonce)
        self.assertEqual((status, result["code"]), (401, "nonce_replayed"))

        def reading(sequence: int, value: float = 10.0) -> dict:
            return {"schema_version": 1, "protocol": PROTOCOL, "device_id": device_id,
                    "sequence": sequence, "active_power_w": {"average": value}}

        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            {"records": [reading(2)]}, "20" * 16)
        self.assertEqual((status, result["ack_sequence"]), (200, 0))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            {"records": [reading(1), reading(2)]}, "30" * 16)
        self.assertEqual((status, result["ack_sequence"]), (200, 2))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            {"records": [reading(1)]}, "40" * 16)
        self.assertEqual((status, result["ack_sequence"]), (200, 2))
        status, result = self.authenticated(device_id, secret, "/api/v1/device-readings/batch",
                                            {"records": [reading(1, 11.0)]}, "50" * 16)
        self.assertEqual((status, result["code"]), (409, "idempotency_conflict"))


if __name__ == "__main__":
    unittest.main()

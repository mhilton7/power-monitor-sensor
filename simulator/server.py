"""Offline central-server simulator for pm-protocol/1.0.0.

It binds to loopback by default and never represents a production fleet server.
Use --cert/--key to exercise firmware TLS validation with a locally trusted CA.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    from .protocol import PROTOCOL, hkdf_sha256, verify
except ImportError:  # Direct execution: python simulator/server.py
    from protocol import PROTOCOL, hkdf_sha256, verify

MAX_REQUEST_BYTES = 512 * 1024
MAX_BATCH_RECORDS = 500


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def problem(status: int, code: str, detail: str, instance: str) -> dict[str, Any]:
    return {
        "type": f"https://powermonitor.local/problems/{code}",
        "title": code.replace("_", " ").title(),
        "status": status,
        "detail": detail,
        "instance": instance,
        "code": code,
    }


@dataclass
class DeviceState:
    secret: bytes
    acknowledged_sequence: int = 0
    records: dict[int, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    last_heartbeat: dict[str, Any] | None = None
    nonces: dict[str, int] = field(default_factory=dict)

    @property
    def inbound_key(self) -> bytes:
        return hkdf_sha256(self.secret, b"pm-device-to-server-v1")

    def nonce_seen(self, nonce: str, timestamp: int) -> bool:
        cutoff = timestamp - 300
        self.nonces = {key: value for key, value in self.nonces.items() if value >= cutoff}
        if nonce in self.nonces:
            return True
        self.nonces[nonce] = timestamp
        return False


@dataclass
class ServerState:
    enrollment_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    token_used: bool = False
    devices: dict[str, DeviceState] = field(default_factory=dict)
    desired_config: dict[str, Any] = field(
        default_factory=lambda: {"schema_version": 1, "config_version": 1}
    )

    def enroll(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        if payload.get("protocol") != PROTOCOL:
            return 409, problem(409, "protocol_mismatch", "Only pm-protocol/1.0.0 is supported.", "/api/v1/device-enrollment/claim")
        if self.token_used or not secrets.compare_digest(
            str(payload.get("enrollment_token", "")), self.enrollment_token
        ):
            return 401, problem(401, "enrollment_rejected", "The enrollment token is invalid, expired, or already used.", "/api/v1/device-enrollment/claim")
        if not payload.get("hardware_id") or not payload.get("local_instance_id"):
            return 422, problem(422, "claim_invalid", "hardware_id and local_instance_id are required.", "/api/v1/device-enrollment/claim")
        device_id = str(uuid.uuid4())
        secret = secrets.token_bytes(32)
        self.devices[device_id] = DeviceState(secret=secret)
        self.token_used = True
        return 200, {
            "device_id": device_id,
            "friendly_name": payload.get("friendly_name", "Unassigned Power Monitor"),
            "enrollment_secret": base64.b64encode(secret).decode("ascii"),
            "protocol": PROTOCOL,
            "config_version": 1,
            "policy": {"heartbeat_interval_seconds": 15, "connection_mode": "hybrid", "batch_maximum": 500},
            "ota_signing_public_key": "not-configured-in-simulator",
        }


class SimulatorHandler(BaseHTTPRequestHandler):
    server_version = "PowerMonitorSimulator/1.0"

    @property
    def state(self) -> ServerState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"simulator {self.address_string()} {format_string % args}")

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, problem(400, "content_length_invalid", "Content-Length is invalid.", self.path), "application/problem+json")
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send(413, problem(413, "request_too_large", "Request exceeds simulator limit.", self.path), "application/problem+json")
            return None
        return self.rfile.read(length)

    def _send(self, status: int, payload: Any | None = None, content_type: str = "application/json") -> None:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authenticate(self, body: bytes) -> tuple[str, DeviceState] | None:
        device_id = self.headers.get("X-PM-Device-ID", "")
        device = self.state.devices.get(device_id)
        if device is None:
            self._send(401, problem(401, "device_unknown", "No enrolled device matches the ID.", self.path), "application/problem+json")
            return None
        ok, code = verify(
            device.inbound_key,
            self.command,
            self.path,
            dict(self.headers.items()),
            body,
            int(time.time()),
            device.nonce_seen,
        )
        if not ok:
            status = 409 if code == "protocol_mismatch" else 401
            self._send(status, problem(status, code, "Authenticated request verification failed.", self.path), "application/problem+json")
            return None
        return device_id, device

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/v1/time":
            self._send(200, {"schema_version": 1, "utc": utc_now()})
            return
        authenticated = self._authenticate(b"")
        if authenticated is None:
            return
        _, _device = authenticated
        if self.path.startswith("/api/v1/device-config/effective"):
            self._send(200, self.state.desired_config)
        elif self.path.startswith("/api/v1/device-firmware/manifest"):
            self._send(204)
        else:
            self._send(404, problem(404, "not_found", "Simulator endpoint not found.", self.path), "application/problem+json")

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_body()
        if body is None:
            return
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            self._send(400, problem(400, "json_invalid", "Body is not valid JSON.", self.path), "application/problem+json")
            return
        if self.path == "/api/v1/device-enrollment/claim":
            status, response = self.state.enroll(payload)
            self._send(status, response, "application/json" if status == 200 else "application/problem+json")
            return
        authenticated = self._authenticate(body)
        if authenticated is None:
            return
        device_id, device = authenticated
        if self.path == "/api/v1/device-heartbeats":
            if payload.get("protocol") != PROTOCOL or payload.get("device_id") != device_id:
                self._send(422, problem(422, "heartbeat_invalid", "Protocol or device identity does not match.", self.path), "application/problem+json")
                return
            device.last_heartbeat = payload
            self._send(200, {"accepted_utc": utc_now(), "ack_sequence": device.acknowledged_sequence, "recommended_heartbeat_interval_seconds": 15, "synchronize_now": False, "desired_config_version": self.state.desired_config["config_version"], "server_time": utc_now()})
        elif self.path == "/api/v1/device-readings/batch":
            records = payload.get("records")
            if not isinstance(records, list) or not 1 <= len(records) <= MAX_BATCH_RECORDS:
                self._send(422, problem(422, "batch_invalid", "records must contain 1 through 500 readings.", self.path), "application/problem+json")
                return
            for record in records:
                if record.get("device_id") != device_id or record.get("protocol") != PROTOCOL:
                    self._send(422, problem(422, "reading_invalid", "Reading identity or protocol does not match.", self.path), "application/problem+json")
                    return
                sequence = int(record.get("sequence", 0))
                if sequence <= 0:
                    self._send(422, problem(422, "sequence_invalid", "Reading sequence must be positive.", self.path), "application/problem+json")
                    return
                existing = device.records.get(sequence)
                if existing is not None and existing != record:
                    self._send(409, problem(409, "idempotency_conflict", "Sequence was previously stored with different content.", self.path), "application/problem+json")
                    return
                device.records[sequence] = record
            while device.acknowledged_sequence + 1 in device.records:
                device.acknowledged_sequence += 1
            self._send(200, {"ack_sequence": device.acknowledged_sequence, "accepted_count": len(records)})
        elif self.path == "/api/v1/device-events/batch":
            events = payload.get("events", [])
            if not isinstance(events, list) or len(events) > MAX_BATCH_RECORDS:
                self._send(422, problem(422, "events_invalid", "events must be a bounded array.", self.path), "application/problem+json")
                return
            device.events.extend(events)
            self._send(200, {"accepted_count": len(events)})
        elif self.path == "/api/v1/device-config/report":
            self._send(204)
        else:
            self._send(404, problem(404, "not_found", "Simulator endpoint not found.", self.path), "application/problem+json")


def serve(host: str, port: int, state: ServerState, cert: Path | None, key: Path | None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), SimulatorHandler)
    server.state = state  # type: ignore[attr-defined]
    if cert or key:
        if not cert or not key:
            raise ValueError("--cert and --key must be provided together")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline Power Monitor central-server simulator")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    args = parser.parse_args()
    state = ServerState()
    server = serve(args.host, args.port, state, args.cert, args.key)
    scheme = "https" if args.cert else "http"
    print(f"Simulator listening at {scheme}://{args.host}:{server.server_port}")
    print(f"One-time enrollment token: {state.enrollment_token}")
    print("This token is shown for the local simulator only and is never written to disk.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

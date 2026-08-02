"""Offline central-server simulator for pm-protocol/1.0.0.

It binds to loopback by default and never represents a production fleet server.
Use --cert/--key to exercise firmware TLS validation with a locally trusted CA.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
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
DEFAULT_ENROLLMENT_TOKEN_ENV = "PM_SIMULATOR_ENROLLMENT_TOKEN"

ENROLLMENT_ENDPOINT = "enrollment"
HEARTBEAT_ENDPOINT = "heartbeat"
READINGS_ENDPOINT = "readings"
EVENTS_ENDPOINT = "events"
CONFIG_REPORT_ENDPOINT = "config_report"

TRANSPORT_RESPONSE_BODY_DELAY = "response_body_delay"
TRANSPORT_CONNECTION_RESET = "connection_reset"


def utc_now() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


def problem(status: int, code: str, detail: str, instance: str) -> dict[str, Any]:
    return {
        "type": f"https://powermonitor.local/problems/{code}",
        "title": code.replace("_", " ").title(),
        "status": status,
        "detail": detail,
        "instance": instance,
        "code": code,
    }


@dataclass(frozen=True)
class FaultResponse:
    """One deterministic RFC 9457 response consumed from an in-memory queue."""

    status: int
    code: str
    detail: str
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if not 400 <= self.status <= 599:
            raise ValueError("fault status must be an HTTP error")
        if not self.code:
            raise ValueError("fault code must not be empty")
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            raise ValueError("Retry-After must not be negative")


@dataclass
class FaultPlan:
    """Thread-safe, deterministic endpoint fault queues for host integration tests."""

    _responses: dict[str, deque[FaultResponse]] = field(
        default_factory=dict, repr=False
    )
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def enqueue(self, endpoint: str, response: FaultResponse) -> None:
        if endpoint not in {
            ENROLLMENT_ENDPOINT,
            HEARTBEAT_ENDPOINT,
            READINGS_ENDPOINT,
            EVENTS_ENDPOINT,
            CONFIG_REPORT_ENDPOINT,
        }:
            raise ValueError(f"unsupported fault endpoint: {endpoint}")
        with self._lock:
            self._responses.setdefault(endpoint, deque()).append(response)

    def take(self, endpoint: str) -> FaultResponse | None:
        with self._lock:
            queue = self._responses.get(endpoint)
            if not queue:
                return None
            response = queue.popleft()
            if not queue:
                del self._responses[endpoint]
            return response


@dataclass(frozen=True)
class TransportFault:
    """One deterministic transport lifecycle fault for mock-HTTPS tests."""

    kind: str
    delay_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.kind not in {
            TRANSPORT_RESPONSE_BODY_DELAY,
            TRANSPORT_CONNECTION_RESET,
        }:
            raise ValueError(f"unsupported transport fault: {self.kind}")
        if self.delay_seconds < 0:
            raise ValueError("transport fault delay must not be negative")
        if self.kind == TRANSPORT_CONNECTION_RESET and self.delay_seconds != 0:
            raise ValueError("connection reset does not accept a delay")


@dataclass
class TransportFaultPlan:
    """Thread-safe, one-shot transport faults consumed after authentication."""

    _faults: dict[str, deque[TransportFault]] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def enqueue(self, endpoint: str, fault: TransportFault) -> None:
        if endpoint not in {
            HEARTBEAT_ENDPOINT,
            READINGS_ENDPOINT,
            EVENTS_ENDPOINT,
            CONFIG_REPORT_ENDPOINT,
        }:
            raise ValueError(f"unsupported transport-fault endpoint: {endpoint}")
        with self._lock:
            self._faults.setdefault(endpoint, deque()).append(fault)

    def take(self, endpoint: str) -> TransportFault | None:
        with self._lock:
            queue = self._faults.get(endpoint)
            if not queue:
                return None
            fault = queue.popleft()
            if not queue:
                del self._faults[endpoint]
            return fault


@dataclass
class DeviceState:
    secret: bytes = field(repr=False)
    hardware_id: str
    acknowledged_sequence: int = 0
    records: dict[int, dict[str, Any]] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    last_heartbeat: dict[str, Any] | None = None
    nonces: dict[str, int] = field(default_factory=dict)
    _nonce_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def inbound_key(self) -> bytes:
        return hkdf_sha256(self.secret, b"pm-device-to-server-v1")

    def nonce_seen(self, nonce: str, timestamp: int) -> bool:
        with self._nonce_lock:
            cutoff = timestamp - 300
            self.nonces = {
                key: value for key, value in self.nonces.items() if value >= cutoff
            }
            if nonce in self.nonces:
                return True
            self.nonces[nonce] = timestamp
            return False

    def missing_ranges(self) -> list[list[int]]:
        if not self.records:
            return []
        maximum = max(self.records)
        start = self.acknowledged_sequence + 1
        ranges: list[list[int]] = []
        while start <= maximum:
            if start in self.records:
                start += 1
                continue
            end = start
            while end + 1 <= maximum and end + 1 not in self.records:
                end += 1
            ranges.append([start, end])
            start = end + 1
        return ranges


@dataclass
class ServerState:
    enrollment_token: str = field(
        default_factory=lambda: secrets.token_urlsafe(24), repr=False
    )
    enrollment_token_expires_at: float | None = None
    token_used: bool = False
    devices: dict[str, DeviceState] = field(default_factory=dict)
    faults: FaultPlan = field(default_factory=FaultPlan)
    transport_faults: TransportFaultPlan = field(default_factory=TransportFaultPlan)
    clock: Callable[[], float] = field(default=time.time, repr=False)
    _enrollment_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    desired_config: dict[str, Any] = field(
        default_factory=lambda: {
            "version": 1,
            "settings": {
                "heartbeat_interval_seconds": 15,
                "durable_log_interval_seconds": 60,
                "live_update_interval_seconds": 5,
                "ct_rating_amps": "100",
            },
            "sha256": "0" * 64,
        }
    )
    firmware_manifest: dict[str, Any] | None = None
    firmware_binary: bytes = field(default=b"", repr=False)
    firmware_release_id: str | None = None
    firmware_deployment_id: str | None = None

    def configure_firmware(
        self,
        manifest: Mapping[str, Any],
        binary: bytes,
        *,
        release_id: str | None = None,
    ) -> str:
        required = {
            "version",
            "channel",
            "hardware_target",
            "protocol_min",
            "protocol_max",
            "sha256",
            "signature",
            "signing_key_id",
            "release_notes",
        }
        if set(manifest) != required:
            raise ValueError(
                "firmware manifest fields do not match the server contract"
            )
        if not binary:
            raise ValueError("firmware binary must not be empty")
        digest = hashlib.sha256(binary).hexdigest()
        if manifest["sha256"] != digest:
            raise ValueError("firmware binary SHA-256 does not match manifest")
        selected_release_id = release_id or str(uuid.uuid4())
        uuid.UUID(selected_release_id)
        self.firmware_manifest = dict(manifest)
        self.firmware_binary = bytes(binary)
        self.firmware_release_id = selected_release_id
        self.firmware_deployment_id = str(uuid.uuid4())
        return selected_release_id

    def queue_fault(
        self,
        endpoint: str,
        status: int,
        code: str,
        detail: str,
        retry_after_seconds: int | None = None,
    ) -> None:
        self.faults.enqueue(
            endpoint,
            FaultResponse(status, code, detail, retry_after_seconds),
        )

    def queue_transport_fault(
        self, endpoint: str, kind: str, *, delay_seconds: float = 0.0
    ) -> None:
        """Queue a test-only connection reset or delayed response body.

        The fault is applied only after the signed request authenticates. This
        keeps authentication failures distinct from network lifecycle failures
        and prevents a transport test from weakening request verification.
        """

        self.transport_faults.enqueue(
            endpoint, TransportFault(kind=kind, delay_seconds=delay_seconds)
        )

    def issue_enrollment_token(
        self, token: str, *, expires_at: float | None = None
    ) -> None:
        _validate_enrollment_token(token)
        with self._enrollment_lock:
            self.enrollment_token = token
            self.enrollment_token_expires_at = expires_at
            self.token_used = False

    def enroll(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path = "/api/v1/device-enrollment/claim"
        with self._enrollment_lock:
            if self.token_used:
                return 401, problem(
                    401,
                    "invalid_enrollment_token",
                    "The enrollment token is invalid or already used.",
                    path,
                )
            if self.enrollment_token_expires_at is not None and (
                self.enrollment_token_expires_at <= self.clock()
            ):
                return 401, problem(
                    401,
                    "enrollment_token_expired",
                    "The enrollment token has expired.",
                    path,
                )
            if not secrets.compare_digest(
                str(payload.get("token", "")), self.enrollment_token
            ):
                return 401, problem(
                    401,
                    "invalid_enrollment_token",
                    "The enrollment token is invalid or already used.",
                    path,
                )
            if payload.get("protocol_version") != PROTOCOL:
                return 409, problem(
                    409,
                    "protocol_mismatch",
                    "Only pm-protocol/1.0.0 is supported.",
                    path,
                )
            capabilities = payload.get("capabilities")
            hardware_id = str(payload.get("hardware_id", ""))
            if (
                len(hardware_id) < 8
                or not isinstance(capabilities, dict)
                or not str(capabilities.get("pzem_model", "")).startswith(
                    "PZEM-004T V4"
                )
                or capabilities.get("sd_present") is not True
                or capabilities.get("sd_required") is not True
            ):
                return 422, problem(
                    422,
                    "claim_invalid",
                    "Hardware identity, PZEM model, and required microSD capability are required.",
                    path,
                )
            if any(
                device.hardware_id == hardware_id for device in self.devices.values()
            ):
                return 409, problem(
                    409,
                    "hardware_exists",
                    "Hardware identity is already enrolled.",
                    path,
                )
            device_id = str(uuid.uuid4())
            secret_text = secrets.token_urlsafe(48)
            secret = secret_text.encode("ascii")
            self.devices[device_id] = DeviceState(
                secret=secret, hardware_id=hardware_id
            )
            self.token_used = True
            return 201, {
                "protocol_version": PROTOCOL,
                "device_id": device_id,
                "enrollment_secret": secret_text,
                "credential_fingerprint": "simulator-only",
                "effective_metadata": {
                    "name": payload.get("requested_name") or "Unassigned Power Monitor",
                    "site_id": "simulator-site",
                    "circuit_id": None,
                    "measurement_role": "submeter",
                    "cost_scope": "energy_only",
                    "ct_rating_amps": "100",
                },
                "server_ota_signing_public_key": None,
                "heartbeat_policy": {"expected_seconds": 15},
                "sync_policy": {
                    "maximum_batch_records": MAX_BATCH_RECORDS,
                    "durable_interval_seconds": 60,
                },
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
            self._send(
                400,
                problem(
                    400,
                    "content_length_invalid",
                    "Content-Length is invalid.",
                    self.path,
                ),
                "application/problem+json",
            )
            return None
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send(
                413,
                problem(
                    413,
                    "request_too_large",
                    "Request exceeds simulator limit.",
                    self.path,
                ),
                "application/problem+json",
            )
            return None
        return self.rfile.read(length)

    def _send(
        self,
        status: int,
        payload: Any | None = None,
        content_type: str = "application/json",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        body = (
            b""
            if payload is None
            else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        delay_seconds = getattr(self, "_response_body_delay_seconds", 0.0)
        if delay_seconds:
            self.wfile.flush()
            time.sleep(delay_seconds)
            self._response_body_delay_seconds = 0.0
        if body:
            self.wfile.write(body)

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        delay_seconds = getattr(self, "_response_body_delay_seconds", 0.0)
        if delay_seconds:
            self.wfile.flush()
            time.sleep(delay_seconds)
            self._response_body_delay_seconds = 0.0
        if body:
            self.wfile.write(body)

    def _prepare_transport(self, endpoint: str) -> bool:
        """Apply a one-shot post-authentication transport fault.

        Returning ``False`` means the connection was deliberately reset before
        request processing. A response delay is retained only for the next
        response generated by this request handler.
        """

        fault = self.state.transport_faults.take(endpoint)
        if fault is None:
            return True
        if fault.kind == TRANSPORT_RESPONSE_BODY_DELAY:
            self._response_body_delay_seconds = fault.delay_seconds
            return True
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()
        return False

    def _send_fault(self, endpoint: str) -> bool:
        response = self.state.faults.take(endpoint)
        if response is None:
            return False
        headers = {}
        if response.retry_after_seconds is not None:
            headers["Retry-After"] = str(response.retry_after_seconds)
        self._send(
            response.status,
            problem(response.status, response.code, response.detail, self.path),
            "application/problem+json",
            headers,
        )
        return True

    def _authenticate(self, body: bytes) -> tuple[str, DeviceState] | None:
        device_id = self.headers.get("X-PM-Device-ID", "")
        device = self.state.devices.get(device_id)
        if device is None:
            self._send(
                401,
                problem(
                    401,
                    "device_unknown",
                    "No enrolled device matches the ID.",
                    self.path,
                ),
                "application/problem+json",
            )
            return None
        ok, code = verify(
            device.inbound_key,
            self.command,
            self.path,
            dict(self.headers.items()),
            body,
            int(self.state.clock()),
            device.nonce_seen,
        )
        if not ok:
            status = 409 if code == "protocol_mismatch" else 401
            self._send(
                status,
                problem(
                    status,
                    code,
                    "Authenticated request verification failed.",
                    self.path,
                ),
                "application/problem+json",
            )
            return None
        return device_id, device

    def do_GET(self) -> None:
        if self.path == "/api/v1/time":
            self._send(200, {"schema_version": 1, "utc": utc_now()})
            return
        authenticated = self._authenticate(b"")
        if authenticated is None:
            return
        device_id, _device = authenticated
        if self.path.startswith("/api/v1/device-config/effective"):
            self._send(
                200,
                {
                    "protocol_version": PROTOCOL,
                    "device_id": device_id,
                    **self.state.desired_config,
                },
            )
        elif self.path.startswith("/api/v1/device-firmware/manifest"):
            if self.state.firmware_manifest is None:
                self._send(200, {"available": False, "protocol_version": PROTOCOL})
            else:
                self._send(
                    200,
                    {
                        "available": True,
                        "protocol_version": PROTOCOL,
                        "deployment_id": self.state.firmware_deployment_id,
                        **self.state.firmware_manifest,
                        "size_bytes": len(self.state.firmware_binary),
                        "download_path": (
                            f"/api/v1/device-firmware/"
                            f"{self.state.firmware_release_id}/download"
                        ),
                    },
                )
        elif self.state.firmware_release_id is not None and self.path == (
            f"/api/v1/device-firmware/{self.state.firmware_release_id}/download"
        ):
            digest = base64.b64encode(
                hashlib.sha256(self.state.firmware_binary).digest()
            ).decode("ascii")
            self._send_bytes(
                200,
                self.state.firmware_binary,
                "application/octet-stream",
                {"Digest": f"SHA-256={digest}"},
            )
        else:
            self._send(
                404,
                problem(404, "not_found", "Simulator endpoint not found.", self.path),
                "application/problem+json",
            )

    def do_POST(self) -> None:
        body = self._read_body()
        if body is None:
            return
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            self._send(
                400,
                problem(400, "json_invalid", "Body is not valid JSON.", self.path),
                "application/problem+json",
            )
            return
        if not isinstance(payload, dict):
            self._send(
                400,
                problem(
                    400,
                    "json_object_required",
                    "The request body must be a JSON object.",
                    self.path,
                ),
                "application/problem+json",
            )
            return
        if self.path == "/api/v1/device-enrollment/claim":
            if self._send_fault(ENROLLMENT_ENDPOINT):
                return
            status, response = self.state.enroll(payload)
            self._send(
                status,
                response,
                "application/json" if status == 201 else "application/problem+json",
            )
            return
        authenticated = self._authenticate(body)
        if authenticated is None:
            return
        device_id, device = authenticated
        if self.path == "/api/v1/device-heartbeats":
            if not self._prepare_transport(HEARTBEAT_ENDPOINT):
                return
            if self._send_fault(HEARTBEAT_ENDPOINT):
                return
            if payload.get("device_id") != device_id:
                self._send(
                    403,
                    problem(
                        403,
                        "device_id_mismatch",
                        "Signed header and payload device IDs differ.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            if (
                payload.get("protocol_version") != PROTOCOL
                or payload.get("schema_version") != "heartbeat/1.0.0"
                or not isinstance(payload.get("pzem"), dict)
                or not isinstance(payload.get("sd"), dict)
                or not isinstance(payload.get("time"), dict)
            ):
                self._send(
                    422,
                    problem(
                        422,
                        "heartbeat_invalid",
                        "Protocol or device identity does not match.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            device.last_heartbeat = payload
            missing_ranges = device.missing_ranges()
            self._send(
                200,
                {
                    "server_receive_time": utc_now(),
                    "highest_contiguous_accepted_sequence": device.acknowledged_sequence,
                    "gap_ranges": missing_ranges,
                    "desired_configuration_version": self.state.desired_config[
                        "version"
                    ],
                    "firmware_release_available": False,
                    "recommended_heartbeat_interval_seconds": 15,
                    "immediate_sync_requested": bool(missing_ranges),
                },
            )
        elif self.path == "/api/v1/device-readings/batch":
            if not self._prepare_transport(READINGS_ENDPOINT):
                return
            if self._send_fault(READINGS_ENDPOINT):
                return
            records = payload.get("readings")
            if (
                not isinstance(records, list)
                or not 1 <= len(records) <= MAX_BATCH_RECORDS
            ):
                self._send(
                    422,
                    problem(
                        422,
                        "batch_invalid",
                        "readings must contain 1 through 500 readings.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            if (
                payload.get("protocol_version") != PROTOCOL
                or payload.get("schema_version") != "reading-batch/1.0.0"
                or payload.get("device_id") != device_id
            ):
                self._send(
                    422,
                    problem(
                        422,
                        "reading_invalid",
                        "Batch identity or protocol does not match.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            accepted: list[int] = []
            duplicates: list[int] = []
            rejected: list[dict[str, Any]] = []
            for record in records:
                if not isinstance(record, dict):
                    self._send(
                        422,
                        problem(
                            422,
                            "reading_invalid",
                            "Each reading must be a JSON object.",
                            self.path,
                        ),
                        "application/problem+json",
                    )
                    return
                try:
                    sequence = int(record.get("sequence", 0))
                except (TypeError, ValueError):
                    sequence = 0
                if sequence <= 0:
                    self._send(
                        422,
                        problem(
                            422,
                            "sequence_invalid",
                            "Reading sequence must be positive.",
                            self.path,
                        ),
                        "application/problem+json",
                    )
                    return
                existing = device.records.get(sequence)
                if existing is not None and existing != record:
                    rejected.append(
                        {
                            "sequence": sequence,
                            "code": "conflicting_duplicate",
                            "detail": "Sequence already exists with different content.",
                        }
                    )
                    continue
                if existing is not None:
                    duplicates.append(sequence)
                else:
                    device.records[sequence] = record
                    accepted.append(sequence)
            while device.acknowledged_sequence + 1 in device.records:
                device.acknowledged_sequence += 1
            self._send(
                200,
                {
                    "accepted": accepted,
                    "duplicates": duplicates,
                    "rejected": rejected,
                    "highest_contiguous_accepted_sequence": device.acknowledged_sequence,
                    "missing_ranges": device.missing_ranges(),
                },
            )
        elif self.path == "/api/v1/device-events/batch":
            if not self._prepare_transport(EVENTS_ENDPOINT):
                return
            if self._send_fault(EVENTS_ENDPOINT):
                return
            events = payload.get("events", [])
            if (
                payload.get("protocol_version") != PROTOCOL
                or payload.get("device_id") != device_id
                or not isinstance(events, list)
                or not 1 <= len(events) <= MAX_BATCH_RECORDS
            ):
                self._send(
                    422,
                    problem(
                        422,
                        "events_invalid",
                        "events must be a bounded array.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            device.events.extend(events)
            self._send(
                200,
                {
                    "accepted": [event.get("event_id") for event in events],
                    "duplicates": [],
                },
            )
        elif self.path == "/api/v1/device-config/report":
            if not self._prepare_transport(CONFIG_REPORT_ENDPOINT):
                return
            if self._send_fault(CONFIG_REPORT_ENDPOINT):
                return
            if (
                payload.get("protocol_version") != PROTOCOL
                or payload.get("device_id") != device_id
                or int(payload.get("version", 0)) <= 0
            ):
                self._send(
                    422,
                    problem(
                        422,
                        "config_report_invalid",
                        "Configuration report identity or version is invalid.",
                        self.path,
                    ),
                    "application/problem+json",
                )
                return
            self._send(200, {"recorded": True})
        else:
            self._send(
                404,
                problem(404, "not_found", "Simulator endpoint not found.", self.path),
                "application/problem+json",
            )


class SimulatorHttpServer(ThreadingHTTPServer):
    """Loopback server with an optional deterministic TLS-accept delay."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.tls_connection_delay_seconds = 0.0

    def get_request(self) -> tuple[socket.socket, Any]:
        # When the listening socket is SSL-wrapped, ``accept`` performs the
        # server handshake. Sleeping before it therefore models a delayed TLS
        # connection without weakening certificate or hostname verification.
        if self.tls_connection_delay_seconds:
            time.sleep(self.tls_connection_delay_seconds)
        return super().get_request()


def serve(
    host: str,
    port: int,
    state: ServerState,
    cert: Path | None,
    key: Path | None,
    *,
    tls_connection_delay_seconds: float = 0.0,
) -> SimulatorHttpServer:
    if tls_connection_delay_seconds < 0:
        raise ValueError("TLS connection delay must not be negative")
    server = SimulatorHttpServer((host, port), SimulatorHandler)
    server.tls_connection_delay_seconds = tls_connection_delay_seconds
    server.state = state  # type: ignore[attr-defined]
    if cert or key:
        if not cert or not key:
            raise ValueError("--cert and --key must be provided together")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def _validate_enrollment_token(token: str) -> str:
    if not 32 <= len(token) <= 256:
        raise ValueError("enrollment token must contain 32 through 256 characters")
    if any(character.isspace() for character in token):
        raise ValueError("enrollment token must not contain whitespace")
    return token


def load_enrollment_token(
    token_file: Path | None,
    token_environment_variable: str,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Load a token without accepting it as a command-line value or displaying it."""

    source = os.environ if environment is None else environment
    if token_file is not None:
        try:
            token = token_file.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ValueError("unable to read the enrollment token file") from error
    else:
        token = source.get(token_environment_variable, "").strip()
        if not token:
            raise ValueError(
                f"set {token_environment_variable} or provide --enrollment-token-file"
            )
    return _validate_enrollment_token(token)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Offline Power Monitor central-server simulator"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument(
        "--enrollment-token-file",
        type=Path,
        help="read the one-time token from an external file; its value is never displayed",
    )
    parser.add_argument(
        "--enrollment-token-env",
        default=DEFAULT_ENROLLMENT_TOKEN_ENV,
        metavar="NAME",
        help=(
            "environment variable containing the one-time token "
            f"(default: {DEFAULT_ENROLLMENT_TOKEN_ENV})"
        ),
    )
    parser.add_argument(
        "--enrollment-token-ttl-seconds",
        type=int,
        default=900,
        help="expire the in-memory one-time token after this many seconds (default: 900)",
    )
    args = parser.parse_args(argv)
    if args.enrollment_token_ttl_seconds <= 0:
        parser.error("--enrollment-token-ttl-seconds must be positive")
    try:
        enrollment_token = load_enrollment_token(
            args.enrollment_token_file, args.enrollment_token_env
        )
    except ValueError as error:
        parser.error(str(error))
    state = ServerState(
        enrollment_token=enrollment_token,
        enrollment_token_expires_at=(time.time() + args.enrollment_token_ttl_seconds),
    )
    server = serve(args.host, args.port, state, args.cert, args.key)
    scheme = "https" if args.cert else "http"
    print(f"Simulator listening at {scheme}://{args.host}:{server.server_port}")
    print(
        "One-time enrollment token loaded from external input; "
        "the simulator will not display or persist it."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

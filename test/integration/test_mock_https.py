from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import ssl
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from simulator.protocol import PROTOCOL, hkdf_sha256, sign
from simulator.server import (
    HEARTBEAT_ENDPOINT,
    TRANSPORT_CONNECTION_RESET,
    TRANSPORT_RESPONSE_BODY_DELAY,
    ServerState,
    serve,
)


def _derive_test_token(label: str) -> str:
    return hashlib.sha256(f"pm-mock-https:{label}".encode()).hexdigest()


def _write_ephemeral_tls_material(
    directory: Path, prefix: str
) -> tuple[Path, Path, Path]:
    """Create a test-only CA and localhost certificate outside the repository."""

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Power Monitor Test CA")]
    )
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / f"{prefix}-ca.pem"
    certificate_path = directory / f"{prefix}-server.pem"
    key_path = directory / f"{prefix}-server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, certificate_path, key_path


class MockHttpsIntegrationTests(unittest.TestCase):
    now_seconds = 1_800_000_000

    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_directory = Path(__file__).resolve().parents[1] / "fixtures"
        cls.tls_prefix = f".mock-https-{os.getpid()}-{uuid.uuid4().hex}"
        cls.addClassCleanup(cls._cleanup_tls_material)
        cls.ca_path, cls.certificate_path, cls.key_path = _write_ephemeral_tls_material(
            cls.fixture_directory, cls.tls_prefix
        )

    @classmethod
    def _cleanup_tls_material(cls) -> None:
        # Class cleanups run even when ``setUpClass`` fails partway through
        # certificate generation, so no test private key remains behind.
        for path in cls.fixture_directory.glob(f"{cls.tls_prefix}-*"):
            path.unlink(missing_ok=True)

    def setUp(self) -> None:
        self.state = ServerState(
            enrollment_token=_derive_test_token("enrollment"),
            enrollment_token_expires_at=self.now_seconds + 300,
            clock=lambda: self.now_seconds,
        )
        self.context = ssl.create_default_context(cafile=str(self.ca_path))
        self.assertTrue(self.context.check_hostname)
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        self._start_server(0)

    def tearDown(self) -> None:
        self._stop_server()

    def _start_server(self, port: int) -> None:
        self.server = serve(
            "127.0.0.1",
            port,
            self.state,
            self.certificate_path,
            self.key_path,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"https://localhost:{self.server.server_port}"

    def _stop_server(self) -> None:
        if not hasattr(self, "server"):
            return
        self.server.tls_connection_delay_seconds = 0.0
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())
        del self.server

    def request_bytes(
        self,
        method: str,
        path: str,
        body: bytes,
        headers: dict[str, str] | None = None,
        *,
        timeout: float = 2.0,
        context: ssl.SSLContext | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
                context=self.context if context is None else context,
            ) as response:
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
        *,
        timeout: float = 2.0,
    ) -> tuple[int, dict, dict[str, str]]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        return self.request_bytes(method, path, body, headers, timeout=timeout)

    def enroll(self) -> tuple[str, bytes]:
        status, result, _headers = self.request(
            "POST",
            "/api/v1/device-enrollment/claim",
            {
                "protocol_version": PROTOCOL,
                "token": self.state.enrollment_token,
                "hardware_id": "esp32s3-mock-https-0001",
                "requested_name": "Mock HTTPS sensor",
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
            },
        )
        self.assertEqual(status, 201)
        return result["device_id"], result["enrollment_secret"].encode("ascii")

    def authenticated(
        self,
        device_id: str,
        secret: bytes,
        path: str,
        payload: dict,
        nonce: str,
        *,
        signing_secret: bytes | None = None,
        timeout: float = 2.0,
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
        return self.request_bytes("POST", path, body, headers, timeout=timeout)

    @staticmethod
    def heartbeat(device_id: str) -> dict:
        return {
            "schema_version": "heartbeat/1.0.0",
            "protocol_version": PROTOCOL,
            "device_id": device_id,
            "boot_id": "9cb7043e-671f-408a-b40a-8b0b386754df",
            "firmware_version": "1.0.9",
            "firmware_build_hash": "mock-https",
            "uptime_seconds": 60,
            "reboot_reason": "power_on",
            "current_ip": "192.168.1.50",
            "hostname": "power-monitor-mock",
            "rssi_dbm": -50,
            "connection_mode": "push",
            "latest": None,
            "pzem": {"ok": True, "status": "healthy", "error_count": 0},
            "sd": {"ok": True, "status": "healthy", "error_count": 0},
            "oldest_stored_sequence": 0,
            "newest_stored_sequence": 0,
            "server_ack_sequence": 0,
            "backlog_estimate": 0,
            "configuration_version": 1,
            "time": {"trusted": True, "source": "sntp", "offset_ms": 0},
            "resources": {},
            "queue": {},
        }

    @staticmethod
    def reading_batch(device_id: str) -> dict:
        return {
            "protocol_version": PROTOCOL,
            "schema_version": "reading-batch/1.0.0",
            "device_id": device_id,
            "readings": [
                {
                    "sequence": 1,
                    "boot_id": "9cb7043e-671f-408a-b40a-8b0b386754df",
                    "interval_start": "2026-08-01T10:00:00Z",
                    "interval_end": "2026-08-01T10:01:00Z",
                    "time_trusted": True,
                    "power_avg": 12.8,
                }
            ],
        }

    @staticmethod
    def event_batch(device_id: str) -> dict:
        return {
            "protocol_version": PROTOCOL,
            "device_id": device_id,
            "events": [
                {
                    "event_id": "mock-https-1",
                    "occurred_at": "2026-08-01T10:00:00Z",
                    "category": "network",
                    "severity": "warning",
                    "evidence": {"safe_reason": "deterministic_fixture"},
                }
            ],
        }

    def test_verified_https_accepts_heartbeat_readings_and_events(self) -> None:
        # The generated server certificate is not trusted by the OS trust store.
        # A client that does not explicitly trust the test CA must fail closed.
        untrusted = ssl.create_default_context()
        with self.assertRaises(urllib.error.URLError):
            self.request_bytes(
                "POST",
                "/api/v1/device-enrollment/claim",
                b"{}",
                context=untrusted,
            )

        device_id, secret = self.enroll()
        status, heartbeat_result, _headers = self.authenticated(
            device_id,
            secret,
            "/api/v1/device-heartbeats",
            self.heartbeat(device_id),
            "10" * 16,
        )
        self.assertEqual(status, 200)
        self.assertEqual(heartbeat_result["highest_contiguous_accepted_sequence"], 0)

        status, readings_result, _headers = self.authenticated(
            device_id,
            secret,
            "/api/v1/device-readings/batch",
            self.reading_batch(device_id),
            "20" * 16,
        )
        self.assertEqual(status, 200)
        self.assertEqual(readings_result["accepted"], [1])

        status, events_result, _headers = self.authenticated(
            device_id,
            secret,
            "/api/v1/device-events/batch",
            self.event_batch(device_id),
            "30" * 16,
        )
        self.assertEqual(status, 200)
        self.assertEqual(events_result["accepted"], ["mock-https-1"])
        self.assertEqual(len(self.state.devices[device_id].events), 1)

    def test_https_429_503_and_authentication_rejection_remain_distinct(self) -> None:
        device_id, secret = self.enroll()
        path = "/api/v1/device-heartbeats"
        heartbeat = self.heartbeat(device_id)

        status, result, _headers = self.authenticated(
            device_id,
            secret,
            path,
            heartbeat,
            "40" * 16,
            signing_secret=b"not-the-enrolled-secret",
        )
        self.assertEqual((status, result["code"]), (401, "signature_invalid"))

        for index, status_code in enumerate((429, 503), start=5):
            self.state.queue_fault(
                HEARTBEAT_ENDPOINT,
                status_code,
                f"mock_https_{status_code}",
                "Deterministic mock-HTTPS response.",
                retry_after_seconds=7,
            )
            status, result, headers = self.authenticated(
                device_id,
                secret,
                path,
                heartbeat,
                f"{index:02x}" * 16,
            )
            self.assertEqual(
                (status, result["code"]), (status_code, f"mock_https_{status_code}")
            )
            self.assertEqual(headers["Retry-After"], "7")

        self.assertIsNone(self.state.devices[device_id].last_heartbeat)

    def test_tls_connection_and_response_body_delays_are_deterministic(self) -> None:
        device_id, secret = self.enroll()
        path = "/api/v1/device-heartbeats"
        heartbeat = self.heartbeat(device_id)

        self.server.tls_connection_delay_seconds = 0.12
        started = time.perf_counter()
        status, _result, _headers = self.authenticated(
            device_id, secret, path, heartbeat, "70" * 16
        )
        connection_elapsed = time.perf_counter() - started
        self.server.tls_connection_delay_seconds = 0.0
        self.assertEqual(status, 200)
        self.assertGreaterEqual(connection_elapsed, 0.08)

        self.state.queue_transport_fault(
            HEARTBEAT_ENDPOINT,
            TRANSPORT_RESPONSE_BODY_DELAY,
            delay_seconds=0.12,
        )
        started = time.perf_counter()
        status, _result, _headers = self.authenticated(
            device_id, secret, path, heartbeat, "71" * 16
        )
        response_elapsed = time.perf_counter() - started
        self.assertEqual(status, 200)
        self.assertGreaterEqual(response_elapsed, 0.08)

    def test_connection_reset_is_one_shot_and_next_request_recovers(self) -> None:
        device_id, secret = self.enroll()
        path = "/api/v1/device-heartbeats"
        heartbeat = self.heartbeat(device_id)
        self.state.queue_transport_fault(HEARTBEAT_ENDPOINT, TRANSPORT_CONNECTION_RESET)

        with self.assertRaises(
            (
                urllib.error.URLError,
                ConnectionResetError,
                ssl.SSLError,
                http.client.RemoteDisconnected,
            )
        ):
            self.authenticated(
                device_id, secret, path, heartbeat, "80" * 16, timeout=0.5
            )
        self.assertIsNone(self.state.devices[device_id].last_heartbeat)

        status, _result, _headers = self.authenticated(
            device_id, secret, path, heartbeat, "81" * 16
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.state.devices[device_id].last_heartbeat, heartbeat)

    def test_server_outage_and_verified_tls_recovery(self) -> None:
        device_id, secret = self.enroll()
        path = "/api/v1/device-heartbeats"
        heartbeat = self.heartbeat(device_id)
        port = self.server.server_port
        self._stop_server()

        with self.assertRaises(
            (urllib.error.URLError, ConnectionResetError, TimeoutError)
        ):
            self.authenticated(
                device_id, secret, path, heartbeat, "90" * 16, timeout=0.5
            )
        self.assertIsNone(self.state.devices[device_id].last_heartbeat)

        self._start_server(port)
        status, _result, _headers = self.authenticated(
            device_id, secret, path, heartbeat, "91" * 16
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.state.devices[device_id].last_heartbeat, heartbeat)


if __name__ == "__main__":
    unittest.main()

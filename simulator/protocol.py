"""Shared pm-protocol/1.0.0 host implementation used by the simulator/tests."""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import parse_qsl, quote, urlsplit

PROTOCOL = "pm-protocol/1.0.0"
ALGORITHM = "PM-HMAC-SHA256-V1"


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    if not salt:
        salt = b"\0" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def canonical_query(query_pairs: list[tuple[str, str]]) -> str:
    encoded = [
        (quote(key, safe="-._~"), quote(value, safe="-._~"))
        for key, value in query_pairs
    ]
    encoded.sort()
    return "&".join(f"{key}={value}" for key, value in encoded)


def canonical_path_query(target: str) -> str:
    split = urlsplit(target)
    query = canonical_query(parse_qsl(split.query, keep_blank_values=True))
    return split.path + ("?" + query if query else "")


def body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(
    method: str, target: str, timestamp: str, nonce: str, content_hash: str
) -> str:
    return "\n".join(
        [
            ALGORITHM,
            method.upper(),
            canonical_path_query(target),
            timestamp,
            nonce,
            content_hash,
        ]
    )


def sign(
    key: bytes, method: str, target: str, timestamp: str, nonce: str, body: bytes
) -> dict[str, str]:
    content_hash = body_sha256(body)
    canonical = canonical_string(method, target, timestamp, nonce, content_hash)
    signature = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-PM-Protocol": PROTOCOL,
        "X-PM-Timestamp": timestamp,
        "X-PM-Nonce": nonce,
        "X-PM-Content-SHA256": content_hash,
        "X-PM-Signature": signature,
    }


def verify(
    key: bytes,
    method: str,
    target: str,
    headers: dict[str, str],
    body: bytes,
    now_seconds: int,
    nonce_seen: callable,
    window_seconds: int = 300,
) -> tuple[bool, str]:
    normalized = {key_name.lower(): value for key_name, value in headers.items()}
    required = [
        "x-pm-protocol",
        "x-pm-timestamp",
        "x-pm-nonce",
        "x-pm-content-sha256",
        "x-pm-signature",
    ]
    if any(name not in normalized for name in required):
        return False, "signature_headers_missing"
    if normalized["x-pm-protocol"] != PROTOCOL:
        return False, "protocol_mismatch"
    try:
        timestamp = int(normalized["x-pm-timestamp"])
    except ValueError:
        return False, "timestamp_invalid"
    if abs(now_seconds - timestamp) > window_seconds:
        return False, "timestamp_outside_window"
    nonce = normalized["x-pm-nonce"]
    if len(nonce) < 32 or any(character not in "0123456789abcdef" for character in nonce):
        return False, "nonce_invalid"
    if normalized["x-pm-content-sha256"] != body_sha256(body):
        return False, "body_hash_mismatch"
    canonical = canonical_string(
        method,
        target,
        normalized["x-pm-timestamp"],
        nonce,
        normalized["x-pm-content-sha256"],
    )
    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, normalized["x-pm-signature"]):
        return False, "signature_invalid"
    if nonce_seen(nonce, timestamp):
        return False, "nonce_replayed"
    return True, "ok"


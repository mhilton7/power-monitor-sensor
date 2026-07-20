"""PMR1 microSD format helpers shared by decoder, repair tool, and tests."""

from __future__ import annotations

import binascii
import json
from dataclasses import dataclass

PREFIX = b"PMR1\t"


@dataclass(frozen=True)
class DecodedLine:
    record: dict
    payload: bytes
    crc32: int


def encode(record: dict) -> bytes:
    payload = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    checksum = binascii.crc32(payload) & 0xFFFFFFFF
    return PREFIX + payload + f"\t{checksum:08x}\n".encode("ascii")


def decode(line: bytes) -> DecodedLine:
    if not line.startswith(PREFIX) or not line.endswith(b"\n"):
        raise ValueError("incomplete_or_wrong_prefix")
    try:
        payload, checksum_bytes = line[len(PREFIX) : -1].rsplit(b"\t", 1)
        checksum = int(checksum_bytes, 16)
    except (ValueError, IndexError) as error:
        raise ValueError("envelope_invalid") from error
    actual = binascii.crc32(payload) & 0xFFFFFFFF
    if actual != checksum:
        raise ValueError("crc_mismatch")
    try:
        record = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError("json_invalid") from error
    return DecodedLine(record, payload, checksum)


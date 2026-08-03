"""Strict ESP32-S3 application descriptor inspection and bounded patching."""

from __future__ import annotations

import hashlib
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

ESP_IMAGE_MAGIC = 0xE9
ESP32_S3_CHIP_ID = 9
ESP_APP_DESC_MAGIC = 0xABCD5432
ESP_CHECKSUM_MAGIC = 0xEF
APP_DESC_SIZE = 256
PROTOCOL_MARKER = b"pm-protocol/1.0.0"
PROJECT_NAME = "power-monitor-sensor"
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class FirmwareImageError(ValueError):
    """Raised when an image does not satisfy the strict application format."""


@dataclass(frozen=True)
class FirmwareMetadata:
    version: str
    project_name: str
    build_time: str
    build_date: str
    build_hash: str
    chip_id: int
    size_bytes: int
    sha256: str
    checksum_offset: int


def _decode_field(data: bytes, start: int, size: int, name: str) -> str:
    field = data[start : start + size]
    if len(field) != size or b"\0" not in field:
        raise FirmwareImageError(f"firmware_{name}_invalid")
    value = field.split(b"\0", 1)[0]
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirmwareImageError(f"firmware_{name}_invalid") from exc
    if not decoded:
        raise FirmwareImageError(f"firmware_{name}_invalid")
    return decoded


def _encode_field(value: str, size: int, name: str) -> bytes:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise FirmwareImageError(f"firmware_{name}_invalid") from exc
    if not encoded or len(encoded) >= size or b"\0" in encoded:
        raise FirmwareImageError(f"firmware_{name}_invalid")
    return encoded + bytes(size - len(encoded))


def _layout(data: bytes) -> tuple[list[tuple[int, int]], int, int]:
    if len(data) < 24 or data[0] != ESP_IMAGE_MAGIC:
        raise FirmwareImageError("firmware_image_invalid")
    segment_count = data[1]
    if segment_count == 0 or segment_count > 16:
        raise FirmwareImageError("firmware_segment_count_invalid")
    chip_id = struct.unpack_from("<H", data, 12)[0]
    if chip_id != ESP32_S3_CHIP_ID:
        raise FirmwareImageError("firmware_wrong_target")
    cursor = 24
    segments: list[tuple[int, int]] = []
    for _ in range(segment_count):
        if cursor + 8 > len(data):
            raise FirmwareImageError("firmware_image_truncated")
        _, size = struct.unpack_from("<II", data, cursor)
        start = cursor + 8
        end = start + size
        if size == 0 or end < start or end > len(data):
            raise FirmwareImageError("firmware_image_truncated")
        segments.append((start, end))
        cursor = end
    checksum_offset = cursor + (15 - (cursor % 16))
    image_length = checksum_offset + 1
    append_digest = data[23]
    if append_digest not in (0, 1):
        raise FirmwareImageError("firmware_image_invalid")
    expected_length = image_length + (32 if append_digest else 0)
    if len(data) < expected_length:
        raise FirmwareImageError("firmware_image_truncated")
    if len(data) != expected_length:
        raise FirmwareImageError("firmware_image_extra_bytes")
    if any(data[cursor:checksum_offset]):
        raise FirmwareImageError("firmware_padding_invalid")
    return segments, checksum_offset, image_length


def _checksum(data: bytes, segments: list[tuple[int, int]]) -> int:
    value = ESP_CHECKSUM_MAGIC
    for start, end in segments:
        for byte in data[start:end]:
            value ^= byte
    return value


def inspect_firmware(
    path: Path,
    *,
    expected_version: str | None = None,
    expected_elf_sha256: str | None = None,
) -> FirmwareMetadata:
    data = path.read_bytes()
    segments, checksum_offset, image_length = _layout(data)
    if data[checksum_offset] != _checksum(data, segments):
        raise FirmwareImageError("firmware_checksum_invalid")
    if (
        data[23] == 1
        and not hashlib.sha256(data[:image_length]).digest() == data[image_length:]
    ):
        raise FirmwareImageError("firmware_appended_sha256_invalid")
    first_start, first_end = segments[0]
    if first_end - first_start < APP_DESC_SIZE:
        raise FirmwareImageError("firmware_not_application_image")
    descriptor = first_start
    if struct.unpack_from("<I", data, descriptor)[0] != ESP_APP_DESC_MAGIC:
        raise FirmwareImageError("firmware_not_application_image")
    version = _decode_field(data, descriptor + 16, 32, "version")
    project_name = _decode_field(data, descriptor + 48, 32, "project")
    build_time = _decode_field(data, descriptor + 80, 16, "build_time")
    build_date = _decode_field(data, descriptor + 96, 16, "build_date")
    build_hash = data[descriptor + 144 : descriptor + 176].hex()
    if project_name != PROJECT_NAME:
        raise FirmwareImageError("firmware_project_mismatch")
    if SEMVER.fullmatch(version) is None:
        raise FirmwareImageError("firmware_version_invalid")
    if expected_version is not None and version != expected_version:
        raise FirmwareImageError("firmware_version_mismatch")
    if expected_elf_sha256 is not None and build_hash != expected_elf_sha256:
        raise FirmwareImageError("firmware_build_hash_mismatch")
    if PROTOCOL_MARKER not in data:
        raise FirmwareImageError("firmware_protocol_marker_missing")
    return FirmwareMetadata(
        version=version,
        project_name=project_name,
        build_time=build_time,
        build_date=build_date,
        build_hash=build_hash,
        chip_id=ESP32_S3_CHIP_ID,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        checksum_offset=checksum_offset,
    )


def patch_firmware_descriptor(
    firmware_path: Path,
    elf_path: Path,
    *,
    version: str,
    build_time: str,
    build_date: str,
) -> FirmwareMetadata:
    if SEMVER.fullmatch(version) is None:
        raise FirmwareImageError("firmware_version_invalid")
    data = bytearray(firmware_path.read_bytes())
    segments, checksum_offset, image_length = _layout(data)
    first_start, first_end = segments[0]
    if (
        first_end - first_start < APP_DESC_SIZE
        or struct.unpack_from("<I", data, first_start)[0] != ESP_APP_DESC_MAGIC
    ):
        raise FirmwareImageError("firmware_not_application_image")
    elf_sha256 = hashlib.sha256(elf_path.read_bytes()).digest()
    data[first_start + 16 : first_start + 48] = _encode_field(version, 32, "version")
    data[first_start + 48 : first_start + 80] = _encode_field(
        PROJECT_NAME, 32, "project"
    )
    data[first_start + 80 : first_start + 96] = _encode_field(
        build_time, 16, "build_time"
    )
    data[first_start + 96 : first_start + 112] = _encode_field(
        build_date, 16, "build_date"
    )
    data[first_start + 144 : first_start + 176] = elf_sha256
    data[checksum_offset] = _checksum(data, segments)
    if data[23] == 1:
        data[image_length:] = hashlib.sha256(data[:image_length]).digest()
    with tempfile.NamedTemporaryFile(
        dir=firmware_path.parent, prefix=f".{firmware_path.name}.", delete=False
    ) as temporary:
        temporary.write(data)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, firmware_path)
    return inspect_firmware(
        firmware_path,
        expected_version=version,
        expected_elf_sha256=elf_sha256.hex(),
    )

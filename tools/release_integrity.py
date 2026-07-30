"""Release artifact provenance and flash-layout validation helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

PROVENANCE_SCHEMA_VERSION = 1
RELEASE_ENVIRONMENT = "esp32-s3-release"
PROVENANCE_FILENAME = "build-provenance.json"
FLASH_LAYOUT_FILENAME = "flash-layout.json"

REQUIRED_BUILD_ARTIFACTS = (
    "bootloader.bin",
    "partitions.bin",
    "boot_app0.bin",
    "firmware.bin",
    "firmware.elf",
    "firmware.map",
)

FLASH_IMAGE_OFFSETS = {
    "bootloader.bin": 0x0000,
    "partitions.bin": 0x8000,
    "boot_app0.bin": 0x11000,
    "firmware.bin": 0x20000,
}

_SOURCE_ROOT_FILES = (
    "platformio.ini",
    "partitions.csv",
)
_SOURCE_TREES: dict[str, frozenset[str]] = {
    "include": frozenset({".h", ".hpp"}),
    "src": frozenset({".c", ".cc", ".cpp", ".h", ".hpp"}),
    "shared": frozenset({".json", ".txt", ".yaml", ".yml"}),
    "tools": frozenset({".py"}),
    "web": frozenset({".css", ".html", ".json", ".ts"}),
}


class ReleaseIntegrityError(ValueError):
    """Raised when build or release provenance is incomplete or stale."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_input_paths(root: Path) -> list[Path]:
    paths = [root / name for name in _SOURCE_ROOT_FILES if (root / name).is_file()]
    for directory, suffixes in _SOURCE_TREES.items():
        source_root = root / directory
        if not source_root.is_dir():
            continue
        paths.extend(
            path
            for path in source_root.rglob("*")
            if path.is_file() and path.suffix.lower() in suffixes
        )
    return sorted(set(paths), key=lambda path: path.relative_to(root).as_posix())


def source_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in build_input_paths(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def artifact_metadata(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ReleaseIntegrityError(f"required build artifact is missing: {path}")
    return {
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def build_provenance_document(
    root: Path,
    build_directory: Path,
    environment: str,
    source_sha256: str,
) -> dict[str, Any]:
    if source_fingerprint(root) != source_sha256:
        raise ReleaseIntegrityError(
            "build inputs changed while firmware was compiling; rebuild from a stable "
            "source state"
        )
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "environment": environment,
        "source_sha256": source_sha256,
        "flash_offsets": {
            name: f"0x{offset:x}" for name, offset in FLASH_IMAGE_OFFSETS.items()
        },
        "artifacts": {
            name: artifact_metadata(build_directory / name)
            for name in REQUIRED_BUILD_ARTIFACTS
        },
    }


def write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(document, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseIntegrityError(f"invalid or missing {path}: {error}") from error
    if not isinstance(document, dict):
        raise ReleaseIntegrityError(f"{path} must contain a JSON object")
    return document


def validate_build_provenance(
    root: Path,
    build_directory: Path,
    expected_environment: str = RELEASE_ENVIRONMENT,
) -> dict[str, Any]:
    provenance = _load_json_object(build_directory / PROVENANCE_FILENAME)
    if provenance.get("schema_version") != PROVENANCE_SCHEMA_VERSION:
        raise ReleaseIntegrityError("unsupported build provenance schema")
    if provenance.get("environment") != expected_environment:
        raise ReleaseIntegrityError(
            "build provenance environment does not match the release environment"
        )
    current_source = source_fingerprint(root)
    if provenance.get("source_sha256") != current_source:
        raise ReleaseIntegrityError(
            "release build is stale: its source fingerprint does not match the "
            "current repository"
        )
    expected_offsets = {
        name: f"0x{offset:x}" for name, offset in FLASH_IMAGE_OFFSETS.items()
    }
    if provenance.get("flash_offsets") != expected_offsets:
        raise ReleaseIntegrityError("build provenance flash offsets are inconsistent")
    artifacts = provenance.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReleaseIntegrityError("build provenance artifact map is missing")
    for name in REQUIRED_BUILD_ARTIFACTS:
        expected = artifacts.get(name)
        actual = artifact_metadata(build_directory / name)
        if expected != actual:
            raise ReleaseIntegrityError(
                f"build artifact changed after provenance was recorded: {name}"
            )
    return provenance


def flash_layout_document(release_directory: Path) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "flash_size_bytes": 0x1000000,
        "images": [
            {
                "filename": name,
                "offset": f"0x{offset:x}",
                **artifact_metadata(release_directory / name),
            }
            for name, offset in FLASH_IMAGE_OFFSETS.items()
        ],
    }


def validate_release_bundle(
    root: Path,
    release_directory: Path,
    *,
    require_current_source: bool = True,
) -> None:
    provenance = _load_json_object(release_directory / PROVENANCE_FILENAME)
    if provenance.get("environment") != RELEASE_ENVIRONMENT:
        raise ReleaseIntegrityError("release provenance is not from the release build")
    if require_current_source and provenance.get("source_sha256") != source_fingerprint(
        root
    ):
        raise ReleaseIntegrityError(
            "release bundle is stale relative to the current source tree"
        )
    artifacts = provenance.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReleaseIntegrityError("release provenance artifact map is missing")
    for name in REQUIRED_BUILD_ARTIFACTS:
        expected = artifacts.get(name)
        actual = artifact_metadata(release_directory / name)
        if expected != actual:
            raise ReleaseIntegrityError(
                f"release artifact does not match build provenance: {name}"
            )
    ota_path = release_directory / "ota.bin"
    if artifact_metadata(ota_path) != artifact_metadata(
        release_directory / "firmware.bin"
    ):
        raise ReleaseIntegrityError("ota.bin must be identical to firmware.bin")
    layout = _load_json_object(release_directory / FLASH_LAYOUT_FILENAME)
    if layout != flash_layout_document(release_directory):
        raise ReleaseIntegrityError("release flash layout is missing or inconsistent")

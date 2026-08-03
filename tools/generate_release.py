#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from firmware_image import FirmwareMetadata, inspect_firmware
from release_integrity import (
    FLASH_LAYOUT_FILENAME,
    PROVENANCE_FILENAME,
    REQUIRED_BUILD_ARTIFACTS,
    flash_layout_document,
    sha256_file,
    validate_build_provenance,
    validate_release_bundle,
    write_json_atomic,
)

ROOT = Path(__file__).resolve().parents[1]


def existing_trust_metadata(
    firmware: FirmwareMetadata, channel: str, release_notes: str
) -> dict[str, object]:
    """Describe a verified binary without creating an upload-side manifest."""
    return {
        "schema_version": "pm-firmware-artifact/1",
        "version": firmware.version,
        "channel": channel,
        "project_name": firmware.project_name,
        "hardware_target": "esp32-s3",
        "protocol_version": "pm-protocol/1.0.0",
        "size_bytes": firmware.size_bytes,
        "sha256": firmware.sha256,
        "build_hash": firmware.build_hash,
        "build_time": firmware.build_time,
        "build_date": firmware.build_date,
        "ota_authentication_mode": "existing_device_hmac",
        "ota_protocol_version": 2,
        "release_notes": release_notes,
    }


def create_staging_directory(release_root: Path, version: str) -> Path:
    """Create an exclusive staging directory that inherits the release ACL."""
    for _ in range(10):
        staging = release_root / f".{version}.{secrets.token_hex(8)}"
        try:
            staging.mkdir()
        except FileExistsError:
            continue
        return staging
    raise RuntimeError("could not allocate a unique release staging directory")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a reproducible existing-trust OTA and USB release bundle"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--channel",
        choices=("development", "canary", "stable"),
        default="stable",
    )
    parser.add_argument(
        "--legacy-signing-key-id",
        help=(
            "Optionally emit an unsigned manifest for older Ed25519-only firmware; "
            "not used by Existing-Trust OTA v2"
        ),
    )
    parser.add_argument(
        "--release-notes",
        help="Release notes; defaults to the standard release summary",
    )
    parser.add_argument("--pio", default="pio")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Replace the exact version directory after a complete staged bundle "
            "passes validation"
        ),
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", args.version):
        raise SystemExit("version must be a safe semantic-version identifier")
    release_root = ROOT / "release"
    release = release_root / args.version
    if release.exists() and not args.overwrite:
        raise SystemExit(
            f"release directory already exists: {release}; use --overwrite only "
            "when intentionally replacing this exact generated version"
        )
    if not args.skip_build:
        subprocess.run(
            [args.pio, "run", "-e", "esp32-s3-release"], cwd=ROOT, check=True
        )
    build = ROOT / ".pio" / "build" / "esp32-s3-release"
    try:
        validate_build_provenance(ROOT, build)
    except ValueError as error:
        raise SystemExit(
            f"release build provenance validation failed: {error}"
        ) from error

    release_root.mkdir(parents=True, exist_ok=True)
    # tempfile.mkdtemp applies a private Windows ACL. Renaming that directory
    # into release/<version> also renames the ACL, which can make generated
    # artifacts unreadable to the normal repository user. An ordinary
    # exclusive mkdir inherits the repository ACL while keeping the same
    # atomic staging-and-replace behavior.
    staging = create_staging_directory(release_root, args.version)
    try:
        for name in REQUIRED_BUILD_ARTIFACTS:
            shutil.copy2(build / name, staging / name)
        shutil.copy2(build / PROVENANCE_FILENAME, staging / PROVENANCE_FILENAME)
        firmware = staging / "firmware.bin"
        write_json_atomic(
            staging / FLASH_LAYOUT_FILENAME, flash_layout_document(staging)
        )

        notes = args.release_notes or (
            f"Power Monitor Sensor Agent {args.version}: pm-protocol/1.0.0 "
            "production release. Physical PZEM, microSD, enclosure, and "
            "device-authenticated HMAC OTA validation remain required on the "
            "target installation."
        )
        firmware_metadata = inspect_firmware(
            firmware,
            expected_version=args.version,
            expected_elf_sha256=sha256_file(staging / "firmware.elf"),
        )
        write_json_atomic(
            staging / "firmware-metadata.json",
            existing_trust_metadata(firmware_metadata, args.channel, notes),
        )
        if args.legacy_signing_key_id:
            legacy_manifest = {
                "version": args.version,
                "channel": args.channel,
                "hardware_target": "esp32-s3-n16r8",
                "protocol_min": "pm-protocol/1.0.0",
                "protocol_max": "pm-protocol/1.0.0",
                "sha256": firmware_metadata.sha256,
                "signing_key_id": args.legacy_signing_key_id,
                "release_notes": notes,
            }
            write_json_atomic(
                staging / "manifest.legacy.unsigned.json", legacy_manifest
            )
        hashes = []
        for path in sorted(
            item
            for item in staging.iterdir()
            if item.is_file() and item.suffix in {".bin", ".elf", ".map"}
        ):
            hashes.append(f"{sha256_file(path)}  {path.name}\n")
        (staging / "SHA256SUMS").write_text(
            "".join(hashes), encoding="ascii", newline="\n"
        )
        (staging / "RELEASE_NOTES.md").write_text(
            f"# Power Monitor Sensor Agent {args.version}\n\n{notes}\n\n"
            "For central-server OTA, select only `firmware.bin`. The server "
            "strictly parses the ESP image, calculates its digest, and creates a "
            "per-device HMAC-authenticated manifest; no signing-key file or "
            "manually supplied manifest is used.\n",
            encoding="utf-8",
            newline="\n",
        )
        dependency = {
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "platform": "espressif32@6.13.0",
            "arduino_esp32": "2.0.17",
            "libraries": [
                {"name": "ArduinoJson", "version": "7.4.3", "license": "MIT"},
                {"name": "AsyncTCP", "version": "3.4.10", "license": "LGPL-3.0"},
                {
                    "name": "ESPAsyncWebServer",
                    "version": "3.11.2",
                    "license": "LGPL-3.0",
                },
            ],
        }
        write_json_atomic(staging / "dependencies.json", dependency)
        slot_size = 0x600000
        size_evidence = {
            "ota_slot_bytes": slot_size,
            "firmware_bytes": firmware.stat().st_size,
            "margin_bytes": slot_size - firmware.stat().st_size,
            "utilization_percent": round(firmware.stat().st_size * 100 / slot_size, 2),
        }
        write_json_atomic(staging / "size-margin.json", size_evidence)
        (staging / "LICENSE").write_text(
            (ROOT / "LICENSE").read_text(encoding="utf-8").rstrip() + "\n",
            encoding="utf-8",
        )
        validate_release_bundle(ROOT, staging)

        if release.exists():
            shutil.rmtree(release)
        staging.replace(release)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(f"release inputs written to {release}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

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
        description="Create unsigned reproducible release inputs and binary hashes"
    )
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--channel",
        choices=("development", "canary", "stable"),
        default="stable",
    )
    parser.add_argument(
        "--signing-key-id",
        required=True,
        help="Public Ed25519 key identifier configured on the server and sensor",
    )
    parser.add_argument(
        "--release-notes",
        help="Signed release notes; defaults to the standard release summary",
    )
    parser.add_argument("--pio", default="pio")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the exact version directory after a complete staged bundle passes validation",
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
        shutil.copy2(firmware, staging / "ota.bin")
        write_json_atomic(
            staging / FLASH_LAYOUT_FILENAME, flash_layout_document(staging)
        )

        digest = sha256_file(firmware)
        notes = args.release_notes or (
            f"Power Monitor Sensor Agent {args.version}: pm-protocol/1.0.0 "
            "production release. Physical PZEM, microSD, enclosure, and signed-OTA "
            "validation remains required on the target installation."
        )
        manifest = {
            "version": args.version,
            "channel": args.channel,
            "hardware_target": "esp32-s3-n16r8",
            "protocol_min": "pm-protocol/1.0.0",
            "protocol_max": "pm-protocol/1.0.0",
            "sha256": digest,
            "signing_key_id": args.signing_key_id,
            "release_notes": notes,
        }
        write_json_atomic(staging / "manifest.unsigned.json", manifest)
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
            "The manifest is intentionally unsigned. Run `tools/sign_firmware.py` "
            "with an external protected Ed25519 key to create `manifest.json`. "
            "Unsigned artifacts are rejected by the server and firmware.\n",
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

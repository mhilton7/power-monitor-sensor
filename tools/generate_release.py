#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create unsigned reproducible release inputs and binary hashes")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--image-url", default="https://server.example.invalid/releases/1.0.0/firmware.bin")
    parser.add_argument("--minimum-rollback-version", default="1.0.0")
    parser.add_argument("--pio", default="pio")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if not args.skip_build:
        subprocess.run([args.pio, "run", "-e", "esp32-s3-release"], cwd=ROOT, check=True)
    build = ROOT / ".pio" / "build" / "esp32-s3-release"
    firmware_source = build / "firmware.bin"
    if not firmware_source.is_file():
        raise SystemExit(f"release firmware missing: {firmware_source}")
    release = ROOT / "release" / args.version
    release.mkdir(parents=True, exist_ok=True)
    firmware = release / "firmware.bin"
    shutil.copy2(firmware_source, firmware)
    shutil.copy2(firmware_source, release / "ota.bin")
    for name in ["bootloader.bin", "partitions.bin", "firmware.elf", "firmware.map"]:
        source = build / name
        if source.is_file():
            shutil.copy2(source, release / name)
    digest = sha256(firmware)
    notes = f"Power Monitor Sensor Agent {args.version}: initial pm-protocol/1.0.0 production release. Physical PZEM, microSD, enclosure, and signed-OTA validation remains required on the target installation."
    manifest = {
        "schema_version": 1, "firmware_version": args.version, "protocol": "pm-protocol/1.0.0",
        "hardware_target": "esp32-s3-n16r8", "image_url": args.image_url,
        "image_size": firmware.stat().st_size, "image_sha256": digest,
        "minimum_rollback_version": args.minimum_rollback_version, "release_notes": notes,
        "signature_algorithm": "ecdsa-p256-sha256", "allow_downgrade": False,
    }
    (release / "manifest.unsigned.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    hashes = []
    for path in sorted(item for item in release.iterdir() if item.is_file() and item.suffix in {".bin", ".elf", ".map"}):
        hashes.append(f"{sha256(path)}  {path.name}\n")
    (release / "SHA256SUMS").write_text("".join(hashes), encoding="ascii", newline="\n")
    (release / "RELEASE_NOTES.md").write_text(f"# Power Monitor Sensor Agent {args.version}\n\n{notes}\n\nThe manifest is intentionally unsigned. Run `tools/sign_firmware.py` with an external protected P-256 key to create `manifest.json`. Unsigned artifacts are rejected by firmware.\n", encoding="utf-8", newline="\n")
    dependency = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "platform": "espressif32@6.13.0", "arduino_esp32": "2.0.17",
        "libraries": [
            {"name": "ArduinoJson", "version": "7.4.3", "license": "MIT"},
            {"name": "AsyncTCP", "version": "3.4.10", "license": "LGPL-3.0"},
            {"name": "ESPAsyncWebServer", "version": "3.11.2", "license": "LGPL-3.0"},
        ],
    }
    (release / "dependencies.json").write_text(json.dumps(dependency, indent=2) + "\n", encoding="utf-8", newline="\n")
    slot_size = 0x600000
    size_evidence = {
        "ota_slot_bytes": slot_size,
        "firmware_bytes": firmware.stat().st_size,
        "margin_bytes": slot_size - firmware.stat().st_size,
        "utilization_percent": round(firmware.stat().st_size * 100 / slot_size, 2),
    }
    (release / "size-margin.json").write_text(json.dumps(size_evidence, indent=2) + "\n", encoding="utf-8", newline="\n")
    shutil.copy2(ROOT / "LICENSE", release / "LICENSE")
    print(f"release inputs written to {release}")


if __name__ == "__main__":
    main()

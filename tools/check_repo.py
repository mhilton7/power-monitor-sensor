#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

from release_integrity import ReleaseIntegrityError, validate_release_bundle

ROOT = Path(__file__).resolve().parents[1]

RECOVERY_FIRMWARE_IDENTIFIERS = (
    "admin-recovery-begin ",
    "admin-password ",
    "PHYSICAL_ADMIN_RECOVERY_BUILD",
    "ADMIN_RECOVERY_TASK_FAILED",
    "ADMIN_RECOVERY_OFFLINE_READY",
    "ADMIN_RECOVERY_COMMAND_REJECTED",
    "ADMIN_PASSWORD_RECOVERY_ARM_REJECTED",
    "ADMIN_PASSWORD_RECOVERY_READY",
    "ADMIN_PASSWORD_RECOVERY_ARMED",
    "ADMIN_PASSWORD_RECOVERY_COMMAND_REJECTED",
    "ADMIN_PASSWORD_RECOVERY_REQUESTED",
    "ADMIN_PASSWORD_RECOVERY_APPLIED",
    "ADMIN_PASSWORD_RECOVERY_REJECTED",
    "ADMIN_PASSWORD_RECOVERY_FAILED",
    "ADMIN_PASSWORD_RECOVERY_COMPLETE",
    "ADMIN_PASSWORD_PHYSICAL_RECOVERY_COMMITTED",
    "ADMIN_PASSWORD_PHYSICAL_RECOVERY_ROLLED_BACK",
)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def production_firmware_artifact_paths(root: Path = ROOT) -> tuple[Path, Path]:
    build_directory = root / ".pio" / "build" / "esp32-s3-release"
    return build_directory / "firmware.bin", build_directory / "firmware.elf"


def recovery_identifier_in_contents(contents: bytes) -> str | None:
    return next(
        (
            identifier
            for identifier in RECOVERY_FIRMWARE_IDENTIFIERS
            if identifier.encode("ascii") in contents
        ),
        None,
    )


def embedded_recovery_identifier(artifact_path: Path) -> str | None:
    if not artifact_path.is_file():
        return None
    return recovery_identifier_in_contents(artifact_path.read_bytes())


def main() -> None:
    protocol = (ROOT / "shared/protocol-version.txt").read_text().strip()
    if protocol != "pm-protocol/1.0.0":
        fail("unexpected shared protocol version")
    for path in (ROOT / "shared").rglob("*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            fail(f"invalid JSON {path}: {error}")
    try:
        import yaml
    except ImportError as error:
        fail(f"PyYAML is required for the build gate: {error}")
    for path in (ROOT / "shared" / "openapi").glob("*.yaml"):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if document.get("openapi") != "3.1.0" or not document.get("paths"):
            fail(f"invalid OpenAPI root in {path}")
    partition_path = ROOT / "partitions.csv"
    partitions: dict[str, tuple[str, str, int, int]] = {}
    with partition_path.open(encoding="utf-8", newline="") as handle:
        rows = csv.reader(line for line in handle if not line.lstrip().startswith("#"))
        for row in rows:
            if not row or len(row) < 5:
                continue
            name, kind, subtype, offset, size = (item.strip() for item in row[:5])
            partitions[name] = (kind, subtype, int(offset, 0), int(size, 0))
    required = {"nvs", "otadata", "phy_init", "pmconfig", "ota_0", "ota_1"}
    if not required.issubset(partitions):
        fail("partition layout is missing required boot, OTA, or configuration entries")
    ordered = sorted(
        (
            (offset, offset + size, name)
            for name, (_, _, offset, size) in partitions.items()
        )
    )
    for (_, previous_end, previous_name), (offset, _, name) in zip(
        ordered, ordered[1:]
    ):
        if offset < previous_end:
            fail(f"partition overlap between {previous_name} and {name}")
    if ordered[-1][1] > 0x1000000:
        fail("partition layout exceeds 16 MB")
    nvs_kind, nvs_subtype, nvs_offset, nvs_size = partitions["nvs"]
    if (nvs_kind, nvs_subtype, nvs_offset) != ("data", "nvs", 0x9000):
        fail("default NVS partition must be data/nvs at 0x9000")
    if nvs_size != 0x8000:
        fail("default NVS must preserve the legacy 0x8000-byte migration range")
    if partitions["otadata"][2:] != (0x11000, 0x2000):
        fail("otadata must follow the preserved legacy NVS range")
    relocation_script = ROOT / "tools" / "relocate_ota_selector.py"
    if not relocation_script.is_file():
        fail("PlatformIO OTA-selector relocation script is absent")
    relocation_text = relocation_script.read_text(encoding="utf-8")
    if 'OTA_SELECTOR_OFFSET = "0x11000"' not in relocation_text:
        fail("PlatformIO boot_app0 image is not aligned to otadata")
    for relocation_marker in (
        'normalized(value) == "boot_app0.bin"',
        "existing_offset not in",
        "env.Replace(UPLOADERFLAGS=uploader_flags)",
        "Verified upload layout:",
    ):
        if relocation_marker not in relocation_text:
            fail(
                "PlatformIO boot_app0 relocation does not verify and rewrite "
                "the executable uploader flags"
            )
    config_kind, config_subtype, config_offset, config_size = partitions["pmconfig"]
    if (config_kind, config_subtype) != ("data", "nvs"):
        fail("pmconfig must be a dedicated data/nvs partition")
    if config_offset < 0x14000 or config_offset + config_size > 0x20000:
        fail("pmconfig must fit between phy_init and the first application")
    if config_size < 0xC000:
        fail("pmconfig is too small for dual-slot configuration and enrollment")
    if partitions["ota_0"][2] != 0x20000:
        fail("ota_0 must begin at the configured 0x20000 upload offset")
    required_assets = ROOT / "src/ui/embedded_assets.h"
    if not required_assets.is_file() or required_assets.stat().st_size < 1000:
        fail("generated embedded UI assets are absent")
    forbidden = re.compile(
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|password\s*=\s*[\"'][^\"']{8,}", re.I
    )
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(
            part
            in {".git", ".pio", ".pio-core", ".test-tmp", "node_modules", "release"}
            for part in path.parts
        ):
            continue
        if path.suffix.lower() not in {
            ".cpp",
            ".h",
            ".py",
            ".ts",
            ".json",
            ".yaml",
            ".yml",
            ".md",
            ".ini",
            ".ps1",
            ".psm1",
            ".psd1",
        }:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text) and "fixtures" not in path.parts:
            fail(f"possible committed secret in {path}")
        if re.search(r"\bTODO\b|\bFIXME\b", text):
            fail(f"unfinished marker in {path}")
    build_config = (ROOT / "include/build_config.h").read_text(encoding="utf-8")
    if "!PM_RELEASE_BUILD || !PM_SIMULATED_METER" not in build_config:
        fail("release/simulator compile guard missing")
    if "!PM_RELEASE_BUILD || !PM_PHYSICAL_ADMIN_RECOVERY" not in build_config:
        fail("release/physical administrator recovery compile guard missing")
    platformio = (ROOT / "platformio.ini").read_text(encoding="utf-8")
    release_environment = platformio[
        platformio.index("[env:esp32-s3-release]") : platformio.index(
            "[env:esp32-s3-debug]"
        )
    ]
    recovery_environment = platformio[
        platformio.index("[env:esp32-s3-admin-recovery]") : platformio.index(
            "[env:native-tests]"
        )
    ]
    if "-DPM_PHYSICAL_ADMIN_RECOVERY=0" not in release_environment:
        fail("release firmware does not explicitly disable physical recovery")
    for marker in (
        "-DPM_PHYSICAL_ADMIN_RECOVERY=1",
        "-DPM_RELEASE_BUILD=0",
        "-DPM_SIMULATED_METER=0",
    ):
        if marker not in recovery_environment:
            fail(f"temporary administrator recovery environment missing {marker}")
    for artifact_path in production_firmware_artifact_paths():
        embedded_identifier = embedded_recovery_identifier(artifact_path)
        if embedded_identifier is not None:
            fail(
                "production firmware artifact contains a physical administrator "
                f"recovery identifier ({embedded_identifier}): {artifact_path}"
            )
    production_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for source_root in (ROOT / "include", ROOT / "src")
        for path in source_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".cpp", ".h"}
    )
    for forbidden_serial_secret in (
        "printSetupCredential",
        "SETUP_AP_CREDENTIAL",
        "scope=physical_serial_only",
        "local_secret",
    ):
        if forbidden_serial_secret in production_text:
            fail(
                "production serial output retains a setup-password disclosure "
                f"path: {forbidden_serial_secret}"
            )
    for required_serial_provisioning_marker in (
        "SETUP_AP_READY",
        "SETUP_AP_PASSWORD_APPLIED",
        "SETUP_AP_PASSWORD_REJECTED",
        "secret_logged=false",
        "writeSetupPasswordResult",
        "kRequestIdLength = 16U",
    ):
        if required_serial_provisioning_marker not in production_text:
            fail(
                "USB-only setup-password provisioning marker missing: "
                f"{required_serial_provisioning_marker}"
            )
    release_root = ROOT / "release"
    if release_root.is_dir():
        for release_directory in sorted(
            path
            for path in release_root.iterdir()
            if path.is_dir() and (path / "firmware.bin").is_file()
        ):
            try:
                validate_release_bundle(ROOT, release_directory)
            except ReleaseIntegrityError as error:
                fail(f"invalid or stale release bundle {release_directory}: {error}")
    print("repository policy, JSON, OpenAPI, partition, UI, and secret checks passed")


if __name__ == "__main__":
    main()

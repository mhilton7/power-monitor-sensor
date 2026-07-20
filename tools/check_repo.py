#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


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
    partition_total = 0x10000 + 0x600000 + 0x600000 + 0x3D0000
    if partition_total > 0x1000000:
        fail("partition layout exceeds 16 MB")
    required_assets = ROOT / "src/ui/embedded_assets.h"
    if not required_assets.is_file() or required_assets.stat().st_size < 1000:
        fail("generated embedded UI assets are absent")
    forbidden = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|password\s*=\s*[\"'][^\"']{8,}", re.I)
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in {".git", ".pio", ".pio-core", ".test-tmp", "node_modules", "release"} for part in path.parts):
            continue
        if path.suffix.lower() not in {".cpp", ".h", ".py", ".ts", ".json", ".yaml", ".yml", ".md", ".ini"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if forbidden.search(text) and "fixtures" not in path.parts:
            fail(f"possible committed secret in {path}")
        if re.search(r"\bTODO\b|\bFIXME\b", text):
            fail(f"unfinished marker in {path}")
    build_config = (ROOT / "include/build_config.h").read_text(encoding="utf-8")
    if "!PM_RELEASE_BUILD || !PM_SIMULATED_METER" not in build_config:
        fail("release/simulator compile guard missing")
    print("repository policy, JSON, OpenAPI, partition, UI, and secret checks passed")


if __name__ == "__main__":
    main()

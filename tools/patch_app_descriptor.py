"""PlatformIO post-action for deterministic Power Monitor app metadata."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

Import("env")  # type: ignore[name-defined]  # PlatformIO/SCons global

ROOT = Path(env.subst("$PROJECT_DIR"))  # type: ignore[name-defined]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from firmware_image import patch_firmware_descriptor  # noqa: E402


def macro(name: str) -> str:
    for definition in env.get("CPPDEFINES", []):  # type: ignore[name-defined]
        if isinstance(definition, (tuple, list)) and definition[0] == name:
            return str(definition[1]).strip('\\"')
    raise RuntimeError(f"Required build macro {name} is unavailable")


def patch_descriptor(target, source, env) -> None:
    del source
    firmware_path = Path(str(target[0]))
    elf_path = Path(env.subst("$BUILD_DIR/${PROGNAME}.elf"))
    version = macro("PM_FIRMWARE_VERSION")
    timestamp = datetime.fromisoformat(
        macro("PM_BUILD_TIMESTAMP").replace("Z", "+00:00")
    )
    metadata = patch_firmware_descriptor(
        firmware_path,
        elf_path,
        version=version,
        build_time=timestamp.strftime("%H:%M:%S"),
        build_date=(
            timestamp.strftime("%b")
            + f" {timestamp.day:2d} "
            + timestamp.strftime("%Y")
        ),
    )
    print(
        "Verified Power Monitor app descriptor: "
        f"version={metadata.version} project={metadata.project_name} "
        f"elf_sha256={metadata.build_hash} image_sha256={metadata.sha256}"
    )


env.AddPostAction(  # type: ignore[name-defined]
    "$BUILD_DIR/${PROGNAME}.bin", patch_descriptor
)

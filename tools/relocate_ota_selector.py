"""Align PlatformIO's Arduino OTA selector image with partitions.csv.

The Arduino PlatformIO integration assumes that every target places otadata at
0xE000. This project preserves the legacy 0x9000..0x10FFF NVS range so an
upgrade can read and migrate existing credentials. Move only the
framework-supplied boot_app0 image to the actual otadata offset; bootloader,
partition-table, and application addresses remain unchanged.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

Import("env")  # type: ignore[name-defined]  # PlatformIO/SCons global

ROOT = Path(env.subst("$PROJECT_DIR"))  # type: ignore[name-defined]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from release_integrity import (  # noqa: E402
    PROVENANCE_FILENAME,
    build_provenance_document,
    source_fingerprint,
    write_json_atomic,
)

OTA_SELECTOR_OFFSET = "0x11000"


def normalized(path: object) -> str:
    return Path(env.subst(str(path))).name.lower()  # type: ignore[name-defined]


images = list(env.get("FLASH_EXTRA_IMAGES", []))  # type: ignore[name-defined]
relocated: list[tuple[str, object]] = []
selector_count = 0
selector_source: Path | None = None
for offset, image in images:
    if normalized(image) == "boot_app0.bin":
        relocated.append((OTA_SELECTOR_OFFSET, image))
        selector_count += 1
        selector_source = Path(env.subst(str(image)))  # type: ignore[name-defined]
    else:
        relocated.append((offset, image))

if selector_count != 1:
    raise RuntimeError(
        "Expected exactly one Arduino boot_app0.bin image; refusing an "
        f"ambiguous upload layout (found {selector_count})."
    )

env.Replace(FLASH_EXTRA_IMAGES=relocated)  # type: ignore[name-defined]

# PlatformIO flattens FLASH_EXTRA_IMAGES into UPLOADERFLAGS before a `post:`
# extra script runs. Updating only FLASH_EXTRA_IMAGES therefore changes later
# metadata consumers but leaves the already-created esptool action unsafe.
# Rewrite the exact address immediately preceding boot_app0.bin as well; the
# upload action expands UPLOADERFLAGS when it executes.
uploader_flags = list(env.get("UPLOADERFLAGS", []))  # type: ignore[name-defined]
uploader_selector_indices = [
    index
    for index, value in enumerate(uploader_flags)
    if normalized(value) == "boot_app0.bin"
]
if len(uploader_selector_indices) != 1:
    raise RuntimeError(
        "Expected exactly one boot_app0.bin in PlatformIO uploader flags; "
        "refusing an unverified upload command "
        f"(found {len(uploader_selector_indices)})."
    )

selector_index = uploader_selector_indices[0]
if selector_index == 0:
    raise RuntimeError(
        "boot_app0.bin has no preceding flash address in uploader flags."
    )
existing_offset = str(uploader_flags[selector_index - 1]).lower()
if existing_offset not in {"0xe000", OTA_SELECTOR_OFFSET.lower()}:
    raise RuntimeError(
        "Unexpected boot_app0.bin uploader offset "
        f"{existing_offset}; refusing to guess."
    )
uploader_flags[selector_index - 1] = OTA_SELECTOR_OFFSET
env.Replace(UPLOADERFLAGS=uploader_flags)  # type: ignore[name-defined]
verified_flags = list(env.get("UPLOADERFLAGS", []))  # type: ignore[name-defined]
if str(verified_flags[selector_index - 1]).lower() != OTA_SELECTOR_OFFSET.lower():
    raise RuntimeError("PlatformIO did not retain the safe OTA selector offset.")

if selector_source is None or not selector_source.is_file():
    raise RuntimeError("The verified framework boot_app0.bin source is unavailable.")
build_directory = Path(env.subst("$BUILD_DIR"))  # type: ignore[name-defined]
build_directory.mkdir(parents=True, exist_ok=True)
shutil.copy2(selector_source, build_directory / "boot_app0.bin")

configured_source_sha256 = source_fingerprint(ROOT)


def write_release_provenance(target, source, env) -> None:
    del target, source
    environment = str(env.subst("$PIOENV"))
    document = build_provenance_document(
        ROOT,
        Path(env.subst("$BUILD_DIR")),
        environment,
        configured_source_sha256,
    )
    write_json_atomic(Path(env.subst("$BUILD_DIR")) / PROVENANCE_FILENAME, document)
    print(
        "Recorded release build provenance: "
        f"environment={environment} source_sha256={configured_source_sha256}"
    )


env.AddPostAction(  # type: ignore[name-defined]
    "$BUILD_DIR/${PROGNAME}.bin", write_release_provenance
)
print(
    f"Verified upload layout: boot_app0.bin will be written at {OTA_SELECTOR_OFFSET}."
)

from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
TEST_TEMP = ROOT / ".test-tmp"
TEST_TEMP.mkdir(exist_ok=True)


def case_directory(name: str) -> Path:
    path = TEST_TEMP / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir()
    return path


from repair_sd_index import rebuild  # noqa: E402
from release_integrity import (  # noqa: E402
    FLASH_IMAGE_OFFSETS,
    PROVENANCE_FILENAME,
    REQUIRED_BUILD_ARTIFACTS,
    ReleaseIntegrityError,
    build_provenance_document,
    flash_layout_document,
    source_fingerprint,
    validate_build_provenance,
    validate_release_bundle,
    write_json_atomic,
)
from generate_release import create_staging_directory  # noqa: E402
from sd_format import decode, encode  # noqa: E402
from sign_firmware import canonical  # noqa: E402


class StorageAndOtaTests(unittest.TestCase):
    def test_release_staging_directory_is_unique_and_inherits_parent(self) -> None:
        root = case_directory("release-staging")
        try:
            first = create_staging_directory(root, "1.0.1")
            second = create_staging_directory(root, "1.0.1")
            self.assertEqual(first.parent, root)
            self.assertEqual(second.parent, root)
            self.assertNotEqual(first, second)
            self.assertTrue(first.is_dir())
            self.assertTrue(second.is_dir())
        finally:
            shutil.rmtree(root)

    def test_release_provenance_rejects_stale_or_incomplete_builds(self) -> None:
        root = case_directory("release-integrity")
        try:
            (root / "platformio.ini").write_text("[platformio]\n", encoding="utf-8")
            (root / "partitions.csv").write_text(
                "ota_0,app,ota_0,0x20000,0x600000\n", encoding="utf-8"
            )
            source = root / "src"
            source.mkdir()
            (source / "main.cpp").write_text("int main() { return 0; }\n")
            build = root / "build"
            build.mkdir()
            for index, name in enumerate(REQUIRED_BUILD_ARTIFACTS, start=1):
                (build / name).write_bytes(bytes([index]) * (index + 3))

            fingerprint = source_fingerprint(root)
            provenance = build_provenance_document(
                root, build, "esp32-s3-release", fingerprint
            )
            write_json_atomic(build / PROVENANCE_FILENAME, provenance)
            self.assertEqual(validate_build_provenance(root, build), provenance)
            self.assertEqual(
                {
                    image["filename"]: image["offset"]
                    for image in flash_layout_document(build)["images"]
                },
                {name: f"0x{offset:x}" for name, offset in FLASH_IMAGE_OFFSETS.items()},
            )

            release = root / "release"
            release.mkdir()
            for name in REQUIRED_BUILD_ARTIFACTS:
                shutil.copy2(build / name, release / name)
            shutil.copy2(build / PROVENANCE_FILENAME, release / PROVENANCE_FILENAME)
            shutil.copy2(build / "firmware.bin", release / "ota.bin")
            write_json_atomic(
                release / "flash-layout.json", flash_layout_document(release)
            )
            validate_release_bundle(root, release)
            (source / "main.cpp").write_text("int main() { return 1; }\n")
            with self.assertRaisesRegex(ReleaseIntegrityError, "stale"):
                validate_release_bundle(root, release)
            validate_release_bundle(root, release, require_current_source=False)
            (source / "main.cpp").write_text("int main() { return 0; }\n")
            (release / "firmware.bin").write_bytes(b"tampered")
            with self.assertRaisesRegex(ReleaseIntegrityError, "build provenance"):
                validate_release_bundle(root, release)

            (source / "main.cpp").write_text("int main() { return 1; }\n")
            with self.assertRaisesRegex(ReleaseIntegrityError, "stale"):
                validate_build_provenance(root, build)
            (build / "boot_app0.bin").unlink()
            with self.assertRaisesRegex(
                ReleaseIntegrityError, "required build artifact"
            ):
                build_provenance_document(
                    root, build, "esp32-s3-release", source_fingerprint(root)
                )
        finally:
            shutil.rmtree(root)

    def test_pmr1_round_trip_crc_and_corrupt_tail(self) -> None:
        record = {
            "schema_version": 1,
            "sequence": 42,
            "start_utc_ms": 1234,
            "value": "µ",
        }
        line = encode(record)
        self.assertEqual(decode(line).record, record)
        corrupt = bytearray(line)
        corrupt[8] ^= 1
        with self.assertRaisesRegex(ValueError, "crc_mismatch"):
            decode(bytes(corrupt))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            decode(line[:-1])

    def test_index_rebuild_repairs_only_incomplete_tail(self) -> None:
        root_directory = case_directory("index-repair")
        try:
            root = root_directory / "POWERMON"
            record_path = root / "records/2026/07/2026-07-20.pmr"
            record_path.parent.mkdir(parents=True)
            records = [
                {"sequence": 1, "start_utc_ms": 10},
                {"sequence": 2, "start_utc_ms": 20},
            ]
            complete = b"".join(encode(record) for record in records)
            record_path.write_bytes(complete + b"PMR1\tpartial")
            count, index_path = rebuild(record_path, True)
            self.assertEqual(count, 2)
            self.assertEqual(record_path.read_bytes(), complete)
            entries = index_path.read_text().splitlines()
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0].split(",")[:2], ["1", "10"])
        finally:
            shutil.rmtree(root_directory)

    def test_complete_corruption_is_never_silently_removed(self) -> None:
        root_directory = case_directory("complete-corruption")
        try:
            path = root_directory / "records/bad.pmr"
            path.parent.mkdir(parents=True)
            line = bytearray(encode({"sequence": 1, "start_utc_ms": 10}))
            line[7] ^= 1
            original = bytes(line)
            path.write_bytes(original)
            with self.assertRaises(SystemExit):
                rebuild(path, True)
            self.assertEqual(path.read_bytes(), original)
        finally:
            shutil.rmtree(root_directory)

    def test_ota_manifest_canonical_signature_and_tamper_rejection(self) -> None:
        manifest = {
            "version": "1.0.1",
            "channel": "stable",
            "hardware_target": "esp32-s3-n16r8",
            "protocol_min": "pm-protocol/1.0.0",
            "protocol_max": "pm-protocol/1.0.0",
            "sha256": "ab" * 32,
            "signing_key_id": "test-ed25519-2026",
            "release_notes": "Unicode is canonical too: \u00b5 \u26a1",
        }
        expected = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        self.assertEqual(canonical(manifest), expected)
        private_key = Ed25519PrivateKey.generate()
        signature = private_key.sign(canonical(manifest))
        private_key.public_key().verify(signature, canonical(manifest))
        tampered = dict(
            manifest,
            release_notes="Unicode is canonical too: \u00b5 \u26a1 (tampered)",
        )
        with self.assertRaises(Exception):
            private_key.public_key().verify(signature, canonical(tampered))


if __name__ == "__main__":
    unittest.main()

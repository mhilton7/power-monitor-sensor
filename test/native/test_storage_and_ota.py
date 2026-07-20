from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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
from sd_format import decode, encode  # noqa: E402
from sign_firmware import canonical  # noqa: E402


class StorageAndOtaTests(unittest.TestCase):
    def test_pmr1_round_trip_crc_and_corrupt_tail(self) -> None:
        record = {"schema_version": 1, "sequence": 42, "start_utc_ms": 1234, "value": "µ"}
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
            "schema_version": 1,
            "firmware_version": "1.0.0",
            "protocol": "pm-protocol/1.0.0",
            "hardware_target": "esp32-s3-n16r8",
            "image_url": "https://example.invalid/firmware.bin",
            "image_size": 123,
            "image_sha256": "ab" * 32,
            "minimum_rollback_version": "1.0.0",
            "release_notes": "Test release",
            "allow_downgrade": False,
        }
        private_key = ec.generate_private_key(ec.SECP256R1())
        signature = private_key.sign(canonical(manifest), ec.ECDSA(hashes.SHA256()))
        private_key.public_key().verify(signature, canonical(manifest), ec.ECDSA(hashes.SHA256()))
        tampered = dict(manifest, image_size=124)
        with self.assertRaises(Exception):
            private_key.public_key().verify(signature, canonical(tampered), ec.ECDSA(hashes.SHA256()))


if __name__ == "__main__":
    unittest.main()

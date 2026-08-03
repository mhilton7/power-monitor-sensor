from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import shutil
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
TEST_TEMP = ROOT / ".test-tmp" / "ota-v2"


def case_directory(name: str) -> Path:
    path = TEST_TEMP / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)
    return path


from firmware_image import (  # noqa: E402
    ESP_APP_DESC_MAGIC,
    ESP_CHECKSUM_MAGIC,
    FirmwareImageError,
    inspect_firmware,
    patch_firmware_descriptor,
)


def hkdf_sha256(secret: bytes, salt: bytes, info: bytes) -> bytes:
    pseudorandom_key = hmac.new(salt, secret, hashlib.sha256).digest()
    return hmac.new(pseudorandom_key, info + b"\x01", hashlib.sha256).digest()


def synthetic_image() -> bytes:
    descriptor = bytearray(256)
    struct.pack_into("<I", descriptor, 0, ESP_APP_DESC_MAGIC)
    descriptor[16:48] = b"old-version\0" + bytes(20)
    descriptor[48:80] = b"arduino-lib-builder\0" + bytes(12)
    descriptor[80:96] = b"00:00:00\0" + bytes(7)
    descriptor[96:112] = b"Jan  1 2024\0" + bytes(4)
    descriptor[112:144] = b"idf-test\0" + bytes(23)
    segment_data = descriptor + bytearray(b"pm-protocol/1.0.0\0")
    segment_data.extend(bytes((-len(segment_data)) % 4))
    header = bytearray(24)
    struct.pack_into("<BBBBI", header, 0, 0xE9, 1, 0, 0, 0x40370000)
    struct.pack_into("<H", header, 12, 9)
    header[23] = 1
    image = header + struct.pack("<II", 0x3C000020, len(segment_data)) + segment_data
    checksum = ESP_CHECKSUM_MAGIC
    for byte in segment_data:
        checksum ^= byte
    checksum_offset = len(image) + (15 - (len(image) % 16))
    image.extend(bytes(checksum_offset - len(image)))
    image.append(checksum)
    image.extend(hashlib.sha256(image).digest())
    return bytes(image)


class OtaManifestVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vector = json.loads(
            (ROOT / "shared/auth-test-vectors/ota-manifest-v2.json").read_text(
                encoding="utf-8"
            )
        )

    def test_normative_hkdf_and_hmac_vector(self) -> None:
        key = hkdf_sha256(
            bytes.fromhex(self.vector["secret_hex"]),
            self.vector["hkdf_salt_utf8"].encode(),
            self.vector["hkdf_info_utf8"].encode(),
        )
        self.assertEqual(key.hex(), self.vector["derived_key_hex"])
        canonical = json.dumps(
            self.vector["manifest_without_hmac"],
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(canonical, self.vector["canonical_json_utf8"])
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(key, canonical.encode(), hashlib.sha256).digest()
            )
            .decode()
            .rstrip("=")
        )
        self.assertEqual(signature, self.vector["manifest_hmac_base64url"])

    def test_wrong_hmac_secret_device_and_manifest_tampering_fail(self) -> None:
        vector = self.vector
        canonical = vector["canonical_json_utf8"].encode()
        expected = vector["manifest_hmac_base64url"]

        def signature(secret: bytes, device_id: str, body: bytes) -> str:
            key = hkdf_sha256(
                secret,
                device_id.encode(),
                vector["hkdf_info_utf8"].encode(),
            )
            return (
                base64.urlsafe_b64encode(hmac.new(key, body, hashlib.sha256).digest())
                .decode()
                .rstrip("=")
            )

        secret = bytes.fromhex(vector["secret_hex"])
        self.assertNotEqual(
            signature(bytes(reversed(secret)), vector["device_id"], canonical),
            expected,
        )
        self.assertNotEqual(
            signature(secret, "123e4567-e89b-12d3-a456-426614174999", canonical),
            expected,
        )
        self.assertNotEqual(
            signature(
                secret,
                vector["device_id"],
                canonical.replace(b"1.0.11", b"1.0.12"),
            ),
            expected,
        )

    def test_bad_hmac_cannot_poison_recovery_before_authentication(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        flow = service[
            service.index("bool OtaService::applyFromManifestUrl") : service.index(
                "bool OtaService::parseManifest"
            )
        ]
        authentication = flow.index("if (!verifyManifest(manifest, error))")
        replay_check = flow.index("const ota_v2::RecoveryRecord prior = recovery_")
        recovery_commit = flow.index("recovery_ = {}")
        self.assertLess(authentication, replay_check)
        self.assertLess(replay_check, recovery_commit)
        rejection = flow[
            authentication : flow.index(
                "const ota_v2::RecoveryRecord prior = recovery_"
            )
        ]
        self.assertNotIn("persistState(", rejection)
        self.assertNotIn("postReport(", rejection)
        self.assertNotIn("recovery_ =", rejection)

    def test_post_boot_failure_defers_terminal_report_until_rollback(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        begin = service[
            service.index("bool OtaService::begin()") : service.index(
                "bool OtaService::runningImagePendingVerification"
            )
        ]
        validation = service[
            service.index("bool OtaService::checkRunningImage") : service.index(
                "bool OtaService::applyFromManifestUrl"
            )
        ]
        deferred = re.compile(
            r"setState\(ota_v2::State::PostBootValidation,\s*"
            r'"post_boot_validation", \{\},\s*true, false\);'
        )
        self.assertRegex(begin, deferred)
        self.assertRegex(validation, deferred)
        self.assertRegex(
            validation,
            re.compile(
                r"setState\(ota_v2::State::Failed,\s*"
                r'"post_boot_failed",\s*failure_code, true, false\);'
            ),
        )

    def test_transient_manifest_failure_cannot_redirect_pending_report(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        self.assertGreaterEqual(
            service.count("reportMilestoneForState(recovery_.state)"), 2
        )
        self.assertNotIn("reportMilestoneForState(status().state)", service)
        self.assertIn(
            "const std::string &failure_code = recovery_.failure_code;", service
        )


class FirmwareDescriptorTests(unittest.TestCase):
    def test_patch_recomputes_descriptor_checksum_and_appended_sha(self) -> None:
        root = case_directory("descriptor-patch")
        try:
            firmware = root / "firmware.bin"
            elf = root / "firmware.elf"
            firmware.write_bytes(synthetic_image())
            elf.write_bytes(b"deterministic synthetic ELF")
            metadata = patch_firmware_descriptor(
                firmware,
                elf,
                version="1.0.11",
                build_time="20:00:00",
                build_date="Aug  2 2026",
            )
            self.assertEqual(metadata.project_name, "power-monitor-sensor")
            self.assertEqual(metadata.version, "1.0.11")
            self.assertEqual(
                metadata.build_hash, hashlib.sha256(elf.read_bytes()).hexdigest()
            )
            self.assertEqual(inspect_firmware(firmware), metadata)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_strict_gate_rejects_corruption_truncation_and_extra_bytes(self) -> None:
        root = case_directory("strict-corruption-gate")
        try:
            firmware = root / "firmware.bin"
            elf = root / "firmware.elf"
            firmware.write_bytes(synthetic_image())
            elf.write_bytes(b"ELF")
            patch_firmware_descriptor(
                firmware,
                elf,
                version="1.0.11",
                build_time="20:00:00",
                build_date="Aug  2 2026",
            )
            valid = firmware.read_bytes()
            cases = {
                "firmware_image_invalid": bytes([0]) + valid[1:],
                "firmware_wrong_target": valid[:12] + b"\x05\x00" + valid[14:],
                "firmware_image_truncated": valid[:-40],
                "firmware_image_extra_bytes": valid + b"x",
                "firmware_checksum_invalid": (
                    valid[:40] + bytes([valid[40] ^ 1]) + valid[41:]
                ),
            }
            for expected, damaged in cases.items():
                firmware.write_bytes(damaged)
                with (
                    self.subTest(expected=expected),
                    self.assertRaisesRegex(FirmwareImageError, expected),
                ):
                    inspect_firmware(firmware)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_ota_sources_preserve_configuration_sequence_and_storage(self) -> None:
        service = (ROOT / "src/ota/OtaService.cpp").read_text(encoding="utf-8")
        recovery = (ROOT / "src/ota/OtaRecoveryStore.cpp").read_text(encoding="utf-8")
        for forbidden in (
            "factoryReset(",
            "networkReset(",
            "setServerAckSequence(",
            "setServerMaximumSeenSequence(",
            "SdStorage",
            "microSD",
        ):
            self.assertNotIn(forbidden, service)
        self.assertIn('kPersistentPartition[] = "pmconfig"', recovery)
        self.assertIn('kOtaRecoverySlots{"ota_a", "ota_b",', recovery)


if __name__ == "__main__":
    unittest.main()

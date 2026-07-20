# Signed OTA

The 16 MB table has two 6 MB OTA slots, OTA metadata, NVS, PHY, LittleFS, and coredump. Updates target the inactive slot. ESP-IDF marks a new image pending; after storage, meter service, network, queues, and tasks start, firmware confirms it. Repeated incomplete boots enter safe mode, and local rollback is available.

Manifest schema 1 requires semantic version, `pm-protocol/1.0.0`, `esp32-s3-n16r8`, HTTPS image URL, byte size, lowercase SHA-256, minimum rollback version, notes, `ecdsa-p256-sha256`, downgrade policy, and base64 DER signature. Signed UTF-8 lines:

```text
PM-OTA-MANIFEST-V1
schema_version
firmware_version
protocol
hardware_target
image_url
image_size
image_sha256
minimum_rollback_version
sha256(release_notes)
true|false
```

Firmware validates policy/public key before download, restricts manifest/image hosts when a server allowlist is configured, enforces the optional UTC update window, uses configured CA/fingerprint, streams to inactive flash with size/time bounds, hashes during write, and finalizes only on exact match. Unsigned, invalid, cross-target/protocol, truncated, oversized, hash-mismatched, out-of-window, and unauthorized downgrade updates fail.

Generate/sign per [BUILD_AND_FLASH.md](BUILD_AND_FLASH.md). Protect and back up the external private key; rotate through an independently authenticated process, never an untrusted manifest.

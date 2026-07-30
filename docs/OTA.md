# Signed central-server OTA

The 16 MB layout has two 6 MB application slots. The ESP32 writes an update to the inactive slot, boots it as pending, and confirms it only after the required health checks pass. Failed confirmation permits the ESP-IDF rollback path. OTA never uses microSD or fabricated firmware data as a fallback.

The sensor polls the configured server’s HMAC-authenticated `GET /api/v1/device-firmware/manifest`. An available response must contain `version`, `channel`, `hardware_target`, `protocol_min`, `protocol_max`, `size_bytes`, lowercase `sha256`, a base64 64-byte Ed25519 `signature`, `signing_key_id`, `release_notes`, and a same-origin relative `download_path`. The signature covers sorted compact JSON containing exactly:

```text
channel
hardware_target
protocol_max
protocol_min
release_notes
sha256
signing_key_id
version
```

This is the same canonical form used by the sibling Power Monitor server: Python `json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()`. The download is another HMAC-authenticated GET, over the relative target supplied by the manifest. For a `.local` URL, both manifest and image requests may resolve through mDNS, but they retain the configured hostname for SNI and SAN verification. HTTPS CA/hostname validation remains mandatory. Firmware enforces the configured key ID, Ed25519 signature, target, protocol range, channel, monotonic semantic version, 6 MiB slot limit, exact content length, and streaming SHA-256 before finalizing.

OTA trust is local-only. During first-run setup, or later through the authenticated network-settings page, paste an independently verified Ed25519 SubjectPublicKeyInfo `PUBLIC KEY` PEM together with its key ID. The key is stored atomically but never returned by an API or diagnostic export. A private key is rejected. Remote desired configuration and an untrusted manifest cannot install or rotate this trust root. With no key, firmware continues normal monitoring and synchronization but OTA fails closed.

The current sibling server needs two server-side corrections before end-to-end OTA can succeed:

- Include `release_notes` unchanged in every available device manifest response. It is part of the uploaded, verified signature, so omitting it makes reconstruction and verification impossible.
- Provide an independently authenticated administrator workflow for distributing the trusted Ed25519 public key and key ID. Its enrollment response currently returns `server_ota_signing_public_key: null`; firmware therefore requires deliberate local provisioning.

Do not weaken TLS, skip HMAC, accept a key from the manifest being verified, or place the offline signing private key on the sensor/server. Generate and sign release input as described in [BUILD_AND_FLASH.md](BUILD_AND_FLASH.md).

# Security model

Assets include Wi-Fi credentials, enrollment secret, directional keys, local password verifier, setup credential, OTA key, history, config, and cursor. Threats include impersonation, replay, CSRF, brute force, malicious OTA, media tampering, leakage, and resource exhaustion.

- Outbound HTTPS requires a CA PEM with certificate-chain and hostname validation. The legacy fingerprint field is retained for protocol/configuration compatibility but fingerprint-only operation fails closed; no production path calls `setInsecure()`.
- Single-use enrollment and at least 256 random secret bits feed separate RFC 5869 directional keys.
- HMAC binds protocol, method, canonical target, timestamp, nonce, and body hash; comparisons, time window, and replay cache are hardened.
- Passwords use PBKDF2-HMAC-SHA256, random 128-bit salts, and 120,000 iterations. Sessions/CSRF are random, short, same-origin, and throttled.
- Secrets are write-only. Config/health/metrics/logs/bundles redact credentials, keys, cookies, and signatures. A new setup password appears only on physical serial output.
- Bodies, pages, queues, responses, SD lines, OTA, and timeouts are bounded. Authenticated APIs use a burst ceiling, history reads are separately throttled, and HTTP callbacks delegate long work.
- OTA requires ECDSA P-256, target/protocol/hash/downgrade checks, dual slots, post-boot confirmation, and rollback.
- SD CRC is integrity/error detection, not confidentiality/authenticity. Protect media and encrypt backups as needed.

Deploy on an IoT VLAN, block inbound Internet, permit DNS/NTP/configured allowlisted server hosts, and use outbound push/hybrid or private VPN. The authenticated local reenrollment workflow revokes the existing device secret before claiming a new single-use token; factory reset also erases credentials.

Physical boundary: NVS encryption and secure boot depend on deployment-specific fuses/keys and are not enabled by a generic developer flash. Hostile sites should provision ESP32-S3 secure boot V2 and flash encryption under an organizational key ceremony after validating recovery.

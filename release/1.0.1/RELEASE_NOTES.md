# Power Monitor Sensor Agent 1.0.1

Repairs persistent server reconnection and backlog synchronization with signed permanent-loss ranges, bulk FATFS reads, serialized TLS/history memory ownership, prioritized primary sync, bounded local history, and crash-safe automatic recovery.

The manifest is intentionally unsigned. Run `tools/sign_firmware.py` with an external protected Ed25519 key to create `manifest.json`. Unsigned artifacts are rejected by the server and firmware.

# Power Monitor Sensor Agent 1.0.5

Repairs overlapping TLS connections, reduces hot-path allocations and UI load, adds resource-aware deferral, and expands memory, task, and compact diagnostics without changing pm-protocol/1.0.0.

The manifest is intentionally unsigned. Run `tools/sign_firmware.py` with an external protected Ed25519 key to create `manifest.json`. Unsigned artifacts are rejected by the server and firmware.

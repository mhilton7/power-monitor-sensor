# Power Monitor Sensor Agent 1.0.0

Power Monitor Sensor Agent 1.0.0: pm-protocol/1.0.0 production firmware with physically validated ESP32-S3 heartbeat, TLS, WebUI isolation, and microSD recovery. PZEM mains and signed OTA deployment remain installation-specific validation.

The manifest is intentionally unsigned. Run `tools/sign_firmware.py` with an external protected Ed25519 key to create `manifest.json`. Unsigned artifacts are rejected by the server and firmware.

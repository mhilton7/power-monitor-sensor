# Power Monitor Sensor Agent 1.0.8

Power Monitor Sensor Agent 1.0.8: pm-protocol/1.0.0 production release. Physical PZEM, microSD, enclosure, and signed-OTA validation remains required on the target installation.

The manifest is intentionally unsigned. Run `tools/sign_firmware.py` with an external protected Ed25519 key to create `manifest.json`. Unsigned artifacts are rejected by the server and firmware.

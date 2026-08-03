# Power Monitor Sensor Agent 1.0.12

Power Monitor Sensor Agent 1.0.12: pm-protocol/1.0.0 production release. Physical PZEM, microSD, enclosure, and device-authenticated HMAC OTA validation remain required on the target installation.

For central-server OTA, select only `firmware.bin`. The server strictly parses the ESP image, calculates its digest, and creates a per-device HMAC-authenticated manifest; no signing-key file or manually supplied manifest is used.

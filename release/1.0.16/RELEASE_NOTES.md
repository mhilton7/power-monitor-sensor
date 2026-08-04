# Power Monitor Sensor Agent 1.0.16

Power Monitor Sensor Agent 1.0.16 canary for non-erasing USB bootstrap validation. Physical PZEM, microSD, enclosure, sensor stability, and device-authenticated HMAC OTA validation are required before stable promotion.

For central-server OTA, select only `firmware.bin`. The server strictly parses the ESP image, calculates its digest, and creates a per-device HMAC-authenticated manifest; no signing-key file or manually supplied manifest is used.

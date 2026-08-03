# Power Monitor Sensor Agent 1.0.13

OTA panic repair: transaction-scoped TLS memory, reboot-safe stage ledger, bounded status responses, deterministic server reconciliation, and fault-injection coverage.

For central-server OTA, select only `firmware.bin`. The server strictly parses the ESP image, calculates its digest, and creates a per-device HMAC-authenticated manifest; no signing-key file or manually supplied manifest is used.

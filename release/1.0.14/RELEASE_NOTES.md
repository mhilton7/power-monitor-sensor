# Power Monitor Sensor Agent 1.0.14

Physical 1.0.13 canary correction: restore idle TLS reserve with a bounded 16 KiB OTA task and scoped internal 4 KiB flash-write buffer; retain transaction-scoped TLS, crash ledger, bounded status responses, and server reconciliation.

For central-server OTA, select only `firmware.bin`. The server strictly parses the ESP image, calculates its digest, and creates a per-device HMAC-authenticated manifest; no signing-key file or manually supplied manifest is used.

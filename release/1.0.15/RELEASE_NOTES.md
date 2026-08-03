# Power Monitor Sensor Agent 1.0.15

Managed-OTA canary for the repaired transaction-scoped TLS lifecycle, allocation-stable Status endpoint, crash ledger, bounded failure reporting, and server reconciliation workflow. Promote only after the physical canary OTA and short live validation pass.

For central-server OTA, select only `firmware.bin`. The server strictly parses the ESP image, calculates its digest, and creates a per-device HMAC-authenticated manifest; no signing-key file or manually supplied manifest is used.

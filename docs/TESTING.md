# Testing

All automated tests are host/low-voltage only. Never connect live mains for them.

- `python -m unittest discover -s test -p 'test_*.py' -v`: canonical HMAC/HKDF/replay, schemas/OpenAPI, PMR1 CRC/tail/index, OTA ECDSA tamper rejection, and loopback enrollment/heartbeat/backfill/dedupe/conflict.
- PlatformIO `native-tests` plus its executable: PZEM request/CRC/parser faults, measurement limits, energy reset/rollover/integration, interval duplicate handling, retention protection, record CRC.
- `npm test -- --run`: login, status, persistent SD warning, setup/write-only secrets, destructive confirmation, mobile and keyboard behavior.
- ESP32 release, debug, and simulated-meter environments.
- `tools/check_repo.py`: JSON/OpenAPI, partitions, embedded UI, simulator guard, unfinished markers, and secret patterns.

The simulator is loopback and volatile. `simulator/scenarios/` describes nominal, outage/backfill, and faults. Physical validation remains required for the exact N16R8 board, translator, purchased PZEM, card, enclosure, real CA, and signed OTA/rollback.

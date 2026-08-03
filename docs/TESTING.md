# Testing

All automated tests are host/low-voltage only. Never connect live mains for
them. Install the pinned dependencies, then run:

```sh
python -m unittest discover -s test -p "test_*.py" -v
cd web
npm ci
npm test -- --run
npm run build
npm run format:check
cd ..
python -m platformio run -e native-tests
python -m platformio run -e native-sanitized
python -m platformio run -e esp32-s3-release
python -m platformio run -e esp32-s3-debug
python -m platformio run -e esp32-s3-simulated-meter
python tools/check_repo.py
```

The Python suite covers schemas/OpenAPI, canonical request HMAC/HKDF/replay,
PMR1 CRC/tail/index behavior, release provenance, ESP application parsing,
cross-language OTA-manifest vectors, and loopback enrollment/heartbeat/
backfill/deduplication/conflict/download behavior. Native and sanitized tests
cover meter parsing, measurement limits, interval/retention/storage behavior,
OTA v2 manifest authentication/policy, stream truncation/extra bytes/hash
failure, partition/recovery state, post-boot success/failure, rollback, and
memory state transitions. The simulated-meter binary is never release firmware.

OTA regression coverage must include:

- correct HKDF salt/info, HMAC canonicalization, constant-time comparison,
  wrong secret/device/context, modified fields, expiry/not-before, and
  cross-device replay;
- wrong project/target/protocol/version, blocked versus explicitly allowed
  downgrade, partition fit, connection reset, timeout, truncation, extra bytes,
  SHA-256 mismatch, write/finalize failure, successful pending boot, validation,
  and automatic rollback;
- configuration, Wi-Fi, enrollment, public CA, microSD history, and sequence
  preservation across application-only bootstrap and inactive-slot OTA; and
- bounded status rendering, ten-second polling, hidden-tab pause, no automatic
  diagnostic/history fan-out, and truthful OTA/memory/freshness labels.

Memory tests preserve the production admission boundaries: 64 KiB total and
32 KiB largest contiguous internal heap for TLS/OTA. A normal TLS transient is
scoped to its active operation and followed by a three-second recovery grace.
Outside a scoped operation, total memory below 56 KiB for three consecutive
idle samples is genuine low total; below 32 KiB, heap-integrity failure, or a
critical allocation failure is emergency. Fragmentation and pressure warnings
remain distinct, and only `low_total_memory` sets legacy `health.low_memory`.
The deterministic one-hour and 24-hour accelerated soaks cover heartbeat,
status polling, meter/storage cadence, server outage/recovery, diagnostics,
fragmentation, low-total recovery, OTA success, and rollback without buffer
growth, state latch, request fan-out, or false Offline transitions. See
[Memory and fragmentation](MEMORY_AND_FRAGMENTATION.md) for exact evidence and
the pinned mbedTLS result.

The browser suite covers the minimal local UI; the server repository covers the
central one-file upload, capability/bootstrap, permissions, canary rollout,
refresh persistence, downgrade confirmation, and deployment states in Chromium,
Firefox, and WebKit.

The simulator and native mocks are deterministic validation infrastructure, not
physical hardware proof. Physical validation remains required on the exact
N16R8 board with a real trusted CA/hostname, low-voltage PZEM test arrangement,
microSD card, and enrolled server. A physical OTA pass requires a real inactive-
slot install, target-version heartbeat/reading confirmation, preservation
checks, induced rollback, and sustained memory/network observation. When no
ESP32 is connected, report physical flash, rollback, preservation, and soak as
pending rather than passed.

The safe target-device serial matrix, including watchdog/backtrace capture, is
in [Serial diagnostics](SERIAL_DIAGNOSTICS.md). Software fault tests must use
the simulated meter and server; do not connect live mains equipment.

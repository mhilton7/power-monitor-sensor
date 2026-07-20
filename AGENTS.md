# Power Monitor Sensor Agent contributor guide

The protocol identifier is `pm-protocol/1.0.0`. Do not remove, rename, or change the meaning of a shared API field without a protocol version bump and matching updates to both OpenAPI documents, JSON schemas, fixtures, simulator, and contract tests. Additive optional v1 fields are allowed.

## Build and test

Use the pinned tools and dependencies in `platformio.ini` and `web/package-lock.json`.

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s test -p "test_*.py" -v
cd web && npm ci && npm test -- --run && npm run build
python -m platformio run -e native-tests
python -m platformio run -e esp32-s3-release
python -m platformio run -e esp32-s3-debug
python -m platformio run -e esp32-s3-simulated-meter
```

Run `python tools/check_repo.py` before release. It validates OpenAPI, JSON examples, generated UI assets, partition sizing, secret patterns, and production-source policy. Run `python tools/generate_release.py` only after the release environment builds.

## Engineering constraints

- Never add switching, relay, contactor, breaker-control, or remote-disconnect behavior.
- Never use LittleFS or NVS as a silent historical-reading fallback. microSD owns history.
- Never add a production path that fabricates meter readings. `SimulatedMeter` is enabled only by the dedicated build flag.
- Keep all GPIO assignments in `include/board_pins.h`.
- Preserve UTC timestamps, monotonic 64-bit sequences, per-record CRC, bounded queues, redacted logs, validated TLS, HMAC direction separation, nonce replay protection, and signed OTA verification.
- Never commit credentials, signing private keys, enrollment tokens, captured device diagnostics, or Wi-Fi configuration.
- Software tests must use the simulator. Do not connect the test environment to live mains equipment.

Format C++ with `clang-format -i include/**/*.h src/**/*.cpp`; format TypeScript with `npm run format`; format Python with `ruff format` when available.

# Power Monitor Sensor Agent

Serial troubleshooting, commands, stable error codes, and backtrace capture
are documented in [docs/SERIAL_DIAGNOSTICS.md](docs/SERIAL_DIAGNOSTICS.md).

Production firmware for an ESP32-S3 N16R8, one PZEM-004T V4.x meter, and a mandatory SPI microSD card. One runtime-provisioned image samples the meter, writes authoritative interval history to microSD, exposes the authenticated `pm-protocol/1.0.0` device API, enrolls with a central server, sends heartbeats, backfills by outbound push synchronization, and accepts only signed OTA releases. The v1 field still recognizes the reserved `pull` and `hybrid` names, but this build rejects them because the local device API is not a mutually authenticated HTTPS listener.

This is a monitoring-only product. It contains no load control and performs no electricity-rate or bill calculation. One CT measures only the conductor passing through it; it is not normally a complete North American split-phase whole-home monitor.

> **DANGER - mains voltage can kill or cause fire.** Firmware does not make mains work safe. Installation must be performed de-energized by a qualified person using an appropriate enclosure, barriers, strain relief, finger-safe terminals, and protection. Start with [docs/SAFETY.md](docs/SAFETY.md) and [docs/WIRING.md](docs/WIRING.md).

## Quick start without mains hardware

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s test -p "test_*.py" -v
cd web && npm ci && npm test -- --run && npm run build
python -m platformio run -e native-tests -e esp32-s3-simulated-meter
python -m simulator.server --port 8088
```

See [docs/BUILD_AND_FLASH.md](docs/BUILD_AND_FLASH.md), [docs/FIRST_RUN.md](docs/FIRST_RUN.md), [docs/SERVER_CA_CERTIFICATE.md](docs/SERVER_CA_CERTIFICATE.md), [docs/SEQUENCE_RECONCILIATION.md](docs/SEQUENCE_RECONCILIATION.md), and [docs/API.md](docs/API.md). The source is firmware `1.0.10` and protocol `pm-protocol/1.0.0`. Release artifacts are generated into `release/1.0.10/`; private OTA keys must remain outside this repository.

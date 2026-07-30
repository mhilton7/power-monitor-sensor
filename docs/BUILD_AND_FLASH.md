# Build and flash

## Prerequisites

Install Git, Python 3.11+, Node.js 20+ with npm, and PlatformIO Core 6.1.19 (`python -m pip install platformio==6.1.19`). VS Code plus its PlatformIO extension is optional. Install the USB-JTAG/serial or USB CDC driver required by the exact board. On Linux grant serial-device access; on macOS use `/dev/cu.*`; on Windows use the Device Manager `COM` name.

```sh
python -m pip install -r requirements-dev.txt
cd web
npm ci
cd ..
```

## Reproducible build and tests

Windows PowerShell:

```powershell
.\tools\build.ps1 -Python python
```

macOS/Linux:

```sh
PYTHON=python3 sh tools/build.sh
```

These run Python native/contract/simulator tests, the native C++ executable, frontend tests/build, gzip embedding, repository checks, and all PlatformIO environments. Individual builds:

```sh
python -m platformio run -e native-tests
python -m platformio run -e esp32-s3-release
python -m platformio run -e esp32-s3-debug
python -m platformio run -e esp32-s3-simulated-meter
```

The simulated-meter binary is never a release. A compile guard forbids `PM_RELEASE_BUILD` plus `PM_SIMULATED_METER`.

## Flash and monitor

Keep mains hardware disconnected. Connect the ESP32-S3 over USB and identify its port.

```powershell
.\tools\flash.ps1 -Port COM7
.\tools\serial_monitor.ps1 -Port COM7
```

```sh
sh tools/flash.sh /dev/cu.usbmodem1101
sh tools/serial_monitor.sh /dev/cu.usbmodem1101
```

If upload cannot connect, hold BOOT, tap RESET/EN, then release BOOT after the ROM download port appears and retry. This only controls the low-voltage board; it is not authorization to open an energized enclosure.

## Release verification

Run `python tools/generate_release.py --skip-build --version 1.0.1 --channel stable --signing-key-id KEY-ID`. It fails if the build provenance is missing/stale, if any required image changed, or if the packaged `boot_app0.bin` selector is not assigned to `0x11000`. Verify every `SHA256SUMS` line plus `flash-layout.json`, `build-provenance.json`, and `dependencies.json` before signing:

```sh
python tools/sign_firmware.py release/1.0.1/manifest.unsigned.json --private-key /secure/offline/ota-ed25519.pem --output release/1.0.1/manifest.json
```

Never commit the private key. The server and firmware reject unsigned manifests.

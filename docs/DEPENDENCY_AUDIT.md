# Dependency and license audit

Checked 2026-07-19 against official project registries/repositories. Versions are pinned in `platformio.ini`, `web/package-lock.json`, or `requirements-dev.txt`. `npm audit` reported zero known vulnerabilities after Vite 7.3.6.

| Component | Version | License | Purpose |
|---|---:|---|---|
| PlatformIO Core | 6.1.19 | Apache-2.0 | build/test/flash |
| Espressif32 platform | 6.13.0 | Apache-2.0 scripts | ESP32 packages |
| Arduino-ESP32 | 2.0.17 | LGPL-2.1 | firmware framework |
| ArduinoJson | 7.4.3 | MIT | bounded JSON |
| AsyncTCP | 3.4.10 | LGPL-3.0 | async TCP |
| ESPAsyncWebServer | 3.11.2 | LGPL-3.0 | local HTTP/API |
| TypeScript | 5.9.3 | Apache-2.0 | frontend types |
| Vite | 7.3.6 | MIT | frontend build |
| Vitest | 4.1.1 | MIT | browser tests |
| jsdom | 29.1.1 | MIT | DOM environment |
| Prettier | 3.8.1 | MIT | formatting |
| PyYAML | 6.0.3 | MIT | OpenAPI gate |
| jsonschema | 4.26.0 | MIT | Draft 2020-12 tests |
| cryptography | 49.0.0 | Apache-2.0/BSD | host signing tests/tool |

Primary references: [PlatformIO Espressif32 releases](https://github.com/platformio/platform-espressif32/releases), [Arduino-ESP32](https://github.com/espressif/arduino-esp32), [ArduinoJson releases](https://github.com/bblanchon/ArduinoJson/releases), [AsyncTCP releases](https://github.com/ESP32Async/AsyncTCP/releases), [ESPAsyncWebServer releases](https://github.com/ESP32Async/ESPAsyncWebServer/releases), [Vite releases](https://github.com/vitejs/vite/releases), and package lock metadata.

Release `dependencies.json` captures embedded dependencies. Preserve the project license and third-party notices required by each dependency. Review advisories before every production release.

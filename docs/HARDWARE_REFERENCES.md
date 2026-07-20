# Hardware references

Checked 2026-07-19 before implementation.

- [ESP32-S3-DevKitC-1 guide](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/index.html): headers, power, and recovery controls.
- [ESP32-S3 datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf): GPIO limits, UART/SPI, flash/PSRAM, and maximum ratings.
- [Arduino-ESP32 documentation](https://docs.espressif.com/projects/arduino-esp32/en/latest/): framework APIs.
- [ESP-IDF OTA guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/system/ota.html): pending verification, validation, and rollback.
- [PZEM-004T V3 protocol implementation](https://github.com/mandulaj/PZEM-004T-v30): Modbus register layout/scaling cross-check. Verify connector order and ratings against the purchased V4.x unit.

The target is `esp32-s3-n16r8`: 16 MB quad-I/O flash and 8 MB octal PSRAM. PlatformIO's generic board summary can print N8 defaults; `platformio.ini` overrides flash size, OPI PSRAM memory type, partition table, and `BOARD_HAS_PSRAM`.

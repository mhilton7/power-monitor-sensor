# Wiring

Read [SAFETY.md](SAFETY.md) first. This is the firmware contract for the ESP32-S3 N16R8 target.

| Function | ESP32-S3 pin | Other endpoint | Electrical notes |
|---|---:|---|---|
| PZEM UART TX | GPIO17 / UART1 TX | Translator LV input; translator HV output to PZEM RX | Crossed UART, 9600 8N1 |
| PZEM UART RX | GPIO18 / UART1 RX | Translator LV output; translator HV input from PZEM TX | Never apply 5 V directly to ESP32 GPIO |
| microSD CS | GPIO10 | Card CS | Dedicated SPI chip select |
| microSD MOSI | GPIO11 | Card DI/MOSI | 3.3 V logic |
| microSD SCK | GPIO12 | Card CLK | Starts at 4 MHz; configurable up to 20 MHz |
| microSD MISO | GPIO13 | Card DO/MISO | 3.3 V logic |
| Low-voltage ground | GND | ESP32, translator, SD, PZEM UART ground | Common only on the low-voltage interface described by the manufacturer |
| 3.3 V | 3V3 regulator | Translator LV rail and bare 3.3 V SD interface | Check current and decoupling |
| 5 V | Regulated 5 V/USB rail | Translator HV rail and interfaces explicitly rated for 5 V | Do not back-feed USB/regulators |

Signal crossing is mandatory: ESP TX goes to PZEM RX, and PZEM TX goes to ESP RX, through a correctly directed translator that supports UART. Verify the actual connector silk-screen and PZEM vendor documentation; revisions and third-party boards can change label order. Do not infer pin order from photographs.

Use a high-endurance FAT32 card on a proper 3.3 V interface. Some SD modules contain 5 V regulators or slow resistor dividers and may be unreliable at ESP32 logic levels. Keep SPI wires short, provide local decoupling, and start at 4 MHz.

The CT surrounds one hot conductor only. Its rating must match `ct_rating_a` and the PZEM model. The PZEM voltage input must reference the same circuit/phase. A single CT does not normally represent both legs of a North American split-phase service.

Maintain a physical barrier and required spacing between mains and the low-voltage assembly. Place the SD slot and USB connector so they can be accessed without exposing mains. Protective earth is not automatically tied to ESP32 DC ground.

Pins were checked against Espressif's official [ESP32-S3-DevKitC-1 guide](https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/index.html). No supplied schematic image was present, so no image is treated as authoritative.

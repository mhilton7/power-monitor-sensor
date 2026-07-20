# Implementation plan

1. Freeze `pm-protocol/1.0.0` schemas, OpenAPI descriptions, canonical HMAC vectors, and the offline central-server simulator.
2. Build host-testable PZEM framing/parsing, measurement validation, energy normalization, interval aggregation, record CRC, sequence recovery, retention, configuration migration, time-trust, and OTA-manifest logic.
3. Integrate ESP32 services: dedicated UART meter, serialized SPI microSD storage, NVS configuration/identity, Wi-Fi/NTP/mDNS, provisioning and enrollment, signed heartbeat and synchronization, authenticated asynchronous local API, diagnostics, and signed dual-slot OTA.
4. Build the bundled accessible local frontend, gzip it into committed firmware assets, and validate its critical interactions.
5. Complete safety, wiring, provisioning, API, storage, recovery, security, OTA, build, maintenance, and dependency documentation.
6. Run native, contract, simulator, frontend, policy, and every PlatformIO build gate; repair failures; generate binaries, manifests, hashes, dependency/license inventory, release notes, and size-margin evidence.

All automated work uses `SimulatedMeter` and temporary filesystems. No live mains equipment is connected during software testing.


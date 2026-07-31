# Firmware 1.0.5 optimization and verification record

## Root cause and implementation

Firmware 1.0.4 had two independent synchronization defects. First, it treated
the lifetime minimum FreeRTOS stack watermark as current free stack and used a
12 KiB threshold as a recurring TLS admission gate. Once the 24 KiB task had
ever reached 11,844 bytes remaining (48 percent), the irreversible lifetime
watermark permanently rejected every later request. Second, the transport
manually connected `WiFiClientSecure` and then handed that already-connected
client to `HTTPClient`, whose send path attempted another connection. The
captured device consequently reported `Connection already in progress` even
with valid Wi-Fi, time, CA, hostname, PZEM, storage, and enrollment.

Firmware 1.0.5 removes stack watermark admission entirely while retaining the
25-percent health warning. `HTTPClient` now owns exactly one connect through a
resolved-address TLS client that preserves hostname verification and SNI.
Temporary heap/lease pressure is `LOCAL_RESOURCE_DEFERRED` with a 1.5-second
retry; it is not an external heartbeat failure. Hot loops use narrow locked
configuration snapshots so they do not repeatedly copy CA and OTA PEM data.
Heavy local APIs defer with typed HTTP 503 and `Retry-After: 2` during TLS,
storage recovery, backlog, or low internal memory.

## Minimal local WebUI

The production navigation contains exactly Status, Setup, and Diagnostics.
Status polls only `GET /api/v1/ui/status`, at most once every five seconds,
never overlaps requests, pauses while hidden, and updates existing text nodes.
Setup fetches `GET /api/v1/config` only when opened. Diagnostics fetches
`GET /api/v1/ui/diagnostics` only when opened or explicitly refreshed. No
status poll loads configuration, metrics, OTA, events, history, storage pages,
or a diagnostic bundle.

| Asset | Previous gzip bytes | 1.0.5 gzip bytes |
|---|---:|---:|
| `index.html` | 348 | 347 |
| `app.js` | 12,875 | 6,919 |
| `style.css` | 1,980 | 1,607 |
| Total | 15,203 | 8,873 |

The embedded total is 41.6 percent smaller and the generator enforces a 40 KiB
total, 28 KiB JavaScript, 8 KiB CSS, and 4 KiB HTML gzip budget.

## Task allocation and baseline evidence

| Task | Core | Priority | Allocation | Watchdog | Responsibility |
|---|---:|---:|---:|---|---|
| DiagLogTask | 0 | runtime | 4 KiB | no | bounded serial log queue |
| MeterTask | 1 | runtime | 6 KiB | yes | PZEM acquisition/validation |
| AggregationTask | 1 | 3 | 8 KiB | yes | immutable interval aggregation |
| StorageTask | 1 | 2 | 8 KiB | no | microSD writes/pages/recovery |
| NetworkTask | 0 | runtime | 8 KiB | yes | Wi-Fi, DHCP, mDNS, SNTP |
| ServerSyncTask | 0 | runtime | 24 KiB | no | sole central TLS/HTTP owner |
| HealthTask | 0 | runtime | 6 KiB | no | health, stack, retention checks |
| OtaMaintenanceTask | 0 | runtime | 12 KiB | no | signed OTA and maintenance |
| SerialCommandTask | 0 | runtime | 24 KiB | no | bounded local recovery/config input |
| PasswordJobTask | 1 | runtime | 16 KiB on demand | no | password/config jobs |

The supplied 1.0.4 diagnostic at 1,295 seconds recorded ServerSyncTask 24,576
allocated / 13,268 high-water bytes (53 percent), 96,464 free internal bytes,
38,900-byte largest internal block, 89,088 free total heap, and 21,920-byte
minimum total heap. PZEM was 1,292/1,292, storage was writable, sequence and
acknowledgement were both 41, and backlog was zero. This is baseline evidence,
not a 1.0.5 physical pass.

## Automated verification

- Python contract/native/simulator suite: 30 passed.
- Native C++ policy build/tests: passed.
- Web component/request tests: 11 passed.
- Web Prettier check: passed.
- TypeScript check and Vite production build: passed through `npm run build`.
- Repository JSON/OpenAPI/partition/UI/secret policy check: passed.
- ESP32-S3 release, debug, and simulated-meter builds: passed on the final
  1.0.5 source fingerprint
  `c27e9b190f439d8c5a6c2b3868dee43d6587de6f383e1947da03af6e6ae80ac2`.
- Release image: 67,960 bytes static RAM (20.7 percent) and 1,526,253 bytes
  flash (24.3 percent of the OTA slot).
- Packaged `firmware.bin` / `ota.bin` SHA-256:
  `f41053c7e0b01a2309c095a68a4d3f13f5088c7d80d615f4a7f24c14c208cc48`.
- The release directory contains an unsigned manifest input. OTA remains
  fail-closed until that exact manifest is signed with the offline release
  key; the private key is not present in or copied into this repository.

## Physical acceptance status

Firmware 1.0.5 was flashed over COM5 through the normal application layout on
2026-07-31 without erasing NVS, credentials, enrollment, or microSD data. The
post-flash serial report confirmed `firmware=1.0.5`,
`protocol=pm-protocol/1.0.0`, `enrolled=true`, Wi-Fi connected, trusted time,
DNS resolution to `192.168.0.175`, validated TLS, and two consecutive accepted
HTTP 200 heartbeats. No overlapping-connection error occurred. PZEM timeouts
were expected because the meter was intentionally unplugged during USB
flashing.

The same packaged image was flashed to the second enrolled sensor on COM6
using the Arduino target's required DIO flash mode. Its post-flash status also
confirmed firmware 1.0.5, preserved enrollment, connected Wi-Fi, trusted time,
reachable server, validated TLS, and an accepted HTTP 200 heartbeat with
acknowledgement sequence 1,821. Its meter was likewise disconnected during
USB verification.

The required 100/200-heartbeat, outage, diagnostics, 1,300-reading, PZEM, and
two-client physical matrix is still pending and cannot truthfully be marked
passed until the sensor is returned to its installed meter connection. Record
the final task table and heap trend after that hardware run.

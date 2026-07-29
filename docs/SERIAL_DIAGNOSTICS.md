# Serial diagnostics

The Power Monitor Sensor Agent exposes a structured, redacted diagnostic
console on the ESP32-S3 USB serial port at **115200 baud, 8 data bits, no
parity, 1 stop bit**. The console is intended for software and network
diagnosis. Do not connect test firmware to energized mains equipment; use the
simulated-meter build for software validation.

## Opening the monitor

From the repository root:

```powershell
python -m platformio device monitor -e esp32-s3-release
```

If PlatformIO does not select the intended port:

```powershell
python -m platformio device monitor -e esp32-s3-release --port COM4
```

PuTTY can also open the board's COM port using a Serial connection, speed
`115200`, 8-N-1, and no flow control. Close PlatformIO, PuTTY, and other serial
programs before flashing because only one program can own the port.

`platformio.ini` enables the supported `time` and
`esp32_exception_decoder` monitor filters. The exception decoder must use the
ELF produced by the exact build that was flashed.

## Log format

Every centralized record has four fixed fields followed by safe key/value
details:

```text
[000001284][INFO ][WIFI    ][CONNECT_ATTEMPT] attempt=1 ssid=Ho***Fi status=6
```

The fields are:

1. Milliseconds since boot.
2. Level: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, or `FATAL`.
3. Subsystem.
4. Stable event name.

Production builds default to `INFO`. Debug and simulated-meter builds default
to `DEBUG`. Expensive raw PZEM frame statements are compiled out of production
builds. The local **Settings** page or the `loglevel` serial command changes
and persists the runtime threshold without clearing any other configuration.

The logger uses a fixed 32-message FreeRTOS queue and a dedicated low-priority
writer task. Producers never wait for serial output. If the queue is full,
records are dropped and the count appears in `HEALTH/PERIODIC_SUMMARY`.
Warnings and errors are copied into a bounded 32-record redacted ring.

## Subsystems

The implementation uses these subsystem names:

```text
BOOT SYSTEM CONFIG AUTH PASSWORD SECURITY WIFI NETWORK DHCP DNS TIME TLS
HTTP SERVER ENROLL SYNC HEARTBEAT WEB MDNS PZEM SD STORAGE QUEUE TASK
WATCHDOG MEMORY OTA MAINTENANCE HEALTH COMMAND LOGGER
```

Related stable events include:

- Boot: `BOOT_START`, `RESET_CAUSE`, `WAKEUP_CAUSE`, `HARDWARE`,
  `REBOOT_LOOP_DETECTED`, `STARTUP_COMPLETE`.
- Configuration: `NVS_OPEN_BEGIN`, `NVS_OPEN_COMPLETE`, `CONFIG_LOADED`,
  `CATEGORY_SUMMARY`, `STAGE_COMPLETE`, `COMMIT_COMPLETE`,
  `REMOTE_UPDATE_RECEIVED`, `REMOTE_CONNECTIVITY_ROLLBACK`.
- Wi-Fi: `WIFI_INIT_BEGIN`, `STATION_STARTED`, `CONNECT_ATTEMPT`,
  `ASSOCIATED`, `IP_ACQUIRED`, `DISCONNECTED`, `RECONNECT_SCHEDULED`,
  `RECONNECT_SUCCESS`, `SCAN_STARTED`, `SCAN_COMPLETE`,
  `SETUP_AP_DRIVER_STARTED`, `SETUP_AP_DRIVER_STOPPED`,
  `SETUP_CLIENT_JOINED`, `SETUP_CLIENT_LEFT`, `STATE_TRANSITION`.
- Network services: `LOOKUP_BEGIN`, `LOOKUP_COMPLETE`, `LOOKUP_FAILED`,
  `NTP_CONFIGURE`, `TIME_TRUSTED`, `TIME_TRUST_LOST`, `MDNS_START_BEGIN`,
  `MDNS_READY`, `MDNS_START_FAILED`.
- Server: `REQUEST_BEGIN`, `HANDSHAKE_BEGIN`, `HANDSHAKE_VERIFIED`,
  `REQUEST_COMPLETE`, `REQUEST_FAILED`, `RETRY_SCHEDULED`,
  `OFFLINE_SUMMARY`, `SYNC_RESUMED`.
- Enrollment and synchronization: `ENROLLMENT_BEGIN`,
  `ENROLLMENT_REJECTED`, `CREDENTIAL_SAVE_FAILED`,
  `ENROLLMENT_COMPLETE`, `HEARTBEAT_BEGIN`, `HEARTBEAT_COMPLETE`,
  `READ_BATCH_BEGIN`, `READ_BATCH_COMPLETE`, `EVENT_BATCH_BEGIN`,
  `EVENT_BATCH_COMPLETE`.
- Local web/authentication: `SERVER_STARTED`, `ROUTE_REGISTERED`,
  `LOCAL_RESPONSE`, `LOCAL_PROBLEM`, `LOCAL_SESSION_ACCEPTED`,
  `SERVER_SIGNATURE_ACCEPTED`, `SERVER_SIGNATURE_REJECTED`,
  `SESSION_CREATED`.
- Password work: `WORKER_READY`, `JOB_QUEUED`, `JOB_STARTED`,
  `JOB_COMPLETE`, `JOB_SLOW`, `JOB_QUEUE_FULL`.
- Storage/PZEM: `MOUNT_BEGIN`, `MOUNT_COMPLETE`, `SELF_TEST_COMPLETE`,
  `RECOVERY_SCAN_BEGIN`, `RECOVERY_SCAN_COMPLETE`, `WRITE_SUMMARY`,
  `UART_INIT_BEGIN`, `UART_READY`, `READ_FAILED`, `METER_RECOVERED`,
  `PERIODIC_SUMMARY`.
- Runtime/OTA: `TASK_STARTED`, `TASK_REPORT`, `LOW_STACK`,
  `BOOT_MEMORY`, `MEMORY_REPORT`, `LOW_HEAP`, `UPDATE_REQUESTED`,
  `MANIFEST_PARSED`, `SIGNATURE_VERIFIED`, `DOWNLOAD_PROGRESS`,
  `IMAGE_VERIFIED`, `UPDATE_COMPLETE`.

Event names are intended to remain stable within firmware 1.x. Additive events
do not alter `pm-protocol/1.0.0`.

## Serial commands

Commands are case-insensitive and newline terminated. Input is processed by a
dedicated nonblocking task and is limited to 95 printable bytes.

```text
help
status
wifi
network
time
tls
server
tasks
memory
sd
pzem
errors
loglevel trace
loglevel debug
loglevel info
loglevel warn
loglevel error
loglevel fatal
reconnect
```

`wifi` also starts one asynchronous diagnostic scan. It reports a masked
configured SSID, match count, strongest RSSI/channel, security code, and
duplicate BSSID count. It does not continuously scan.

`errors` prints the bounded recent warning/error ring. The same data is
available to an authenticated local client at
`GET /api/v1/diagnostics/recent-errors` and is included in the redacted
diagnostic bundle.

`reconnect` restarts the station connection state machine. It does **not**
erase Wi-Fi credentials or perform a network reset.

Restore the production threshold after temporary diagnosis:

```text
loglevel info
```

## Redaction and security

All formatted details pass through one redaction policy before being queued.
Assignment keys containing any of these fragments are replaced with
`[REDACTED]`:

```text
password passwd secret token authorization cookie signature private_key
api_key session credential csrf
```

SSIDs, device identifiers, and MAC addresses are masked by dedicated helpers.
Request/response bodies, authorization headers, cookies, CSRF values, session
IDs, enrollment material, HMAC keys, password hashes, salts, and plaintext
passwords are never logged. TRACE does not relax this policy.

Outbound TLS requires a configured CA PEM and normal hostname validation.
The ESP32 Arduino TLS client cannot implement fingerprint-only validation
without first accepting an unverified connection, so legacy fingerprint-only
configuration fails closed as `PM-TLS-001`. No firmware path calls
`setInsecure()`.

Password creation and verification run in `PasswordJobTask`, not in
`async_tcp`. The web callback copies the bounded request into a four-entry
queue, returns HTTP 202, and retains no `AsyncWebServerRequest*`. The browser
polls an opaque 32-hex-character job ID. Results expire after 60 seconds. A
logical 15-second budget fails closed, jobs slower than 2 seconds produce a
warning, and queue exhaustion returns HTTP 503. The worker is not registered
with the task watchdog and the watchdog is never disabled.

## Stable error-code catalog

| Code | Subsystem | Meaning | Typical corrective action |
|---|---|---|---|
| `PM-BOOT-001` | BOOT | Repeated abnormal startup resets | Capture the full boot and exact ELF; inspect the prior subsystem/event |
| `PM-CONFIG-001` | CONFIG | NVS could not open | Check flash/partition integrity; do not erase configuration without a backup |
| `PM-CONFIG-004` | CONFIG | Configuration validation rejected staging | Correct the named validation category |
| `PM-WIFI-001` | WIFI | Wi-Fi initialization degraded | Inspect the following driver event and memory state |
| `PM-WIFI-002` | WIFI | Configured AP not found | Verify the masked SSID and enable 2.4 GHz |
| `PM-WIFI-003` | WIFI | Authentication/security handshake failed | Re-enter the password and use WPA2-AES or WPA2/WPA3 transition mode |
| `PM-WIFI-004` | WIFI | Association failed | Check AP compatibility and client limits |
| `PM-WIFI-005` | WIFI | Beacons/timing were lost | Check signal, channel congestion, and AP stability |
| `PM-WIFI-006` | WIFI | Station connection exceeded 60 seconds | Inspect disconnect reason; use the recovery AP |
| `PM-WIFI-007` | WIFI | Recovery AP failed to start | Check heap and Wi-Fi driver state |
| `PM-WIFI-008` | DHCP | Static IPv4 configuration rejected | Correct address, gateway, subnet, and DNS |
| `PM-WIFI-009` | DHCP | DHCP initialization failed | Inspect AP DHCP and ESP32 network state |
| `PM-WIFI-010` | WIFI | Explicit scan failed | Retry after the current connection transition |
| `PM-DNS-001` | DNS | Server hostname lookup failed | Verify DNS address, hostname, and gateway |
| `PM-TIME-001` | TIME | Trusted time was lost | Restore Wi-Fi/DNS and verify NTP availability |
| `PM-TLS-001` | TLS | CA missing or fingerprint-only trust rejected | Install the server CA PEM |
| `PM-TLS-002` | TLS | CA PEM parse failed | Export a complete PEM certificate chain/CA |
| `PM-TLS-003` | TLS | Time is not trusted | Resolve NTP before TLS/signed requests |
| `PM-TLS-004` | TLS | TLS client/handshake setup failed | Check CA, certificate SAN, server port, and TLS compatibility |
| `PM-HTTP-001` | HTTP | Outbound request transport failed | Use its request ID and DNS/TLS category |
| `PM-HTTP-002` | HTTP | Local request body exceeded the limit | Send at most the documented bounded JSON size |
| `PM-SERVER-001` | HEARTBEAT | Heartbeat failed | Inspect HTTP status/category and scheduled retry |
| `PM-SERVER-003` | SERVER | URL/host is invalid or not allowlisted | Correct HTTPS URL or allowlist |
| `PM-ENROLL-001` | ENROLL | Enrollment was rejected/unreachable | Verify token on the server without printing it |
| `PM-ENROLL-002` | ENROLL | Enrollment response/protocol invalid | Validate the shared simulator contract |
| `PM-SYNC-001` | SYNC | Stored batch could not be loaded | Inspect microSD recovery and index state |
| `PM-SYNC-003` | SYNC | Reading batch upload failed | Inspect HTTP category and retry/backlog |
| `PM-AUTH-001` | AUTH | Local credentials rejected | Retry the correct credential after throttling |
| `PM-AUTH-005` | AUTH | Server HMAC rejected | Check time, protocol, nonce, and directional key configuration |
| `PM-PASSWORD-001` | PASSWORD | Worker primitives could not start | Capture boot memory/task report |
| `PM-PASSWORD-002` | PASSWORD | Hash operation exceeded the slow threshold | Capture task/memory reports; operation remains off `async_tcp` |
| `PM-PASSWORD-004` | PASSWORD | Bounded worker queue is full | Wait for the current job and retry |
| `PM-SD-001` | SD | microSD mount failed | Check FAT32 card, power, and board pin wiring; firmware will not format it |
| `PM-SD-002` | SD | Card is not writable | Remount or replace the card; history has no silent NVS fallback |
| `PM-SD-005` | SD | Record append was incomplete | Check media health and power |
| `PM-SD-009` | SD | Journal corruption/repair issue | Preserve the card and inspect recovery output |
| `PM-PZEM-001` | PZEM | PZEM UART initialization/read degraded | With mains isolated, check 9600-8N1 RX/TX wiring and meter power |
| `PM-QUEUE-001` | QUEUE | Sample queue full | Inspect task stack/latency and storage state |
| `PM-QUEUE-003` | QUEUE | Storage queue full | Restore microSD writes; measurements remain isolated from networking |
| `PM-TASK-001` | TASK | Task or primitive creation failed | Inspect boot heap and exact build |
| `PM-TASK-002` | TASK | Stack/history resource low or busy | Run `tasks` and capture high-water marks |
| `PM-MEM-001` | MEMORY | Free heap is below 32 KiB | Capture `memory`, `tasks`, and the operation preceding the warning |
| `PM-OTA-005` | OTA | Manifest signature invalid | Use the enrolled public key and correctly signed manifest |
| `PM-OTA-008` | OTA | Downloaded image hash mismatched | Regenerate/rehost the release artifact |

Unknown Wi-Fi reasons retain their original numeric code as `PM-WIFI-099`.
Unknown transport failures retain the negative HTTPClient code and sanitized
error text.

## Wi-Fi disconnect reasons

The firmware translates common IEEE/ESP driver reasons. Important categories:

| Numeric | Name | Interpretation |
|---:|---|---|
| 2 | `AUTH_EXPIRE` | Authentication expired; AP stability or signal may be involved |
| 4 | `ASSOC_EXPIRE` | Association expired |
| 6 | `NOT_AUTHED` | Station is no longer authenticated |
| 15 | `FOUR_WAY_HANDSHAKE_TIMEOUT` | WPA handshake timed out |
| 18–24 | cipher/AKM/RSN errors | AP security mode is incompatible |
| 200 | `BEACON_TIMEOUT` | AP beacons were lost |
| 201 | `NO_AP_FOUND` | Configured SSID was not found |
| 202 | `AUTH_FAIL` | AP rejected authentication |
| 203 | `ASSOC_FAIL` | AP rejected association |
| 204 | `HANDSHAKE_TIMEOUT` | Security handshake timed out |
| 205 | `CONNECTION_FAIL` | Connection could not complete |
| 206 | `AP_TSF_RESET` | AP reset timing state |
| 207 | `ROAMING` | Station is moving between APs |

Ambiguous reasons are described as possibilities, not definite root causes.

## Capturing failures

### Complete boot

1. Start the monitor before resetting the board.
2. Press RESET once.
3. Capture from the first `ESP-ROM` line through `BOOT/STARTUP_COMPLETE` and
   the first `HEALTH/PERIODIC_SUMMARY`.
4. Run `status`, `tasks`, `memory`, `sd`, `pzem`, and `errors`.
5. Save the log locally and remove any site-specific IP/hostname information
   before sharing it.

### Reconnect failure

1. Run `loglevel debug`.
2. Run `wifi` for one explicit scan, then `reconnect`.
3. Capture `CONNECT_ATTEMPT`, `DISCONNECTED`, `SCAN_COMPLETE`,
   `RECONNECT_SCHEDULED`, and the next 60-second health summary.
4. Restore `loglevel info`.

### TLS failure

1. Confirm `time` reports `trusted=true`.
2. Run `tls` and `server`.
3. Trigger **Test server TLS** in the local interface.
4. Capture the matching `request_id` from `DNS/LOOKUP_BEGIN` through
   `HTTP/REQUEST_COMPLETE` or `HTTP/REQUEST_FAILED`.
5. Do not paste CA private keys; this firmware accepts CA certificates only.

## Representative output

Successful boot:

```text
[000000083][INFO ][BOOT     ][BOOT_START] product=Power Monitor Sensor Agent firmware=1.0.0 protocol=pm-protocol/1.0.0 build=release
[000000121][INFO ][MEMORY   ][BOOT_MEMORY] heap_free=312488 heap_min=312488 psram_free=8382012
[000000301][INFO ][SD       ][MOUNT_BEGIN] bus=FSPI cs_gpio=10 sck_gpio=12 miso_gpio=13 mosi_gpio=11 requested_hz=4000000
[000000512][INFO ][SD       ][MOUNT_COMPLETE] result=success card_type=SDHC filesystem=FAT32
[000000529][INFO ][PZEM     ][UART_READY] uart=1 protocol=modbus-rtu address=248
[000003182][INFO ][WIFI     ][STATION_ONLINE] ip=192.168.1.44 rssi_dbm=-57 channel=6
[000004106][INFO ][TIME     ][TIME_TRUSTED] source=sntp utc_ms=1785304761000
[000004881][INFO ][HTTP     ][REQUEST_COMPLETE] request_id=1 method=POST endpoint=/api/v1/device-heartbeats status=200 category=success
[000005063][INFO ][BOOT     ][STARTUP_COMPLETE] storage=ready meter=ready network=ready http=ready
```

Wi-Fi failure:

```text
[000000629][INFO ][WIFI     ][CONNECT_ATTEMPT] attempt=1 ssid=Ho***Fi status=6 status_name=disconnected connection_timeout_ms=15000
[000003417][ERROR][WIFI     ][DISCONNECTED] error=PM-WIFI-003 reason=AUTH_FAIL numeric=202 explanation=The access point rejected authentication.
[000003428][INFO ][WIFI     ][RECONNECT_SCHEDULED] attempt=2 delay_ms=15000 reason=connection_pending
[000018114][INFO ][WIFI     ][SCAN_COMPLETE] duration_ms=2401 networks=7 configured_ssid_found=true matches=2 strongest_rssi_dbm=-62 channel=11
```

TLS failure:

```text
[000008102][INFO ][TLS      ][HANDSHAKE_BEGIN] request_id=4 host=monitor.local port=8443 ca_validation=true hostname_validation=true
[000008711][ERROR][HTTP     ][REQUEST_FAILED] error=PM-HTTP-001 request_id=4 method=POST endpoint=/api/v1/device-heartbeats transport=connection refused tls_category=TLS_NEGOTIATION_FAILED elapsed_ms=609
```

Password work:

```text
[000041201][INFO ][PASSWORD ][JOB_QUEUED] kind=login queue_depth=1 capacity=4 body=redacted
[000041214][INFO ][PASSWORD ][JOB_STARTED] kind=login queue_wait_ms=13 core=1 priority=1 heap_free=201844
[000043911][INFO ][PASSWORD ][JOB_COMPLETE] kind=login result=failed duration_ms=2697 timeout=false high_water_words=1532
[000043912][WARN ][PASSWORD ][JOB_SLOW] error=PM-PASSWORD-002 kind=login duration_ms=2697 budget_ms=15000
```

## Backtraces and exact ELF matching

Build and keep the exact ELF:

```powershell
python -m platformio run -e esp32-s3-release
Get-FileHash .pio\build\esp32-s3-release\firmware.elf -Algorithm SHA256
```

The serial boot/panic output includes an ELF SHA-256. It must match the ELF
kept with the incident. Decode interactively through the configured monitor:

```powershell
python -m platformio device monitor -e esp32-s3-release --filter time --filter esp32_exception_decoder
```

For a saved address, use the toolchain from PlatformIO with the same ELF:

```powershell
& "$env:USERPROFILE\.platformio\packages\toolchain-xtensa-esp32s3\bin\xtensa-esp32s3-elf-addr2line.exe" -pfiaC -e .pio\build\esp32-s3-release\firmware.elf 0x42000000
```

Never decode against a newly rebuilt ELF, even if the source version string is
unchanged. Build metadata or link layout can change addresses.

## Target-device verification matrix

Use simulated server faults and safe, de-energized hardware. Never use live
mains to create a software failure.

1. Valid Wi-Fi: observe association, DHCP, NTP, mDNS, and online transition.
2. No Wi-Fi credentials: observe unconfigured/provisioning and recovery AP.
3. Wrong password: observe reason 202/handshake category and backoff.
4. SSID unavailable: observe reason 201 and a scan with no match.
5. Weak signal: observe RSSI and recovery without stopping PZEM/storage tasks.
6. DHCP failure: observe waiting-for-IP and connection timeout.
7. DNS failure: use the simulator hostname fault and observe `PM-DNS-001`.
8. Incorrect server hostname: use a SAN mismatch and observe TLS failure.
9. Missing CA: observe `PM-TLS-001`.
10. Invalid CA PEM: observe `PM-TLS-002`.
11. Hostname mismatch: observe the TLS request ID and fail-closed result.
12. Server offline: stop the simulator; observe rate-limited offline summaries.
13. Rejected enrollment token: use the simulator rejection scenario.
14. HTTP 401: select the simulator 401 scenario and inspect categorization.
15. HTTP 403: select the simulator 403 scenario.
16. HTTP 409: send a conflicting sequence fixture.
17. HTTP 429: enable simulator rate limiting and inspect retry scheduling.
18. HTTP 503: enable simulator outage.
19. Wi-Fi disconnect/recovery: disable and restore the test AP.
20. microSD missing: boot without a card and observe `PM-SD-001`; no format.
21. PZEM disconnected: use de-energized UART/simulated build and observe
    timeouts without task loss.
22. Low memory: use a diagnostic-only allocation harness; verify
    `MEMORY/LOW_HEAP`, then remove the harness.
23. Password creation: submit setup and observe the background job.
24. Password verification: submit an incorrect credential and verify
    throttling without a watchdog reset.
25. Former watchdog reproduction: submit repeated bounded password jobs while
    refreshing `/api/v1/live`; verify `async_tcp` remains responsive, PZEM and
    storage progress continue, and no task watchdog event occurs.

## Known limitations

- Arduino `HTTPClient` does not expose independent TCP, TLS, and response phase
  timings. DNS is timed separately; the remaining phases are reported as a
  bounded combined duration.
- The Arduino TLS wrapper does not expose the negotiated TLS version/cipher
  suite consistently. CA parsing, trusted time, hostname validation intent,
  request duration, and categorized transport errors remain visible.
- Wi-Fi driver events do not expose every internal authentication phase.
  Association, IP acquisition, disconnect reason, state transition, and retry
  events are reported without overclaiming a cause.
- Runtime TRACE can only reveal TRACE statements compiled into the selected
  environment. Production intentionally compiles out raw PZEM frames.

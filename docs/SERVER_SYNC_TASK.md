# Server synchronization task

`ServerSyncTask` is the only owner of active central-server DNS, TLS, HTTP,
response-stream, heartbeat, reading-upload, event-upload, remote-configuration,
and firmware-manifest operations. It runs on core 0 at priority 2. AsyncTCP,
the WebUI, Wi-Fi callbacks, the meter task, and the storage task never execute
central-server transport work.

## Call path and ownership

```text
Application::syncTask
  -> ServerSync::tick
     -> heartbeat | pushReadings | pushEvents | pullConfiguration |
        reportConfiguration | checkFirmware
        -> request
           -> SingleFlightGate::tryBegin (single-flight admission)
           -> cached endpoint or bounded DNS/mDNS resolution
           -> WiFiClientSecure (CA, SNI, hostname verification)
           -> HTTPClient (bounded request and response)
           -> transaction cleanup guard
        -> bounded JSON response validation
```

The application task is the sole caller of `tick()`. Timer and WebUI actions
only set a bounded pending flag; they never call the transport path. Storage
pages are loaded asynchronously by `StorageTask` through the storage
coordinator before the transaction, and their raw records are released before
TLS begins. `ServerSyncTask` never enumerates FAT directories directly.

## Why the task is bounded

The original failure was reproduced on an ESP32-S3 N16R8. A heartbeat
completed successfully, after which the same task loaded 114 durable readings
and retained the raw records, the ArduinoJson tree, and a 67,117-byte serialized
body at the same time. Internal free heap fell from about 128 KiB to 9,296
bytes, with a 3,120-byte observed minimum. The next mbedTLS allocation failed
with `SSL - Memory allocation failed`; DNS, AsyncTCP, ping, and the WebUI then
stopped making progress even though the Wi-Fi station still reported connected.
The meter, storage, and health tasks continued, proving this was network-plane
starvation caused by transient internal-memory exhaustion rather than a Wi-Fi
credential failure.

The automatic heartbeat completed with HTTP 200. The following backlog
operation prepared the 114-record, 67,117-byte body and its TLS allocation
failed. Once those buffers unwound, an event batch, configuration fetch, and
firmware-manifest fetch happened to complete; the manifest HTTP 200 was the
last successful server stage. The next oversized backlog retry then timed out
in DNS, and all later DNS, ping, and WebUI requests lost forward progress. No
cyclic mutex wait or credential rejection preceded the failure.

The repair addresses ownership and peak live memory:

- Reading pages are limited to 8 records and 8 KiB of stored payload. This
  leaves enough contiguous internal heap for a fresh validated TLS handshake
  after the ESP32-S3 heap has reached its normal post-handshake layout.
- Event pages are limited to 24 records and 16 KiB of stored payload.
- The ArduinoJson tree is destroyed before TLS starts.
- The page's raw string vector is released before TLS starts.
- HTTP response `Content-Length` is required. Heartbeat and event responses
  are capped at 8 KiB, reading acknowledgements at 12 KiB, enrollment at
  16 KiB, and all other responses at 24 KiB. Request bodies are bounded per
  endpoint before TLS begins.
- Response bytes are read through a bounded stream loop, not `getString()`.
- TLS admission requires at least 64 KiB of free internal heap and a largest
  contiguous internal block of at least 32 KiB. The total floor reflects the
  bounded 41 KiB historical TLS working set and an independent post-response
  reserve; the contiguous guard remains unchanged. Historical live-PZEM traces
  informed these guards but do not validate the current binary.
- Local JSON and embedded-asset responses send `Connection: close`. This
  bounds AsyncTCP connection lifetime under concurrent WebUI/health polling
  instead of weakening the TLS admission reserve when clients retain idle
  HTTP/1.1 connections.
- One `tick()` performs at most one server operation, leaving an idle/yield
  boundary between heartbeat, backlog, event, configuration, and manifest work.
- In-progress storage jobs do not expire while `StorageTask` is still scanning.
  Only completed, unconsumed results expire after 60 seconds. This prevents a
  long scan from losing its result handle and being queued repeatedly.
- Durable measurement backlog has priority over diagnostic-event uploads.
  Events remain on microSD and are uploaded only after the server has advanced
  the reading acknowledgement cursor. This keeps low-priority evidence scans
  from competing with heartbeat TLS or primary measurements.
- A heartbeat response with `immediate_sync_requested=true` releases the
  reading retry deadline at most once for each distinct server
  acknowledgement while that acknowledgement is behind the newest stored
  sequence. A stalled acknowledgement therefore honors the operation backoff
  instead of retrying a failed batch after every heartbeat. When the server
  cursor advances, one new immediate release permits prompt catch-up without
  hiding persistent local or protocol faults.
- Reading-page coverage includes both retained-but-unsyncable records and
  sequence holes that no longer exist on the card. The signed unavailable
  ranges plus the selected readings form contiguous coverage from the server
  acknowledgement through the end of the page, so a locally missing interval
  cannot strand the server cursor forever. No more than the protocol's
  500 unavailable sequences are declared in one request.
- A durable reading backlog is a strict secondary-work barrier. While a
  microSD page is queued or the reading retry deadline is pending, the task
  does not fall through into configuration, firmware, or event HTTPS work.
  This prevents mbedTLS from running concurrently with the page scan.
- Configuration and firmware policy checks run before diagnostic event
  uploads. While an event page is being prepared, its 250 ms poll deadline
  remains authoritative; the 30-second idle interval begins only after the
  page is consumed. This prevents a completed page from expiring and avoids
  repeatedly rescanning the same event files.
- TLS and microSD history scans share a high-memory-operation gate. Server
  synchronization waits up to five seconds for an already-running bounded
  storage scan so a harmless memory-owner race does not turn a due heartbeat
  into a false server outage.
  Authenticated local history remains available through bounded retry, but it
  cannot overlap an active TLS working set. Primary server-sync history is
  queued ahead of local browser history, and local history is deferred while
  the first heartbeat or a durable reading backlog is pending. Local result
  pages are limited to 8 KiB each and the TLS preflight requires 80 KiB free
  internal RAM plus a 36 KiB contiguous block. This admits the measured
  39,924-byte layout seen after a complete 1,300-record catch-up while the
  local WebUI was active, with approximately 3 KiB of allocator variation,
  while retaining more protection than the former unsafe 32 KiB reserve.
  A server-owned storage page keeps local browser history deferred until the
  page has been consumed and its HTTPS transaction finishes. This closes the
  page-publication race where a second local scan could take the memory gate
  between server page consumption and event upload.
- A successful DNS result is cached for the unchanged host and port. TLS still
  receives the configured hostname for SNI and SAN validation. Two consecutive
  cached-address transport failures invalidate the cache and force a fresh
  lookup, so a server address change remains recoverable.
- `HTTPClient` owns the single TCP/TLS connect call. A resolved-address client
  routes that call to the cached address while retaining the configured host
  for SNI and certificate verification. The former manual secure-client
  connect followed by `HTTPClient::sendRequest()` attempted a second connect
  and produced the observed `Connection already in progress` failure.
- The transport snapshot copies only the server URL, CA, fingerprint, and
  allowlist. Hot Network, meter, and heartbeat loops use narrower snapshots
  and never copy the complete PEM-bearing `RuntimeConfig`.
- microSD recovery always performs all three advertised reset/mount attempts.
- Runtime recovery retries the configured preferred SPI speed before the
  fallback and 400 kHz recovery speeds; it never treats the last failed
  recovery frequency as the new permanent preference.
- At the 400 kHz recovery speed, secondary local-history reads and diagnostic
  event uploads remain durable on the card but are deferred so they cannot
  retain the shared TLS-memory lease across heartbeat intervals. Primary
  reading synchronization retains priority.
- A heartbeat may wait up to 20 seconds for an already-running bounded primary
  storage page. This remains inside the 30-second request budget and avoids
  reporting a false server outage during recovery.
- Storage health readers use a separately locked last-known-complete snapshot
  while FAT recovery or a history page owns the SD mutex. They never copy
  partially updated sequence bounds, and they do not report a writable card
  as unavailable merely because a scan is active.
  A sensor configured at the 400 kHz recovery speed no longer collapses those
  attempts into one merely because all fallback frequencies are equal. Each
  attempt deasserts chip select and supplies a fresh 80 idle clocks. While a
  recovery scan owns storage, heartbeat status uses a conservative unavailable
  snapshot rather than exposing partially reconstructed sequence bounds.
  Remount and recovery also hold the shared high-memory lease, preventing TLS
  handshakes or local history scans from overlapping a multi-file FAT repair.
  Record validation and repair copying yield cooperatively every eight records
  or 512-byte chunks, so recovery cannot starve the watchdog-protected meter
  and aggregation tasks on their shared CPU core.
- Wi-Fi station sleep is disabled because the sensor is an always-on network
  appliance. This avoids multi-second receive latency for ICMP and AsyncTCP
  while a DNS or TLS operation is active.

If a local memory reserve or high-memory lease is temporarily unavailable,
the transaction is classified `LOCAL_RESOURCE_DEFERRED`, releases ownership,
and retries after 1.5 seconds. It does not mark the server unreachable, clear
authentication, increment external heartbeat-failure counters, or enter the
external exponential-backoff ladder. DNS, TCP, TLS, HTTP, and rate-limit
failures retain their bounded external retry behavior.

The task's stack high-water mark is lifetime diagnostic evidence. It emits a
rate-limited `STACK_LOW` warning below the 25-percent release threshold, but
is never a per-request TLS admission gate. A lifetime minimum cannot rise
after a deep call unwinds; using it as admission caused the former permanent
`TLS_STACK_PREFLIGHT_REJECTED` latch.

## Single-flight behavior

`SingleFlightGate` permits one active transaction and one pending request.
A local action queues the pending bit. Further actions coalesce into that bit.
Only `ServerSyncTask` consumes it. Every request has a cleanup guard that:

1. ends `HTTPClient` if it began, otherwise stops `WiFiClientSecure`;
2. marks the transaction complete, failed, or locally deferred;
3. clears the active request identifier;
4. releases the single-flight gate; and
5. retains at most one pending request.

No transport mutex is held across DNS, TCP, TLS, HTTP, microSD, or NVS.
Configuration and identity values needed by a request are copied into small,
request-owned snapshots; an active TLS client is never shared.

## Deadlines

| Stage | Limit |
|---|---:|
| Unicast DNS expected completion | 8 seconds |
| `.local` mDNS fallback | 2 seconds |
| TCP connect | 5 seconds |
| TLS handshake | 8 seconds |
| HTTP response | 10 seconds |
| Response-body read | 5 seconds |
| Overall transaction | 30 seconds |
| Response-body polling yield | 10 milliseconds |

The Arduino `WiFi.hostByName` implementation has its own finite 15-second
internal limit; the task rejects a result that arrives beyond the stricter
8-second transaction budget. A successful result is reused instead of
re-entering that process-global blocking resolver on every 15-second
heartbeat. Ordinary transport failures never reboot the sensor. Retry is
exponential, capped by the configured maximum, jittered, and honors a valid
server `Retry-After`.

## Fragmentation and reusable transport storage

TLS admission reads one `HeapSnapshot` and requires both 64 KiB total free
internal heap and a 32 KiB largest contiguous internal block. A state with
72,280 bytes total free and only a 24,564-byte largest block is classified as
local fragmentation. It is not a DNS, Wi-Fi, authentication, signature, or
server-transport failure and therefore does not advance external exponential
backoff. Optional UI work remains deferred and the heartbeat receives a short
bounded local retry after memory coalesces.

`ServerSyncTask` owns one 20 KiB request buffer and one 24 KiB response buffer.
Both are allocated once from PSRAM, never grow, and are reused for heartbeat,
reading, event, and bounded response bodies. A request body that exceeds its
documented capacity fails locally; it is never rebuilt in a larger internal
buffer. The CA-bearing transport configuration is cached and copied again only
when the persistent configuration generation changes. Request-specific
canonical/authentication values remain bounded and are destroyed by the one
transaction cleanup path.

The 32 KiB contiguous TLS guard is deliberately unchanged. Historical device
evidence established the safety boundary, but that evidence does not validate
the new binary. Current-run evidence consists of deterministic allocation,
fragmentation, mock-transport, native, browser, and build tests. Physical
confirmation remains a separate deployment step with the exact final ELF.

## Local isolation

`GET /api/local/health` is an unauthenticated, read-only LAN liveness probe.
It performs no server request, password hashing, HMAC operation, or microSD
history read. It contains no device identity or secret. It reports uptime,
Wi-Fi/time/storage/meter booleans, sync state, heartbeat counters, task stack
margin, and internal-heap state so a host soak test can verify the WebUI while
TLS is active or failing.

The following command is reserved for later physical deployment validation;
it is not an acceptance gate for the software-only repair:

```powershell
.\tools\diagnostics\Test-SensorHeartbeatSoak.ps1 `
  -Address 192.168.0.26 `
  -TargetHeartbeatIntervals 100
```

The generated CSV is machine-readable and includes every ping, WebUI, local
health, heartbeat-counter, stack, and heap sample. The command fails if it
does not reach the target, observes a reboot, loses ping/WebUI/health
availability, observes disconnected Wi-Fi or non-writable storage, or sees a
stack margin below 25 percent. Each sample permits three bounded 400 ms ICMP
attempts so one dropped packet is recorded without being misclassified as a
device outage; the root and health HTTP probes remain independent and
fail-closed.

Do not treat results from another source revision as release evidence. A
future physical run must use the exact released binary, matching ELF hash,
source fingerprint, timestamps, and task table. No prior 1.0.5 or other-binary
soak is evidence for this build.

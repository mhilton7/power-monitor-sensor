# Server synchronization task

`ServerSyncTask` is the only owner of active central-server DNS, TLS, HTTP,
response-stream, heartbeat, reading-upload, event-upload, remote-configuration,
and firmware-manifest operations. It runs on core 0 at priority 2. AsyncTCP,
the WebUI, Wi-Fi callbacks, the meter task, and the storage task never execute
central-server transport work.

## Call path and ownership

```text
Application::serverTask
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

- Reading pages are limited to 32 records and 20 KiB of stored payload.
- Event pages are limited to 24 records and 16 KiB of stored payload.
- The ArduinoJson tree is destroyed before TLS starts.
- The page's raw string vector is released before TLS starts.
- HTTP response `Content-Length` is required and capped at 24 KiB.
- Response bytes are read through a bounded stream loop, not `getString()`.
- TLS admission requires at least 64 KiB of free internal heap and a largest
  contiguous internal block of at least 40 KiB.
- One `tick()` performs at most one server operation, leaving an idle/yield
  boundary between heartbeat, backlog, event, configuration, and manifest work.
- In-progress storage jobs do not expire while `StorageTask` is still scanning.
  Only completed, unconsumed results expire after 60 seconds. This prevents a
  long scan from losing its result handle and being queued repeatedly.
- Durable measurement backlog has priority over diagnostic-event uploads.
  Events remain on microSD and are uploaded only after the server has advanced
  the reading acknowledgement cursor. This keeps low-priority evidence scans
  from competing with heartbeat TLS or primary measurements.
- A successful DNS result is cached for the unchanged host and port. TLS still
  receives the configured hostname for SNI and SAN validation. Two consecutive
  cached-address transport failures invalidate the cache and force a fresh
  lookup, so a server address change remains recoverable.
- Wi-Fi station sleep is disabled because the sensor is an always-on network
  appliance. This avoids multi-second receive latency for ICMP and AsyncTCP
  while a DNS or TLS operation is active.

If the memory reserve is unavailable, the transaction fails as
`MEMORY_EXHAUSTED`, releases ownership, and enters normal bounded backoff.
It does not attempt a TLS allocation that could destabilize lwIP.

## Single-flight behavior

`SingleFlightGate` permits one active transaction and one pending request.
A local action queues the pending bit. Further actions coalesce into that bit.
Only `ServerSyncTask` consumes it. Every request has a cleanup guard that:

1. ends `HTTPClient` if it began;
2. stops `WiFiClientSecure`;
3. marks the transaction complete or failed;
4. clears the active request identifier;
5. releases the single-flight gate; and
6. retains at most one pending request.

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

## Local isolation

`GET /api/local/health` is an unauthenticated, read-only LAN liveness probe.
It performs no server request, password hashing, HMAC operation, or microSD
history read. It contains no device identity or secret. It reports uptime,
Wi-Fi/time/storage/meter booleans, sync state, heartbeat counters, task stack
margin, and internal-heap state so a host soak test can verify the WebUI while
TLS is active or failing.

Run the physical soak from the repository root:

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

The final COM6 verification completed 100/100 automatic heartbeats with 771
host samples and zero reset, heartbeat, ping, WebUI, health, Wi-Fi, or storage
failures. Seventy-eight samples landed while a server transaction was active;
all local probes succeeded. The minimum task margin was 32 percent, minimum
free internal heap was 71,136 bytes, and the idle-heap average was higher over
the final 20 samples than the first 20 samples.

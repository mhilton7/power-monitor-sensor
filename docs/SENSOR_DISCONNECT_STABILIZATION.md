# Sensor disconnect and local-session stabilization

> Historical record: the physical observations below apply only to the named
> 1.0.6-1.0.8 binaries. They are not physical validation of the current
> fragmentation repair. Current Status polling is 10 seconds and is documented
> in `LOCAL_WEB_UI.md`.

The corrective release is firmware `1.0.8`. Version `1.0.5` had been reused
for non-identical binaries during earlier troubleshooting, so it remains
historical evidence and is not overwritten. Version `1.0.6` was a physical
pre-release candidate whose boot trace exposed an insufficient HealthTask
stack margin. Version `1.0.7` corrected that margin, but physical verification
also proved that ESPAsyncWebServer's default duplicate-header replacement
dropped the `pm_session` cookie when the CSRF cookie was added. Both candidates
remain immutable evidence. Both final sensors must use the same verified
`1.0.8` application image, which preserves both session headers.

## Baseline evidence

The July 31 diagnostic bundles showed two independent failure classes:

- Outdoor-AC recorded 9 local HTTP signature rejections and 0 central-sync
  authentication rejections.
- Indoor-AC recorded 7 local HTTP signature rejections and 0 central-sync
  authentication rejections, plus 7,739 microSD reads and 1,782 local HTTP
  requests during a similar uptime window.

The local error text was misleading. `HttpApi::authorize` tried a browser
cookie first, then passed the same ordinary browser request into the HMAC
verifier when the cookie was expired or had been replaced. The single-record
`SessionManager` allowed any new tab, browser, phone, renewal, or elevated login
to replace the previous client. Neither diagnostic bundle showed a genuine
central-server HMAC rejection.

The high microSD read count was caused by the former WebUI request fan-out:
multiple independently polled endpoints requested history/storage work. The
three-view 1.0.8 WebUI polled only `/api/v1/ui/status` every five seconds. The
current policy is one immediate request followed by one request every 10
seconds while visible. The endpoint reads an in-memory measurement and a
compact cached storage-health snapshot; it does not scan historical files.
Setup does not poll. Diagnostics loads only on entry or explicit refresh.

## Authentication repair

Requests are classified before verification as exactly one of:

1. local browser session;
2. complete server-to-device HMAC request;
3. unauthenticated request; or
4. malformed partial HMAC request.

An invalid or expired browser cookie returns `local_session_invalid` or
`local_session_expired`, clears only that browser's cookies, and never enters
the HMAC verifier. Partial HMAC headers return
`authentication_headers_incomplete`. A genuine complete HMAC request retains
all `pm-protocol/1.0.0` timestamp, nonce, body-hash, device-ID, and signature
checks.

The local session store has six fixed slots. It stores SHA-256 token and CSRF
digests, timestamps, bounded elevation, and a generation counter. It does not
store raw tokens. Session establishment reuses and refreshes the requesting
slot, refuses active-slot eviction, and reports
`local_session_capacity_reached` when full. Logout revokes only the requesting
slot. Password elevation changes only the requesting slot.

The browser uses one in-page renewal promise, pauses and aborts Status polling
during renewal, renews after returning from background, and retries a failed
safe GET at most once. Mutations are never automatically replayed. A readable
SameSite CSRF cookie prevents two tabs that share the HttpOnly session cookie
from retaining different CSRF values.

## Resource and disconnect diagnostics

- Browser-session failures, malformed authentication headers, browser rate
  limits, and server-HMAC rate limits have separate counters.
- The session table reports active, peak, created, reused, refreshed, expired,
  invalid, revoked, and capacity-rejection counts.
- A 16-entry allocation-free RAM tail captures meaningful station start,
  association, IP, authentication-mode, IP-loss, and disconnect transitions.
  Every transition is also queued into the rotating CRC-protected microSD
  event archive, so the initiating evidence survives an ordinary reboot and
  the retained archive comfortably covers the required 512 transitions. It
  records masked BSSID, channel, translated reason, RSSI, DHCP duration,
  network addresses, internal free heap, and largest internal block. It never
  records an SSID, password, key, cookie, signature, token, or request body.
- Download the bounded record from
  `/api/v1/diagnostics/disconnect-flight-recorder` while a local session is
  active.
- Memory pressure uses `normal`, `pressure_warning`, `low_memory`, and
  `recovering` states with consecutive samples, asymmetric thresholds, and
  dwell time. Entry, recovery, cumulative duration, longest episode, and heap
  minimums are exported. A normal transient TLS allocation no longer causes
  one-second enter/exit log oscillation.
- TLS local-resource deferrals remain distinct from DNS, TCP, TLS trust, HTTP,
  and HMAC failures. TLS certificate and hostname verification remain enabled.
- Every outbound transaction supplies a safe
  `pm-<boot-id>-<request-sequence>` `X-Request-ID`. The server already records
  this value as its request correlation ID, linking sensor serial evidence to
  API receipt and dashboard processing without exposing credentials.

## Correlation tools

```powershell
tools/diagnostics/Monitor-TwoSensors.ps1 `
  -SensorUrls http://192.168.0.26,http://192.168.0.202 `
  -DurationMinutes 60 -OutputPath two-sensors.jsonl
```

```powershell
tools/diagnostics/Capture-SensorSerial.ps1 -Port COM5 -LogDirectory .\captures
tools/diagnostics/Capture-SensorSerial.ps1 -Port COM6 -LogDirectory .\captures
```

The server monitor requires a cookie in a local file and validates TLS with the
provided CA. The cookie contents are never emitted:

```powershell
python tools/diagnostics/Monitor-ServerHeartbeats.py `
  --base-url https://power-monitor.home.arpa:8443 `
  --site-id HOME_ID --cookie-file session-cookie.txt --ca-file root.crt `
  --duration-minutes 60 --output server.jsonl
```

Merge captures chronologically:

```powershell
python tools/diagnostics/Correlate-DisconnectTimeline.py `
  two-sensors.jsonl server.jsonl --output correlated.jsonl
```

## Physical acceptance

Do not call the repair physically accepted until both enrolled sensors retain
their NVS credentials, CA trust, SD history, and acknowledgement cursor while
passing:

- at least 1,000 consecutive configured heartbeat intervals each;
- a 60-minute no-WebUI baseline;
- 60 minutes each with one Status client, two Status clients, Setup open, and
  Diagnostics on-demand;
- central-server and access-point outage/recovery cases;
- backlog drain and diagnostic-export-during-heartbeat cases;
- automatic recovery after power-cycle and network loss.

Record starting and ending firmware/ELF hashes, boot IDs, reset reasons,
heartbeat and batch counts, HMAC and browser-auth counters, TLS deferrals,
acknowledgement sequences, microSD reads by workload, minimum internal heap,
largest block, and task margins. Sensor Test Mode is not physical evidence.

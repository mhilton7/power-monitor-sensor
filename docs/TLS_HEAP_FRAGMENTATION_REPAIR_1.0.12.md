# TLS heap fragmentation repair (firmware 1.0.12)

## Scope and evidence

This release corrects the internal-heap lifecycle that could leave an ESP32-S3
with enough total memory but no 32 KiB contiguous block for the next verified
TLS connection. It does not lower the 64 KiB total or 32 KiB contiguous TLS
admission requirements, weaken certificate/hostname validation, erase device
state, or turn a local resource deferral into a network failure.

The production baseline was captured from both sensors on firmware 1.0.11 for
20 minutes at a non-mutating 10-second interval. All 240 requests succeeded.

| Sensor | Healthy idle | TLS transient | apparent idle low-total | Idle free median | Idle largest-block median | Active TLS minimum free / largest | Heartbeats | Reading batches |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Outdoor-AC | 100 | 18 | 2 | 74,246 B | 37,876 B | 19,684 / 8,436 B | +76 | +19 |
| Indoor-AC | 106 | 13 | 1 | 74,320 B | 34,804 B | 27,184 / 17,396 B | +75 | +20 |

Both backlogs remained zero and neither sensor lost a reading batch. The brief
low-total samples occurred at transaction boundaries, while the measured heap
returned to its normal idle baseline. Together with the captured production
incident (74,244 B free with only a 27,636 B largest block), this separated the
authorized TLS working-memory dip from persistent idle fragmentation.

Raw baseline responses are intentionally ignored by Git. The sanitized summary
is generated at `artifacts/live-memory-validation/pre-fix/summary.json` by
`tools/live_sensor_memory_probe.ps1`.

## Confirmed causes

The repair found several interacting firmware causes:

1. `MemoryPressurePolicy` evaluated the low-total emergency threshold before
   considering an already-authorized TLS or OTA operation. A normal TLS sample
   such as 27,032 B free / 18,420 B largest could therefore latch
   `low_total_memory`.
2. Once latched, `low_total_memory` could not be reclassified as fragmented
   when total memory recovered but the largest block did not. This obscured the
   actual idle condition and delayed the normal recovery sequence.
3. the health task materialized and queued a string-bearing persistent memory
   event immediately when the transition occurred, even while TLS owned its
   working memory. That allocation could occupy a just-created gap before TLS
   regions were destroyed and coalesced.
4. recurring interval and event persistence allocated variable-lifetime
   `IntervalRecord` and `EventData` objects with `new`.
5. `/api/local/health`, which is also the physical diagnostic probe, copied
   string-bearing models and built a dynamic JSON document and response string.
   Polling could therefore perturb the allocator it was measuring.
6. heartbeat/reading/configuration transports and the independent OTA
   manifest/download/report paths did not expose fixed lifecycle samples after
   `HTTPClient::end`, transport destruction, and high-memory lease release.

The application does not claim one allocation site alone caused every physical
incident. The causes above are the confirmed paths that allowed an active-TLS
dip to become persistent state and inserted variable allocations into the
critical cleanup window.

## Corrected ownership and ordering

Memory policy now applies this order:

1. heap-integrity failure and true critical low-total faults;
2. authorized TLS/OTA transient classification and post-operation grace;
3. idle low-total classification;
4. idle high-total/low-largest fragmentation classification;
5. bounded recovery hysteresis back to normal.

A former low-total state can become `fragmented` after total memory recovers,
then progress through `recovering` to `normal`. Only true idle low-total memory
sets the legacy low-memory Boolean.

Persistent memory events are reduced to a fixed scalar pending record during
TLS/OTA and grace. The event is materialized only if a later idle classifier
confirms the condition; a recovered transient is discarded.

Recurring storage messages use fixed PSRAM-backed pools allocated once at
startup:

- 120 compact interval slots;
- 16 compact event slots; and
- one reusable `IntervalRecord` in the storage task.

Every dequeue, failure, and shutdown path returns the slot. Capacity, active,
peak, and exhaustion counters are published by local health and diagnostics.
Pool exhaustion is visible and fail-closed; it does not fall back to `new`.

`GET /api/local/health` now captures compact fixed snapshots and writes schema
2 into one 3,072-byte response slot with a bounded JSON writer. A concurrent
request receives a typed bounded 503. It no longer constructs a
general-purpose JSON document, full identity/network/storage copies, or a
dynamically growing response body.

## TLS and OTA lifecycle evidence

Diagnostics keep the last 32 allocation-free checkpoints. Each checkpoint has
a request ID, monotonic time, operation context, fixed endpoint label, free
internal heap, and largest internal block. The lifecycle records:

- before client construction;
- after TLS configuration;
- after HTTP begin;
- after request;
- after `HTTPClient::end`;
- after the TLS client and transport helpers are destroyed; and
- after the high-memory lease is released.

Declaration order and lexical scopes guarantee that cleanup, `HTTPClient`, and
TLS client destructors run before the lease-release checkpoint. The same
ordering is used by heartbeat/reading/event/configuration requests and by OTA
manifest, binary download, and report operations. No `setInsecure()` path was
added and the pinned mbedTLS library configuration was not changed.

## Regression gates

`tools/check_hot_paths.py` now rejects dynamic ownership in the local-health
handler, recurring storage message types, and server synchronization paths. It
also requires every TLS lifecycle checkpoint. Native tests cover the exact
active-TLS and idle-fragmentation samples, pool exhaustion/release, bounded
local-health serialization, overflow rejection, and accelerated one-hour and
24-hour mixed TLS/OTA/WebUI/storage soaks.

Firmware 1.0.12 passed the repository policy, native C++ tests, the checked
sanitizer environment available on pinned Windows MinGW, all Python contract
and integration tests, embedded WebUI unit/build checks, and Chromium,
Firefox, and WebKit polling/two-tab tests before canary deployment.

## Qualification status

Outdoor-AC is the only permitted canary. Indoor-AC remains the firmware 1.0.11
control until Outdoor-AC passes the preliminary 90-minute and extended 24-hour
minimum gates, backlog recovery, and WebUI/diagnostics checks. Results from
different firmware binaries must never be combined.

The 24–48-hour Outdoor-AC qualification, subsequent Indoor-AC deployment,
60-minute Indoor qualification, 72-hour dual-sensor soak, and controlled
reboot/power-cycle checks are elapsed-time production gates. Until all complete,
the only valid status language is:

> The correction passed engineering tests and preliminary canary validation.
> Long-duration production qualification remains in progress.


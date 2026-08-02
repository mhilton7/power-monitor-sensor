# Memory and fragmentation

## Why free heap is not enough

ESP32 allocation succeeds only when one free block can satisfy the requested
allocation. A sensor can therefore have substantial total free internal heap
and still be unable to start mbedTLS. The controlling production incident had
72,280 bytes free in total but a largest internal block of only 24,564 bytes.
The TLS policy correctly rejected an operation requiring a 32,768-byte block.
Wi-Fi, metering, and microSD remained healthy because this was fragmentation,
not a network or authentication failure.

The 32 KiB contiguous-block requirement remains unchanged. Lowering it would
move a deterministic local deferral into an unpredictable TLS allocation
failure. The independent total-internal-heap floor is also retained. Policy
uses both values from `IHeapTelemetry`; native tests use the same policy with a
deterministic `FragmentingInternalHeap` arena.

## Pressure states

The bounded memory policy distinguishes:

| State | Meaning | Primary behavior |
|---|---|---|
| `normal` | Total and contiguous headroom are healthy | Normal UI and synchronization |
| `pressure_warning` | Headroom is approaching a guard | Defer optional heavy work |
| `fragmented` | At least 64 KiB is free, but no 32 KiB block exists | Local TLS deferral; release optional leases; short local retry |
| `low_total_memory` | Total internal memory is below the floor | Preserve meter/storage; defer heavy UI and TLS |
| `recovering` | Hysteresis is proving stable headroom | Keep optional work bounded until normal |

Fragmentation never increments authentication, Wi-Fi-disconnect, or external
transport-failure counters. It does not enter external exponential backoff.
The local retry path is bounded and resumes after optional allocations are
released and adjacent free blocks coalesce.

## Recurring allocation map

Before this correction, every compact Status request could own all of these at
once:

- full `NetworkStatus`, `StorageHealth`, sync, meter, and sensor-status copies;
- a general-purpose ArduinoJson document and its internal nodes;
- a dynamically growing serialized `std::string` response; and
- AsyncWebServer response storage for the copied body.

The heartbeat path also recreated request JSON, URL/canonical-signature
strings, response storage, and a complete CA-bearing transport configuration.
It additionally copied string-bearing network, storage, identity, and narrow
runtime-configuration snapshots and formatted UTC timestamps. The recorded
production symptoms are consistent with repeated allocation/free ordering
from browser Status polls interleaved with heartbeat and TLS work. The
deterministic arena reproduces the high-total/low-largest-block state. This run
did not capture a physical allocator call trace, so it does not attribute the
production decline to one allocation site or claim that the simulator proves
the exact physical allocation order.

The corrected ownership model is bounded:

| Storage | Capacity | Placement | Lifetime |
|---|---:|---|---|
| Compact Status response pool | 2 x 2,048 bytes | Long-lived internal heap | One move-only lease per response; all modeled completion/cancel/error cleanup paths release it |
| Compact status snapshot | Fixed fields and arrays | Handler stack | One request, before serialization |
| Heartbeat/request scratch | 20 KiB | PSRAM (`MALLOC_CAP_SPIRAM`) | Allocated once by `ServerSyncTask`, reused |
| Response scratch | 24 KiB | PSRAM (`MALLOC_CAP_SPIRAM`) | Allocated once by `ServerSyncTask`, reused |
| Canonical HMAC scratch | 2 KiB | PSRAM (`MALLOC_CAP_SPIRAM`) | Allocated once, wiped and reused after signing |
| Full request URL scratch | 1 KiB | PSRAM (`MALLOC_CAP_SPIRAM`) | Allocated once and reused |
| Canonical target | 1 KiB reserved string | Long-lived internal heap | Reserved once; recurring path cannot grow it |
| Build metadata and embedded UI | Compile-time data | Flash/PROGMEM | Firmware lifetime |
| TLS working memory | mbedTLS-managed internal heap | Internal heap | One admitted transaction |

PSRAM placement is limited to byte payloads whose consumers accept external
8-bit memory. TLS library state, DMA-sensitive objects, synchronization
primitives, and short lock-protected snapshots are not blindly moved to
PSRAM. Scratch allocation failure is fail-closed and visible; it does not fall
back to an unbounded internal buffer.

## Compact Status budget

`GET /api/v1/ui/status` uses `CompactUiStatusSnapshot`,
`BoundedJsonWriter`, and `StatusResponsePool`. The response maximum is 2,047
bytes plus a terminator. After warm-up the payload capture and serialization
path performs no large dynamic allocation, no configuration persistence, no
server request, and no storage-history scan. A small
`PooledUiStatusResponse` object and framework-owned response/header bookkeeping
still use the web library's normal allocation path; this is the documented
small exception and must not be reported as zero total request allocations.
The object itself has a compile-time `sizeof <= 512` assertion. Runtime
diagnostics publish its exact compiled size, allocation count, destructor
release count, and largest internal block immediately before and after response
construction. Its destructor explicitly releases the fixed body lease before
recording cleanup, so normal completion, disconnect, and error destruction all
use the same lifecycle. The difference between allocation and release counts is
therefore the observable outstanding-response count (apart from the instant a
diagnostics snapshot races an active response). Pool exhaustion returns a
static typed `503` with bounded `Retry-After`; it does not allocate a larger
fallback.

The recurring browser authorization path is separately allocation-stable. It
reads only the setup-AP boolean under the network mutex, parses `pm_session`
once from the existing AsyncWebServer header into a fixed 65-byte request-local
array, validates a non-owning `StringView`, and compares Origin/Host without
temporary Arduino `String` concatenation. An oversized session value remains
classified as presented but produces an empty validation view, preserving the
fail-closed session behavior without allocating attacker-selected storage.

`python tools/check_hot_paths.py` lexically checks the route, its authorization
helpers, and its serializer/response ownership helpers. It rejects full
snapshots, general-purpose JSON, dynamic containers, repeated cookie parsing,
history/diagnostic generation, and missing pool/serializer markers. Native
tests exercise writer bounds, pool lifetime, move-only release, repeated
cleanup, and pool pressure. Those are deterministic ownership tests, not a
claim that a physical AsyncTCP disconnect or allocator trace was observed.
Browser tests cover actual Chromium/Firefox/WebKit cancellation behavior
against the mock sensor server, not a physical ESP32 network stack.

## Test/debug allocation scopes

`DebugAllocationScope` is a fixed-capacity, caller-instrumented accounting
helper for native tests and explicitly enabled debug work. Its scope identifiers
cover Status, Setup, Diagnostics, browser sessions, heartbeat/reading/event
JSON, request signing, HTTP responses, TLS, storage pages, and OTA. For each
operation it records allocation count, allocated/freed bytes, outstanding
allocations/bytes, largest allocation, peak simultaneous bytes, preferred and
observed Internal/PSRAM placement, operation start/end, and largest
Internal/PSRAM blocks at both boundaries.

The helper has no dynamic bookkeeping and fails closed when its record capacity
is exhausted. It is not a `malloc` interceptor, heap hook, AsyncTCP trace, or
physical ESP32 allocator measurement. An operation is balanced only when it
ended without accounting/capacity errors and every caller-recorded allocation
was freed.

`WiFiClientSecure` and `HTTPClient` remain transaction-local. Retaining either
object risked stale connection, certificate, and cleanup state in the Arduino
libraries. The single-flight task destroys them after every bounded request;
task-owned payload, response, signing, URL, and cached configuration storage is
reused around that deliberate transport lifecycle.

## Exact incident fixture

The native incident fixture records:

```text
duration_seconds                    2100
status_requests                     341
heartbeat_interval_seconds          15
server_offline_after_seconds        30
free_internal_bytes                 72280
largest_internal_block_bytes        24564
tls_required_largest_block_bytes    32768
starting_tls_heap_deferrals         46
ending_tls_heap_deferrals           117
wifi_connected                      true
authentication_failures             0
network_failures                    0
```

The legacy model reproduces the local TLS deferral and server Offline
transition. The corrected model must keep normal post-warm-up Status polling
allocation-stable, admit all scheduled heartbeats, and recover an induced
fragmentation episode without reboot or external backoff.

## Deterministic accelerated-soak coverage

The native virtual-time model exercises fixed Status leases and scoped
Internal allocations around a persistent warm baseline. The following are
software-model counters, not physical timing or allocator traces:

| Scenario | Status | Meter | Durable | Heartbeats admitted | Session renewals | Visibility | Diagnostics | Outage |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 35-minute historical worst case | 341 | 2,100 | 35 | 140/140 | 1 | 1 pause/resume | 1 refresh | none |
| 35-minute current 10-second policy | 211 | 2,100 | 35 | 140/140 | 1 | 1 pause/resume | 1 refresh | none |
| 24-hour current policy | 8,641 | 86,400 | 1,440 | 5,760/5,760 TLS admissions | 48 | 4 pause/resume | 10 refreshes + 2 downloads | 8 deliberate failed server deliveries, then recovery |
| 35-minute two-client case | 422 total | 2,100 | 35 | 140/140 | 2 | 2 pause/resume | 2 refreshes | none |

Every scenario asserts one request at a time per client, at most two concurrent
Status leases, no Status-triggered history scan, no buffer growth, no TLS heap
or stack deferral in normal operation, no stale-connected label, no pool
exhaustion, balanced allocation scopes, zero final outstanding allocations,
and identical warm/minimum/end largest-block values. The 24-hour case records
one dashboard Offline transition only inside the deliberate outage and one
recovery; it asserts zero false transitions outside that interval.

## Build-map evidence

Generate comparable reports only after all three environments build:

```powershell
python -m platformio run -e esp32-s3-release
python -m platformio run -e esp32-s3-debug
python -m platformio run -e esp32-s3-simulated-meter
python tools/report_build_memory.py --require-artifacts `
  --output .pio/build/memory-report.json
```

The report includes firmware/ELF/map sizes and SHA-256 values, linker output
totals for static DRAM, IRAM, and flash, PSRAM-related map lines, large input
sections, configured task-stack totals, WebUI asset sizes, response-pool size,
and transport-scratch size. Large input-section rows are advisory because a
linker can fold or aggregate library sections; output-section totals are the
comparison authority.

The pre-edit baseline was reconstructed from an untouched checkout of Git
commit `085386e1185bcd352a721d3a28d64e418fddb2dc` with the same pinned
toolchain. That baseline used 1,629,309 program bytes, produced a
1,629,744-byte `firmware.bin`, used 125,264 bytes of static DRAM, and used
70,107 bytes of IRAM. The completed 1.0.10 release build uses 1,649,249
program bytes, produces a 1,649,696-byte `firmware.bin`, uses 125,528 bytes of
static DRAM, and uses 70,107 bytes of IRAM. The correction therefore adds
19,940 program bytes, 19,952 binary bytes, and 264 static-DRAM bytes while
leaving IRAM unchanged. The generated 1.0.10 release bundle carries its own
authoritative size and hash manifests. An older
1,629,488-byte workspace artifact was not used as the comparison baseline.

## Validation scope

The deterministic simulator, native tests, WebUI tests, mock HTTPS tests, and
ESP32 release/debug/simulated-meter builds are software evidence. Configured
stack sizes and linker maps are static evidence, not physical high-water
measurements. No COM port, serial monitor, upload, or physical ESP32 soak is
part of this repair run.

`native-sanitized` enables AddressSanitizer, UndefinedBehaviorSanitizer, and
LeakSanitizer on host toolchains that provide their runtimes. The repository's
pinned Windows MinGW 5.1 package does not include those runtime libraries, so
that host runs checked libstdc++ iterators plus stack canaries and prints the
limitation explicitly. It must not be described as an ASan result. A separate
native test build compiled with Visual C++ `/fsanitize=address` also passed on
this host. The installed Windows toolchain does not provide UBSan or
LeakSanitizer, so neither is claimed.

Physical deployment validation remains a later step. It must use the exact
binary and matching ELF hash, confirm real heap/stack telemetry, and must not
reuse a soak result from another source revision or firmware image.

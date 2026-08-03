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

The calibrated policy uses exact internal-heap thresholds:

- `normal` evidence requires at least 68 KiB total and a largest block of at
  least 32 KiB;
- `fragmented` requires at least 64 KiB total with a largest block below
  32 KiB;
- `low_total_memory` requires three consecutive idle samples below 56 KiB;
- below 32 KiB, failed heap integrity, or a critical allocation failure enters
  the critical state immediately in every operation context; and
- after TLS/OTA cleanup, a three-second grace precedes idle classification.
  Three safe samples move a latched low/fragmented state to `recovering`, and
  three more safe samples return it to `normal`.

Samples taken in `tls_preparing`, `tls_active`, or `ota_active` record transient
minima but do not classify persistent pressure unless an emergency condition is
present. A latched `low_total_memory` state remains latched through an
intermediate 60 KiB or fragmented sample; only the safe recovery sequence can
clear it. The legacy `health.low_memory` Boolean is true only for
`low_total_memory`.

Fragmentation never increments authentication, Wi-Fi-disconnect, or external
transport-failure counters. It does not enter external exponential backoff.
The local retry path is bounded and resumes after optional allocations are
released and adjacent free blocks coalesce.

Firmware 1.0.12 evaluates an authorized TLS/OTA operation before applying idle
low-total or fragmentation classifications. Heap-integrity failure and a true
critical floor remain immediate faults. A normal admitted TLS dip is recorded
as a transient minimum, then the allocator is evaluated after transport
destruction, high-memory lease release, and the post-operation grace period.
Persistent memory-event storage is deferred until that idle evaluation agrees;
it cannot allocate a string-bearing event while TLS owns the heap.

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
| Local-health body | 1 x 3,072 bytes | Long-lived internal heap | One bounded lease; overlap returns typed 503 |
| Durable interval messages | 120 compact slots | Long-lived PSRAM | Slot returned after storage task consumes or rejects it |
| Durable event messages | 16 compact slots | Long-lived PSRAM | Slot returned after storage task consumes or rejects it |

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

`GET /api/local/health` is independently bounded because it is polled during
physical memory qualification. It uses compact network, storage, identity,
sync, pressure, queue, pool, and heap snapshots and serializes schema 2 directly
into one fixed 3,072-byte response slot. It does not use ArduinoJson, a dynamic
response string, a history scan, or a central-server request. The single slot
avoids reserving a larger idle internal-DRAM pool; concurrent probes receive a
bounded 503 and must retry at their configured interval.

The last 32 TLS/OTA lifecycle checkpoints are also fixed-capacity. They sample
before client construction, after TLS setup, after HTTP begin/request/end,
after the transport destructors, and after the high-memory lease release. This
separates expected active TLS minima from a failed idle coalescence.

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

## Pinned mbedTLS result (Phase 27)

The pinned `espressif32@6.13.0` Arduino platform links the ESP-IDF/mbedTLS
libraries supplied as prebuilt framework archives. The selected ESP32-S3
`qio_opi` framework configuration was inspected in both its shipped
`tools/sdk/esp32s3/sdkconfig` and generated `include/sdkconfig.h`. It reports:

```text
CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y
CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=16384
# CONFIG_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH is not set
CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=y
```

The dynamic-buffer and dynamic-free configuration options requested by the
audit are not enabled in that prebuilt framework. The pinned
`WiFiClientSecure` API also exposes no `setBufferSizes` method. Adding
`CONFIG_MBEDTLS_*` names to this application's `build_flags` would compile the
application against different declarations without rebuilding the linked
mbedTLS archives; it would not safely change the library and could create an
ABI/configuration mismatch. This repair therefore does not invent an
unsupported runtime call or claim those options are active. Enabling them
would require a separately pinned and fully rebuilt Arduino-as-component or
custom framework, followed by the same TLS, OTA, rollback, and memory-soak
validation.

The safe optimization for the current framework is at the application
boundary: one serialized TLS/OTA owner, a 64 KiB total/32 KiB contiguous
admission guard, 20 KiB reusable request and 24 KiB reusable response buffers
in PSRAM, a 2 KiB canonical-HMAC buffer, a 1 KiB URL buffer, a 16 KiB bounded
OTA manifest parser, and exact `Content-Length` checks before reading bounded
responses or firmware. TLS objects remain internal-memory and
transaction-local so their destructors run before the high-memory lease records
the post-operation grace timestamp.

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
LeakSanitizer only on host toolchains that provide their runtimes. The
repository's pinned Windows MinGW 5.1 package does not include those runtime
libraries. On this Windows validation run the environment therefore used
checked libstdc++ iterators and `-fstack-protector-all`; its build and native
test executable passed. It was not an ASan, UBSan, or LeakSanitizer run, and no
separate sanitizer-capable toolchain was run for this source revision.

Physical deployment validation remains a later step. It must use the exact
binary and matching ELF hash, confirm real heap/stack telemetry, and must not
reuse a soak result from another source revision or firmware image.

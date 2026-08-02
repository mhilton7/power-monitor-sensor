# ESP32 task stack sizing

For the pinned ESP32 Arduino/ESP-IDF toolchain in this repository,
`xTaskCreatePinnedToCore()` stack depth and
`uxTaskGetStackHighWaterMark()` are byte counts. The task constants therefore
use names ending in `StackBytes`, and serial diagnostics use
`stack_allocated_bytes` and `stack_high_water_bytes`.

This differs from upstream FreeRTOS ports that document stack depth in
`StackType_t` words. Do not multiply or divide these ESP-IDF values by four.

## Central task table

Production task allocations are defined in `include/app/TaskConfig.h` instead
of being repeated as numeric literals:

| Task | Allocation |
|---|---:|
| Diagnostic logger | 4 KiB |
| Meter | 6 KiB |
| Aggregation | 8 KiB |
| Storage | 12 KiB |
| Network | 8 KiB |
| Server synchronization | 24 KiB |
| Health | 12 KiB |
| Maintenance | 12 KiB |
| Serial command | 24 KiB |
| Password worker (on demand) | 16 KiB |

`ServerSyncTask` remains on core 0 at priority 2. Before this repair it was
12 KiB on the same core and priority. The larger 24 KiB allocation is a
measured safety provision for secure-client call depth; it is not the primary
memory fix. Peak heap ownership was reduced and bounded independently.
`SerialCommandTask` was first increased from 4 KiB to 8 KiB after the
baseline diagnostic capture proved that formatting a task/memory report could
overflow that task. It is now 24 KiB because configuration-changing serial
commands atomically persist and re-verify the complete configuration,
including parsing the configured Caddy CA with mbedTLS. A production trace
captured a double exception in `mbedtls_pem_read_buffer` while an 8 KiB serial
task applied `loglevel info`; the larger stack keeps that verified write path
safe.

The production NetworkTask previously left 1,020 bytes of a 6,144-byte
allocation (16 percent). Hot network paths now copy a narrow configuration
snapshot that excludes CA/OTA PEM data, reuse one configured SSID during a
scan, and use an 8,192-byte allocation. Replaying reconnect, DHCP, mDNS,
setup-AP, scan, and concurrent synchronization is required before release;
the same former worst-case use would leave 37 percent.

Serial input remains a small nonblocking loop, but serial configuration writes
retain their independently measured worker stack because they must parse and
atomically verify the complete CA-bearing configuration. Password work is
created only while a bounded job exists. They are not merged: doing so would
couple physical recovery input to browser authentication, expand the shared
secret lifetime, and add priority-inversion and queue-starvation risk. OTA and
maintenance remain off AsyncTCP and keep a dedicated bounded worker because
signed download, flash writes, rollback, and storage repair may block.

Server synchronization does not enumerate or read microSD files directly.
It submits bounded history jobs to `StorageTask` through
`StorageCoordinator`, then polls the result from later scheduler ticks. This
keeps recursive FAT directory scans and SPI reads off the Wi-Fi core, so a
large offline backlog cannot starve `NetworkTask` or the core idle task.
On core 1, `StorageTask` runs at priority 0 while the watchdog-supervised
`AggregationTask` runs at priority 3. Recovery also yields while scanning
record bytes and records. Idle priority lets the scheduler service the
watchdog-monitored idle task while every online task can preempt a slow 400 kHz
card recovery. This ordering is intentional: recovery must never prevent
AggregationTask from waking, feeding its watchdog, and preserving the
measurement pipeline.

## Measurement

At `TASK_START` and every major sync checkpoint, firmware records:

- allocated and high-water bytes;
- estimated used bytes;
- unused margin percentage;
- core and priority;
- current/minimum heap;
- largest general and internal heap blocks; and
- free PSRAM.

Checkpoints cover JSON build, DNS, TLS, HMAC, HTTP send, response parsing,
transaction completion, and transaction failure. A rate-limited `STACK_LOW`
warning is emitted below the 25-percent minimum.

The margin formula is:

```text
margin_percent = min(high_water_bytes, allocated_bytes)
                 * 100 / allocated_bytes
```

For a 24 KiB task, acceptance requires at least 6 KiB of measured high-water
space at the worst tested checkpoint. NetworkTask and ServerSyncTask have a
30-percent target; other application tasks retain the 25-percent minimum.
Native/simulated runs can prove configured capacity and modelled margin only.
Record an actual minimum from a later physical run in the release verification
report; never replace physical measurement with configured allocation.

## Sizing procedure

1. Build and flash the exact production environment without erasing flash.
2. Capture a matching ELF SHA-256 and full serial log.
3. Exercise heartbeat, maximum bounded reading/event payloads, server errors,
   response parsing, and outage recovery.
4. Run at least 100 automatic intervals while collecting local health.
5. Use the smallest observed `stack_high_water_bytes` as the worst case.
6. Require at least 25 percent unused space and no downward trend suggesting
   corruption.
7. If the margin fails, first remove large locals and shorten live object
   lifetimes; change allocation only after remeasurement.

Never disable the watchdog, increase its timeout to mask a task defect, or use
an unbounded stack allocation.

## Physical verification

Physical results are valid only for the exact source fingerprint and binary
listed in the release verification record. Earlier ServerSyncTask soak claims
do not describe the current 24 KiB layout, fixed Status-response pool, or
PSRAM transport scratch and therefore are not current acceptance evidence.

This repair run is software-only: it records configured/static and simulated
evidence, builds all ESP32 environments, and does not connect, flash, or
monitor hardware. Physical task high-water, Wi-Fi, and TLS confirmation remain
a later deployment-verification step using the exact final ELF.

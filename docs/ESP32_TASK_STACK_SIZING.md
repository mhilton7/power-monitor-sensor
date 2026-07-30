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
| Storage | 8 KiB |
| Network | 6 KiB |
| Server synchronization | 24 KiB |
| Health | 6 KiB |
| Maintenance | 12 KiB |
| Serial command | 24 KiB |

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

Server synchronization does not enumerate or read microSD files directly.
It submits bounded history jobs to `StorageTask` through
`StorageCoordinator`, then polls the result from later scheduler ticks. This
keeps recursive FAT directory scans and SPI reads off the Wi-Fi core, so a
large offline backlog cannot starve `NetworkTask` or the core idle task.

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

For a 16 KiB task, acceptance requires at least 4 KiB of measured high-water
space at the worst tested checkpoint. Record the actual minimum from the
physical 100-heartbeat CSV in the release verification report; never replace
measurement with the configured allocation.

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

The ESP32-S3 N16R8 production image was exercised on COM6 for 100 consecutive
automatic heartbeat intervals while a host sampled ICMP, `/`, and
`/api/local/health`. All 100 heartbeats succeeded across 771 host samples.
There were no resets, watchdogs, lost local probes, Wi-Fi failures, or storage
failures.

The worst `ServerSyncTask` high-water value was 5,384 bytes out of the
16,384-byte allocation. Estimated worst-case use was therefore 11,000 bytes,
leaving a measured 32 percent margin. The task remained on core 0 at priority
2.

Minimum sampled free internal heap during TLS was 71,136 bytes and the minimum
largest internal block was 59,380 bytes. Idle free internal heap was 122,456
bytes at the first sample and 122,204 bytes at the last; the first 20 idle
samples averaged 121,671.2 bytes and the last 20 averaged 122,008.2 bytes.
The largest idle block began and ended at 69,620 bytes. These measurements show
no continuous heap loss or fragmentation trend.

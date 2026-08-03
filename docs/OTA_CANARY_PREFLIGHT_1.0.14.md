# OTA canary preflight correction (1.0.14)

## Physical 1.0.13 bootstrap result

The authorized application-only USB bootstrap wrote and verified firmware
1.0.13 on the Indoor-AC canary without erasing NVS, partitions, filesystem, or
microSD data. The first boot preserved the device boot identity lineage and
started all runtime services, but physical serial evidence exposed a release
blocker before any managed OTA was attempted:

```text
free_internal_heap=60960..61068
largest_internal_block=52212
minimum_free_internal=65536
minimum_largest_block=32768
result=internal_heap_reserve_low
```

Heartbeat, effective-configuration, and firmware-manifest transactions all
failed closed at TLS preflight. No TLS threshold was lowered and no failed
transaction was counted as a server outage.

## Root cause in the candidate

Firmware 1.0.13 increased the long-lived OTA maintenance task from 12 KiB to
24 KiB. That permanent additional 12 KiB allocation, together with the new
crash ledger and bounded response-object metadata, reduced idle internal heap
below the required 64 KiB TLS reserve. This is a confirmed contributor in the
1.0.13 candidate; it does not prove the cause of the unmatched original 1.0.11
panic.

Firmware 1.0.14 uses a 16 KiB maintenance stack. The exact 4 KiB OTA stream
buffer remains internal-memory-backed for flash safety, but it is now acquired
only after TLS preflight and is released with the HTTP/TLS transport before
`Update.end()`. This recovers 8 KiB of idle internal heap and 4 KiB of OTA task
stack consumption without weakening TLS admission or flash-write validation.

The 16 KiB bound is provisional until a real server-managed OTA records its
maintenance-task high-water mark with at least the required 25% margin. A new
application-only bootstrap authorization is required for 1.0.14 because the
prior authorization named the 1.0.13 artifact. The corrected OTA itself must
then use a separately versioned follow-up release.

# OTA panic and recovery repair (1.0.13)

## Incident evidence and decode limit

The affected Indoor-AC sensor (`fd15f3e1-37a1-4eab-9b22-d95d0dff07aa`) rebooted with ESP reset reason 4 (`PANIC`) while an OTA deployment remained at Downloading 0%. It returned on 1.0.11, commit `5565e1b278bd`, and reported firmware binary SHA-256 `24819fd63bf94c02e1fb9ab2a05848886cb926fd3f6781d3e63c26ebdc7112a9`.

The retained repository artifact named 1.0.11 is not the exact incident image:

- retained 1.0.11 firmware SHA-256: `74447d23603114b0bd779c705ac1fca50aa0a24a91b4e21037b5059491142d8f`
- retained 1.0.11 ELF SHA-256: `2cf49e1fd1bd390c13a54ccdab085d59ea540ef0787d46f5db802f890b1e7802`

Consequently, decoding the old panic against that ELF would be misleading. No raw PC/register/backtrace or exact matching ELF is available in the repository. The original exception location remains unproven. A controlled canary reproduction, if one occurs, must be decoded against the exact 1.0.13 (or follow-up) ELF. The repair does not label memory pressure as the original panic cause.

## Confirmed code defects and contributing risks

The audit identified and corrected these independently demonstrable defects:

1. The OTA workflow previously retained a broad high-memory ownership context across several HTTPS transactions. Each manifest, report, and binary transaction now owns a separate TLS lease.
2. The binary transaction still retained HTTP/TLS objects until after `Update.end()`. The repaired lexical boundary destroys HTTP/TLS and releases its lease before flash finalization.
3. Several milestone reports could be sent in one burst. Each bounded attempt now sends one report transaction.
4. The maintenance task stack was 12 KiB while the main synchronization TLS task uses 24 KiB. It is now 24 KiB. Stack exhaustion was a plausible risk, not a decoded cause.
5. Compact Status response wrappers used fragmented general heap allocation. Fixed response-object and body pools now own this path, with bounded 503 behavior on exhaustion.
6. Active authorized TLS consumption was being surfaced as durable low-total-memory state in diagnostics. Active TLS/OTA samples are transient minima; idle samples retain the 64 KiB/32 KiB admission rules and persistent classification.
7. Crash evidence did not preserve the OTA stream boundary. A CRC-protected, allocation-free RTC ledger now retains boot identity, firmware/build, reset reason, deployment attempt, stage, byte count, Update-open flag, reboot expectation, heap, PSRAM, task/stack, operation context, partitions, and last error.

## Lifecycle and failure safety

The ledger records workflow lock, per-transaction lease, manifest response/parse/authentication, milestone reports, firmware headers, metadata receipt/validation, `Update.begin`, first byte, 64 KiB progress checkpoints, stream completion, SHA finalization, hash/protocol verification, transport destruction, `Update.end` begin/complete, boot-partition selection, recovery persistence, reboot report/request, post-boot detection/validation, rollback, and failure persistence.

`OtaFaultInjection.h` provides compile-time-disabled deterministic boundaries for before-first-byte, after metadata, after `Update.begin`, halfway, after download, before/after `Update.end`, and before reboot. Production builds use `PM_OTA_FAULT_STAGE=-1` and cannot trigger a test fault.

Failure state is persisted before a fresh bounded report transaction. Every open Update handle is aborted on stream failure, every SHA context is freed, exact Content-Length is required, partial writes fail, extra bytes fail, the complete image hash and protocol marker are verified, and the boot target is not selected until finalization succeeds.

## Validation status

Starting sensor commit: `5c98b6939764de74ff70f17ba119593ae781b610`.

Static and simulated validation is recorded in the task result. Physical validation remains deliberately incomplete until the user authorizes an application-only USB canary bootstrap. The required command must write only the application at `0x20000`; it must not erase flash. After bootstrap, a separately versioned follow-up image must complete a real server-managed OTA and the approximately one-hour live test before this repair can be called fully accepted.

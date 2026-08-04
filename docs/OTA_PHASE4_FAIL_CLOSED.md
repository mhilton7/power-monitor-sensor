# OTA Phase 4 fail-closed state machine

This revision hardens the existing `pm-ota-manifest/2` flow. It does not change
`pm-protocol/1.0.0`, partition layout, TLS validation, HMAC derivation, device
identity, settings, or microSD history.

## Durable pre-reboot proof

Recovery persistence returns a typed result: loaded, saved and verified,
cleared, not found, load/parse/serialize/commit/readback failure, identity
mismatch, clear failure, or state-lock failure. A save is successful only when
the active copy can be read back and every recovery-record field matches.

The install sequence is fail closed:

1. Authenticate the manifest and durably checkpoint it.
2. Stream and verify the exact image into the inactive application partition.
3. Durably checkpoint `partition_written`.
4. Select the candidate and verify its address, label, type, subtype, size,
   non-running identity, OTA state, project, version, and build metadata.
5. Durably checkpoint `reboot_pending` and then `rebooting`.
6. Perform one final full-identity readback before reboot.

Any failure after candidate selection restores the original running boot
partition. The primary failure and any restore failure remain distinct. No
failure branch treats an unverified `ESP.restart()` as recovery.

On the candidate boot, recovery evidence is checked before storage, meter,
network, HTTP, synchronization, or other production services start. A pending
image with missing/corrupt recovery state or a version/build mismatch requests
automatic ESP-IDF rollback immediately. If rollback is unavailable, injected,
or cannot be marked, the image remains PENDING_VERIFY and enters an explicitly
restricted local-recovery runtime. That runtime starts only networking, the
embedded Web UI, authenticated diagnostics/configuration, OTA maintenance, and
the serial console. Meter polling, aggregation, microSD record creation and
retention, server synchronization, and healthy-boot/mark-valid processing never
start.

Because missing/corrupt recovery evidence has no authenticated deployment tuple,
the implementation does not invent one for the normal OTA report endpoint. It
instead commits an independent, identity-neutral incident to separate atomic
NVS slots and verifies the readback before advertising it as durable. The local
OTA status/diagnostics surface exposes the failure code, rollback result,
pending-image state, running version/build, boot identity/count, and pending
operator-report flag. If even that incident checkpoint fails, recovery still
starts, but truthfully reports `restricted_incident_durable=false`. Normal
mutations return `409 ota_restricted_recovery_active`; rollback, verified OTA,
network/config recovery, reboot/reset, login/logout, and read-only diagnostics
remain available. When ESP-IDF reports that a rollback image still exists, a
replacement OTA install is rejected until rollback completes because the
two-slot partition layout would otherwise overwrite the last known-good image.
If no rollback image exists, authenticated verified OTA remains an available
recovery path. Network and Web UI readiness are reported only after network
subsystem startup; serial recovery remains available when that startup fails.

Each durable transition atomically increments a persisted unsigned 64-bit
`evidence_sequence`. Reports and signed heartbeat recovery evidence expose that
same value. Heartbeats include the current deployment ID, attempt, and sequence
together only while a real OTA attempt is active, so evidence cannot be applied
to another attempt. Retries do not increment it, legacy recovery records begin
at zero, and exhaustion fails closed rather than wrapping. The optional
`waiting_for_schedule` milestone is reported only when a device actually waits
for its configured installation window. Successful report delivery keeps the
queue active until every missed milestone has been replayed.

## Post-boot classification

The pending candidate observes local health for 30–60 seconds while feeding the
watchdog and yielding. Evidence is classified as:

- `healthy`: local runtime and required initialization are sound;
- `healthy_external_degraded`: local runtime is sound while server, DNS, Wi-Fi,
  or time is temporarily unavailable;
- `retryable_local_initialization`: local services still have a bounded chance
  to become ready, so validation is checkpointed and deferred;
- `local_initialization_blocked`: microSD recovery, a valid PZEM response, or
  network-subsystem initialization did not complete by the 60-second deadline;
  the candidate remains unvalidated and exposes recovery without rebooting or
  requesting rollback; or
- `fatal_local_runtime`: running identity, task progress, heap integrity, or a
  required local invariant has failed.

Only a healthy or externally degraded local image is marked valid. Retryable
initialization waits through the complete bounded window. Storage is remounted
through its normal non-formatting recovery ladder, PZEM availability requires a
successful live poll, and network initialization is separate from Wi-Fi link
availability. Persistent local-initialization failure becomes a typed,
non-rebooting blocker. A LAN, DNS, clock, or server outage cannot produce that
blocker. Fatal local runtime requests typed rollback. Mark-valid and
rollback-mark results are checked; failures keep the local recovery surface
available without a blind restart.

## Bounded evidence

The OTA report body uses a fixed 2048-byte buffer. Recovery/readback and
partition-validation outcomes have stable typed names. The CRC-protected RTC
stage ledger records partition verification, recovery readback, boot-partition
restore, retryable post-boot validation, rollback request, and rollback-mark
failure without retaining credentials or payloads.

## Fault injection and tests

Compile-time fault boundaries cover the original stream/finalization stages and
the following persistence/boot stages:

- before and after recovery persistence;
- before recovery readback and forced readback mismatch;
- after boot-partition selection;
- before post-boot validation and before mark-valid;
- forced mark-valid failure;
- before rollback marking and forced rollback-mark failure.

Native policy tests mutate partition address, label, subtype, size, running
identity, OTA state, project, version, and build metadata. They also cover full
recovery-record equality, external-degraded acceptance, bounded local
initialization, non-rebooting local blockers, fatal rollback, typed rollback
failure, no blind restart, fixed report capacity, and all configured fault
points. Tests also cover not-found/load-failed/parse-failed recovery identity,
rollback unavailable/mark failure, atomic restricted-incident readback, and the
absence of measurement/storage/sync tasks in restricted recovery. Physical
rollback and sustained post-boot verification still require an enrolled
ESP32-S3; host and simulated tests are not represented as physical proof.

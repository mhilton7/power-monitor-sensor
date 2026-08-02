# Replaced-card sequence reconciliation

Firmware 1.0.10 preserves the separation between server connectivity and local
microSD recovery. A
valid HTTP 200 heartbeat proves that the enrolled device reached the server
and authenticated successfully. A missing, read-only, or replacement card can
degrade durable History, but it does not turn that accepted heartbeat into a
network failure.

## Authoritative high-water mark

Before a durable reading is assigned a sequence, the sensor calculates the
highest of:

- the largest record on the mounted card;
- the verified sequence journal (including a recoverable temporary or backup
  journal);
- the acknowledgement persisted in NVS;
- the server's maximum-seen sequence;
- the high-water checkpoint saved before safe card removal.

The next sequence is exactly one greater than that value. A blank replacement
card presented to a device whose server reports acknowledgement 785 and
maximum-seen 790 therefore starts at 791, never at 1 or 786. A maximum value of
`UINT64_MAX` is a fail-closed conflict and no record is written.

## Storage ownership and power-loss behavior

Only `StorageTask` performs runtime sequence reconciliation. ServerSync queues
the highest requested floor and continues normal heartbeat scheduling. Requests
are coalesced so repeated heartbeats do not create unbounded work.

`StorageTask` runs at idle priority on core 0, while `ServerSyncTask` runs on
core 1. Some recovering FAT cards can hold `openNextFile()` inside the SD/VFS
driver for longer than the ESP-IDF task-watchdog window. Directory enumeration
therefore uses a scoped guard that temporarily removes only the current core's
idle task from the task watchdog and always restores it after enumeration. It
does not disable the interrupt watchdog or the watchdogs registered for
application tasks. This keeps heartbeat/TLS work responsive on the other core
without allowing a slow but valid card scan to reset the sensor.

The journal update writes and flushes a temporary file, reopens and verifies
it, preserves the prior journal as a backup, installs the new journal, reopens
and verifies the installed value, and only then removes the backup. Boot
recovery uses the highest valid target, temporary, or backup journal.

## Card identity

`/POWERMON/manifest.json` schema 2 binds a card to the enrolled device UUID and
a safe hardware fingerprint and assigns a card-generation value. A schema 1
card is upgraded without changing readings. A schema 2 card from another
sensor is rejected read-only; factory reset and formatting are never automatic.

## Operator states

- **Online**: accepted heartbeats and durable storage are ready.
- **Online · Storage reconciling**: heartbeats are accepted while StorageTask
  is restoring the sequence floor.
- **Online · Storage degraded**: heartbeats are accepted, but local durable
  History needs attention.
- **Offline**: no signed heartbeat was received within the server threshold.

The manual microSD test is diagnostic evidence only. It cannot change the
mounted/writable lifecycle state by itself.

## Authoritative snapshot and diagnostics

Firmware decisions use one locked `SequenceState` snapshot rather than
combining unrelated health reads. It records card presence and writability,
card emptiness, local record count and sequence range, the recovered journal,
prepared-removal checkpoint, persisted server acknowledgement and maximum,
the effective floor, next sequence, and card identity.

Sequence-floor persistence reports the precise failing stage: temporary-file
write, temporary verification, backup rename, journal installation, or final
verification. Counters distinguish floor advances, write failures, and verify
failures. Backlog is calculated from the newest **syncable** reading, so
untrusted recovery artifacts cannot create phantom History backlog.

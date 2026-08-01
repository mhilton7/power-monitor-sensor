# Protected microSD retention and card replacement

The sensor treats microSD history as a durable, acknowledgement-aware queue.
Automatic cleanup never formats a card and never changes device identity,
enrollment, credentials, or server acknowledgement state.

## Recommended policy

New configurations use `continuous_protected` with these defaults:

- measurement retention target: 730 days;
- minimum protected local window: 30 days;
- free-space states: notice 20%, warning 10%, critical 5%, emergency 2%;
- absolute emergency reserve: 512 MiB;
- cleanup target: the larger of 10% free or 1 GiB free;
- event evidence retention: 730 days.

Upgrades preserve the previous behavior. A legacy configuration with retention
enabled migrates to `strict_age`; a legacy configuration with retention disabled
migrates to `disabled`. The server shows the signed effective policy reported by
the sensor until an administrator explicitly changes it.

## Retention modes

- `disabled`: no automatic record or event cleanup. Temporary recovery artifacts
  are still bounded when their state is unambiguous.
- `strict_age`: deletes only closed, valid, server-acknowledged, trusted-time
  segments older than the configured age and outside the minimum local window.
- `continuous_protected`: applies strict-age cleanup normally. At emergency
  pressure it may also reclaim the oldest closed, valid, acknowledged segment
  outside the minimum window. Untrusted-time segments are eligible only during
  this emergency path and never merely because an estimated age was guessed.

The active segment, corrupt or incomplete segments, missing/invalid indexes,
unacknowledged sequences, active cleanup files, and recent minimum-window data
are never eligible. A legitimate full card can therefore remain blocked when
only protected data exists; this is safer than silently deleting unconfirmed
history.

Closed-segment metadata avoids rescanning every retained record on each hourly
evaluation. The cache is accepted only when its CRC envelope, paths, closed
state, file presence, and record/index sizes still match. Every selected
deletion candidate is then fully rescanned and its envelope/index integrity and
sequence bounds are compared with the cached evidence immediately before the
transaction begins.

## Transaction and recovery model

Cleanup is owned by `StorageTask`. For each eligible record/index pair it writes
a CRC-protected cleanup journal, stages both files under the cleanup trash area,
commits the journal, deletes staged files, and verifies reclaimed space. A boot
with a planned transaction reverses unambiguous moves. A committed transaction
finishes deletion. Missing or duplicate copies, a corrupt journal, or an unknown
stage blocks cleanup and preserves all files for manual repair.

Record writes have priority over ordinary cleanup. Before append, the sensor
reserves enough space for the record, index row, journals, and filesystem
overhead. If protected content makes that impossible, the sensor reserves the
sequence as an explicit durable-history gap and reports a critical event instead
of pretending that the interval was stored.

Event evidence has its own monotonic sequence and persisted server acknowledgement
cursor. The server advances that cursor only across contiguous stored event
sequences; event cleanup never depends on measurement acknowledgement.

## Safe replacement

1. In the server dashboard open **Settings → Sensors**, select the sensor's
   storage controls, and review acknowledgement, unsynchronized count, protected
   bytes, and cleanup-recovery state.
2. If unsynchronized readings exist, restore server connectivity and wait for
   the reading acknowledgement to advance. Do not replace the card merely to
   clear a pressure warning.
3. Select **Run safe cleanup** if acknowledged reclaimable data is available.
4. Select **Prepare for removal**, type the exact sensor name, and wait until the
   dashboard reports that the card is unmounted.
5. Power the sensor off. Only then remove the card.
6. Keep the old card unmodified until the replacement is mounted, writable, and
   has stored and synchronized new readings.
7. Insert a FAT32 card prepared according to `MICROSD_FORMAT.md`, then power on.
   The firmware initializes missing directories and starts the next sequence
   above the persisted local/server acknowledgement floor. It does not reset or
   reenroll the sensor.
8. Confirm a fresh heartbeat, a durable interval, and a server acknowledgement.
   Retain or archive the old card according to the site's evidence policy.

Never hot-remove a mounted card. Never use the replacement workflow to format a
production card. Never copy a stale sequence journal from one sensor to another.

## Troubleshooting states

- `notice`, `warning`, `critical`, `emergency`: graduated free-space evidence;
- `cleanup_blocked_unacknowledged`: free space is low but the server has not
  acknowledged the candidate data;
- `cleanup_blocked_untrusted`: strict-age cleanup cannot prove record age;
- `cleanup_recovering`: an interrupted unambiguous transaction is being repaired;
- `read_only` or `full`: new durable intervals cannot currently be committed;
- `failed`: mount, integrity, or journal evidence requires intervention;
- `prepared_for_removal`: the card is intentionally unmounted.

Storage diagnostics and logs redact credentials and contain paths, sequences,
capacity, acknowledgement, eligibility, cleanup result, and gap evidence only.

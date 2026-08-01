# microSD storage lifecycle audit

This audit records the pre-change storage design used by firmware 1.0.8. It
was completed before the acknowledgement-aware circular-storage changes.

## Data path

PZEM samples are validated and accumulated by `IntervalAggregator`. At the
configured durable interval, `AggregationTask` submits an `IntervalRecord` to
`StorageCoordinator`. `StorageTask` assigns the next sequence and appends a
CRC-protected PMR1 JSON envelope to a UTC-day `.pmr` file, appends a CSV index
entry, and atomically replaces `sequence.journal`. `ServerSyncTask` requests
ordered pages through `StorageCoordinator`, submits them to the server, and
persists the server's monotonic acknowledgement in NVS. Retention currently
scans every record in each daily file and directly removes a complete file and
its matching index when every record is time-trusted, the newest sequence is
acknowledged, and the newest timestamp is older than the age cutoff.

## Existing formats and granularity

- Record files: `/POWERMON/records/YYYY/MM/YYYY-MM-DD.pmr`; newline-delimited
  PMR1 CRC envelopes containing one JSON interval record.
- Index files: matching `.idx` paths with
  `sequence,utc_ms,offset,payload_crc` rows.
- Untrusted records: boot-id files below `records/untrusted` and matching
  indexes.
- Event files: UTC-day or untrusted boot-id `.events` files using the same CRC
  envelope. Event sequence was derived from the general write counter and the
  upload cursor existed only in RAM.
- Sequence state: `sequence.journal`, atomically replaced through a temporary
  file; recovery uses the maximum of the journal and scanned record sequence.
- Recovery: scans all record envelopes, repairs a truncated tail through a
  `.repair` copy, and rejects complete corruption.

## Confirmed shortcomings

- Health exposes mounted/writable and a fixed 64 MiB warning value, but no
  graduated pressure state, reclaimability, blocked-cleanup reason, growth
  estimate, or cleanup result.
- Existing deployed sensors default to disabled retention and 365 days.
- `HealthTask` calls the large retention scan directly instead of scheduling
  work owned by `StorageTask`.
- Retention repeatedly scans complete files, has no closed-segment metadata,
  and deletes record/index paths without a recoverable cleanup journal.
- Cleanup is age-only and cannot safely reclaim acknowledged segments before
  the age target under critical pressure.
- Active-day files are not explicitly protected; event and temporary artifact
  retention are not bounded.
- Event acknowledgement is not persisted and the server response does not
  provide a durable contiguous event cursor.
- Append starts without reserving space for the record, index, sequence
  journal, cleanup journal, and FAT overhead.
- A no-space write is treated as a generic storage failure, marks the card
  unwritable after a partial record, and causes the coordinator to remount
  every 30 seconds.
- Cleanup success is not verified against reclaimed capacity and interrupted
  deletion has no deterministic recovery path.
- Card replacement preserves the NVS server acknowledgement, but blank-card
  sequence-floor recovery previously depended on acknowledgement
  classification and had no explicit storage-replacement evidence.

## Safety baseline retained by the implementation

PMR1 CRC validation, immutable server readings, sequence monotonicity, HMAC
authentication, index recovery, atomic configuration, and the rule that only
complete server-acknowledged local data may be automatically removed remain
mandatory. No production card is formatted or filled as part of automated
tests.

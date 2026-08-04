# Storage recovery

The UI keeps a critical warning visible whenever the card is absent, unmounted, read-only, full, or unwritable. Live readings may continue, but bounded RAM is not durable and flash never masquerades as history.

## Missing/reinserted card

Select **Prepare removal**, wait for mounted/writable to clear, then remove only when enclosure access is safe. Insert a FAT32 high-endurance replacement and **Remount**. Firmware initializes `/POWERMON`, validates records, repairs only an incomplete tail, and resumes from the journal. Do not hot-plug a socket in a mains compartment.

## Full/read-only card

Do not repeatedly reboot. Prepare removal, copy the entire card to two locations, verify the copy, then free only server-acknowledged old files or replace the card. Correct write-lock/filesystem faults on a desktop. Retention never deletes unacknowledged or time-untrusted records.

## Interrupted write/index rebuild

Boot trims an incomplete final envelope by copy-and-rename; complete CRC-invalid records are preserved. Use local **Rebuild index** or:

```sh
python tools/repair_sd_index.py /path/to/POWERMON/records/2026/07/2026-07-20.pmr
python tools/repair_sd_index.py /path/to/file.pmr --repair-incomplete-tail
```

The repair flag only accepts a non-newline tail and refuses complete corruption.

The firmware's local health, storage API, and signed heartbeat expose separate
reading-index and event-log integrity fields. The legacy `index_healthy` and
`history_integrity_verified` fields remain compatible and now describe the
reading records/indexes used for server synchronization. The additive fields
are:

- `event_log_healthy` / `event_log_integrity_verified`;
- `event_log_integrity_status`, such as `verified`,
  `event_record_corruption_detected`, or `event_log_open_failed`.

An `event_record_corruption_detected` result does not mean the measurement
backlog is corrupt. Do not format or erase the card. Copy the entire card for
forensics, keep the corrupt event envelope unchanged, and allow normal reading
synchronization to continue. **Rebuild index** repairs only derived reading
indexes transactionally and deliberately does not clear this event-log state.

For example, `server_ack_sequence=5168`, `newest_syncable_sequence=5251`, and
`event_log_healthy=false` means 83 reading sequences remain pending and
protected even though separate event evidence is damaged. The index action
must neither delete those readings nor claim that it repaired the event log.
The observed pre-deployment baseline and its physical-verification boundary are
recorded in `STORAGE_INTEGRITY_BASELINE_2026-08-03.md`.

## Export/backup verification

Export bounded JSON/NDJSON through `/api/v1/readings` by sequence/date. For removed media, copy the entire `POWERMON` tree unchanged and validate all records:

```sh
python tools/decode_sd_logs.py /path/to/backup/POWERMON/records --format ndjson > verified.ndjson
```

The decoder stops on bad prefix, incomplete line, CRC mismatch, or JSON error. Compare file counts and SHA-256 hashes of source/backup. Retain manifest, state, events, and indexes. Keep the old card unchanged until the server has accepted all sequences. Never merge two trees with ordinary file copy.

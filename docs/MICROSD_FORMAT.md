# microSD format

The mandatory FAT32 card is authoritative history. NVS stores identity, secrets, config, cursors, and energy offset. LittleFS is for UI/recovery assets; neither silently replaces the card.

```text
/POWERMON/
  manifest.json
  records/YYYY/MM/YYYY-MM-DD.pmr
  records/untrusted/<boot-id>.pmr
  indexes/YYYY/MM/YYYY-MM-DD.idx
  indexes/untrusted/<boot-id>.idx
  events/YYYY/MM/YYYY-MM-DD.pme
  events/untrusted/<boot-id>.pme
  state/sequence.journal
  exports/
  recovery/
```

Each record/event line is `PMR1<TAB><compact UTF-8 JSON><TAB><8-hex CRC32><LF>`. CRC covers JSON bytes. Index lines are `sequence,start_utc_ms,file_offset,payload_crc32`. The journal flushes only after record/index durability; boot recovery uses the maximum valid record/journal so sequences are never reused.

Writes are append-only and serialized. Records carry raw endpoints, normalized lifetime/interval energy and method, statistics, quality, boot/firmware/CT identity, UTC trust, and monotonic boundaries. Untrusted-time records remain under `untrusted/` and retention never deletes them.

Boot replaces an incomplete tail with a verified valid-prefix copy. Complete corrupt records remain and surface a fault. Indexes rebuild from record envelopes. Retention removes only complete, trusted, expired daily files whose highest sequence is server-acknowledged.

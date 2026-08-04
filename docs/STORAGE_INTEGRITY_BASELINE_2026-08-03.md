# Live storage-integrity baseline — 2026-08-03

This is a sanitized pre-deployment observation, not acceptance evidence for the
candidate firmware.

- sensor: `Indoor-AC`;
- running firmware: `1.0.15`;
- boot ID prefix: `e76ecc05…`;
- Wi-Fi, time, microSD mount/write, and PZEM checks: healthy;
- legacy `storage_index_healthy`: `false`;
- server acknowledgement: sequence `5168`;
- durable reading backlog: `99` and growing;
- queue/pool drops: none observed;
- TLS transaction: locally blocked at the observation point.

An earlier snapshot of the same boot showed newest sequence `5251`, giving 83
unacknowledged readings. The later backlog of 99 confirms that readings
continued to be written while the legacy combined integrity Boolean remained
false. This is consistent with the retained
`event_record_corruption_detected` evidence: the event fault was being folded
into `index_healthy`, even though reading history remained mounted, writable,
and sequenced.

The candidate changes do not erase or format this card. They publish
reading/index and event-log integrity separately, leave the corrupt event
envelope untouched, and protect every reading above the verified server
acknowledgement. A reading-index rebuild stages, reads back, swaps, and verifies
only derived `.idx` files; it cannot clear the separate event fault. Physical
acceptance still requires deploying the candidate and confirming backlog drain,
the additive heartbeat/local-health fields, and continued absence of drops.

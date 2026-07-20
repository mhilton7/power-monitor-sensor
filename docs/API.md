# API and protocol

The compatibility ID is exactly `pm-protocol/1.0.0`. Additive optional fields are allowed; changing/removing a field requires a version bump. Unknown fields are ignored, missing required fields get typed errors, UUIDs are lowercase, and UTC JSON timestamps use ISO 8601 `Z`. The device stores measurements and energy, never tariffs, currency, bills, or alerts.

Machine contracts are `shared/openapi/device-api.yaml`, `shared/openapi/server-ingest-api.yaml`, and `shared/schemas/`.

## Device API

Reads: `GET /api/v1/health`, `/info`, `/live`, `/readings`, `/events`, `/storage`, `/sync-status`, `/config`, `/metrics`, and `/diagnostics/bundle`. Readings accept `after_sequence`, `from_utc`, `to_utc`, and bounded `limit`; `Accept: application/x-ndjson` returns one record per line. An expired cursor returns 410 with the retained range.

Mutations: `PUT /api/v1/config`, `POST /api/v1/sync/ack`, `/setup/apply`, `/ota/apply`, and `/actions/{test-pzem,test-sd,remount-sd,rebuild-index,prepare-card-removal,test-dns,test-ntp,test-server-tls,test-heartbeat,reboot,network-reset,factory-reset,rollback-ota}`. Long work uses a bounded maintenance queue. Destructive actions require exact `X-PM-Action-Token` phrases.

Browser sessions use a random short-lived `HttpOnly; SameSite=Strict` cookie plus `X-PM-CSRF`; origin checks and login throttling apply. The local UI is HTTP, so its cookie does not claim `Secure`. Do not expose it to the public Internet; use a trusted LAN/VLAN or private VPN.

## HMAC authentication

Enrolled requests carry `X-PM-Protocol`, `X-PM-Device-ID`, `X-PM-Timestamp`, `X-PM-Nonce`, `X-PM-Content-SHA256`, and `X-PM-Signature`. Canonical UTF-8 is:

```text
PM-HMAC-SHA256-V1
UPPERCASE_METHOD
/percent-encoded/path?sorted=percent-encoded-query
unix_timestamp_seconds
32-byte-lowercase-hex-nonce
lowercase_body_sha256
```

Query pairs use RFC 3986 unreserved encoding, sort by encoded key/value, and retain duplicates. Signature is lowercase hex HMAC-SHA256. The timestamp window is 300 seconds and nonces cannot replay. Executable examples are in `shared/fixtures/auth-vectors.json`.

```sh
curl -H 'X-PM-Protocol: pm-protocol/1.0.0' \
  -H 'X-PM-Device-ID: 00000000-0000-4000-8000-000000000000' \
  -H 'X-PM-Timestamp: 1700000000' \
  -H 'X-PM-Nonce: <32-byte-hex>' \
  -H 'X-PM-Content-SHA256: <sha256>' \
  -H 'X-PM-Signature: <hmac>' \
  'http://power-monitor-xxxxxx.local/api/v1/readings?after_sequence=100&limit=50'
```

## Server-facing API

Outbound endpoints: enrollment claim, `POST /api/v1/device-heartbeats`, `/device-readings/batch`, `/device-events/batch`, `/device-config/report`; authenticated `GET /api/v1/device-config/effective` and `/device-firmware/manifest`. HTTPS CA or fingerprint validation is mandatory. Sequence batches are idempotent: identical retransmission succeeds, conflicting content is 409, and acknowledgement advances only through contiguous sequences.

Errors use `application/problem+json` with RFC 9457 `type`, `title`, `status`, `detail`, `instance`, and optional `code`. Treat 409/422 as protocol/config faults; network/5xx failures retry with bounded exponential backoff plus jitter. Different protocol IDs are explicitly rejected.

# API and protocol

The compatibility ID is exactly `pm-protocol/1.0.0`. Additive optional fields are allowed; changing/removing a field requires a version bump. Unknown fields are ignored, missing required fields get typed errors, UUIDs are lowercase, and UTC JSON timestamps use ISO 8601 `Z`. The device stores measurements and energy, never tariffs, currency, bills, or alerts.

Machine contracts are `shared/openapi/device-api.yaml`, `shared/openapi/server-ingest-api.yaml`, and `shared/schemas/`.

## Device API

Reads: `GET /api/v1/health`, `/info`, `/live`, `/readings`, `/events`, `/storage`, `/sync-status`, `/config`, `/metrics`, `/ota/status`, `/diagnostics/bundle`, `/ui/status`, `/ui/diagnostics`, and HMAC-only `/data-reset/status`. The compact `/ui/status` route is the only automatic browser poll; it uses in-memory snapshots and never scans storage, contacts the central server, or exposes configuration secrets. `/ui/diagnostics` is loaded only on demand. Readings accept `after_sequence`, `from_utc`, `to_utc`, and bounded `limit`; `Accept: application/x-ndjson` returns one bounded page with one durable record per line. The JSON history response retains the durable `records` array and also supplies translated `readings` and `events` arrays. The `readings` entries use the shared pm-protocol/1.0.0 server field names, so a v1 pull client does not have to understand the on-card representation. An expired cursor returns 410 with the retained range. General authenticated traffic has a burst ceiling, and expensive history reads have a separate rate limit.

Mutations: `PUT /api/v1/config`, `PUT /api/v1/network-settings`, `POST /api/v1/sync/ack`, `/setup/apply`, `/enrollment/reenroll`, `/ota/apply`, `/data-reset/{prepare,commit,cancel}`, and `/actions/{test-pzem,test-sd,remount-sd,rebuild-index,prepare-card-removal,test-dns,test-ntp,test-server-tls,test-heartbeat,reboot,network-reset,factory-reset,rollback-ota}`. Long work uses a bounded worker or maintenance queue.

`GET /api/v1/ota/status` exposes bounded, non-secret v2 state: protocol and
authentication mode, target deployment/release/version/hash, progress and byte
count, running/next partition, pending verification, last result/failure, and
rollback evidence. It never includes the enrollment secret, derived manifest
key, request signatures, or canonical key material. Local `/ota/apply` and
rollback remain elevated maintenance actions; normal installation is initiated
from the central server, not by uploading a binary to this HTTP UI.

For backward compatibility, `/readings`, `/events`, configuration, network settings, setup, acknowledgement, and reenrollment return their final HTTP 200 response when `Prefer` is omitted. AsyncTCP remains nonblocking while the response waits on the bounded worker. A caller that sends `Prefer: respond-async` receives HTTP 202 plus an opaque job ID and polls `/api/v1/history-jobs` or `/api/v1/auth/password-jobs`. The embedded UI opts into this polling behavior. Password login always uses the password-job flow.

Password-job authorization depends on the operation that created the job. A login request requires an exact same-origin non-privileged session and CSRF token; its result is bound to that creator session and cannot elevate a different session even if its opaque identifier is disclosed. Configuration, setup, network-settings, and local reenrollment results require a local session or device HMAC as applicable to the initiating operation. A synchronization acknowledgement result is HMAC-only.

`POST /api/v1/sync/ack` is HMAC-only and accepts exactly one of `ack_sequence` or the server compatibility alias `highest_contiguous_sequence`. Reenrollment requires the exact `X-PM-Action-Token: REENROLL` header, revokes the old device credential locally after persistence succeeds, and consumes a new single-use token through the normal TLS enrollment flow. Only a local browser session may request asynchronous reenrollment; an HMAC caller must omit `Prefer: respond-async` because its credential is no longer valid for a later result poll.

### Coordinated data-only reset

Firmware 1.0.18 advertises the additive capability `data-reset/1.0.0`. The central server coordinates the HMAC-only `POST /api/v1/data-reset/prepare`, `POST /api/v1/data-reset/commit`, `GET /api/v1/data-reset/status?operation_id=<uuid>&target_generation=<n>`, and `POST /api/v1/data-reset/cancel` routes. These routes use the existing six `X-PM-*` signed headers; local sessions and CSRF credentials cannot authorize them.

Prepare freezes configuration, enrollment, administrator/network/factory reset, desired-configuration apply, retention deletion, and OTA; it also gates reading aggregation and upload while allowing safe heartbeat, event, and diagnostic traffic. The storage task drains existing writes before the sensor captures card, sequence, PZEM, build, boot, and keyed configuration-preservation evidence. The returned canonical receipt and its HMAC digest expose only bounded cumulative-energy baseline scalars—never interval readings, credentials, or other secrets. Authenticated `GET /api/v1/storage` supplies exact read-only planning evidence including local record count, card identity/generation, data generation, sequence floor, and next sequence.

Commit accepts only the exact prepared operation and approved monotonic boundary. It durably records `commit_authorized` before the checkpoints `sequence_advanced`, `cursors_advanced`, `readings_cleared`, `baseline_installed`, `verified`, and `completed`. Only positively classified reading records, indexes, exports, and reading metadata are removed; events, configuration, credentials, OTA evidence, the card identity, and unrelated diagnostic artifacts are preserved. Unknown or corrupt artifacts inside the reset-managed reading, index, export, metadata, and retention-trash paths fail closed. The physical PZEM counter is never reset; application energy is re-baselined in software.

Identical prepare and commit retries are idempotent, and boot recovery resumes the first incomplete durable checkpoint while keeping reading gates closed. A durable completion is exposed as `completed` only after the configuration freeze, storage-write gate, and reset-admission gate are observably open; status and mutation replay remain HTTP 202 at `verified` while that reversible release is pending. Cancel is allowed only before `commit_authorized` and restores normal work without changing records, cursors, generation, sequence, or the energy baseline; a durable cancellation likewise remains HTTP 202/`attention_required` until every gate reopens. Every new durable reading, wire reading, reading-batch root, and heartbeat carries additive `data_generation`; generation zero identifies devices that have never completed this reset.

Configuration schema 1 includes display identity and mirrored site/circuit role, DHCP or static IPv4, server TLS trust and host allowlist, connection mode, live/heartbeat/sync/meter/log intervals, CT rating and threshold fractions, voltage/frequency limits, NTP/timezone, SD warning/retention policy, local session duration, signed-OTA channel/window, and diagnostic level. The `pm-protocol/1.0.0` field retains the `pull`, `push`, and `hybrid` values, but current firmware accepts only `push`; `pull` and `hybrid` fail closed with `connection_mode_unsupported` because the port-80 local API is not a mutually authenticated HTTPS server. Secret fields are write-only. `PUT /api/v1/network-settings` preserves the saved Wi-Fi password and TLS trust by default, requires explicit replacement actions for either secret, commits the network/server group atomically, and requests a live network reconfiguration without an intervening reboot.

`PUT /api/v1/config` may update ordinary runtime fields but rejects changes to
Wi-Fi, static IPv4, server URL, TLS trust, server allowlist, or connection
mode with `network_settings_route_required`. This prevents the generic
redacted configuration document from changing an SSID without its write-only
password or replacing server identity without the explicit trust action.

The embedded browser UI creates a random short-lived **non-privileged** session automatically through `/api/v1/auth/session`; no login screen is displayed. Factory reset, network reset, reenrollment, OTA apply/rollback, configuration changes, and Wi-Fi/TLS credential replacement require an elevated local session. The UI asks for the administrator password only when one of those actions is requested, submits it to the existing bounded asynchronous `/api/v1/auth/login` verifier, clears the input immediately, and continues only if the returned session is elevated. Before an administrator exists, that verifier accepts the physical setup-AP password.

Sessions use an `HttpOnly; SameSite=Strict` cookie plus `X-PM-CSRF`. Every browser mutation must also carry an `Origin` exactly matching the addressed sensor authority; a missing, `null`, or different Origin is rejected. HMAC-authenticated non-browser clients may omit Origin. Supported PowerShell and Python provisioning tools set the matching Origin explicitly. The local UI is HTTP, so its cookie does not claim `Secure`. Do not expose it to the public Internet; use a trusted LAN/VLAN or private VPN.

First-run setup is crash-atomic across the dual-slot config record and the
default-NVS enrollment/admin verifier keys. Before any credential changes, the
firmware writes and verifies a CRC-protected rollback journal in the dedicated
configuration partition. Journal removal is the commit point. A reset at any
earlier instruction restores the previous credential snapshots and, when
needed, rolls the active config marker back to the recorded generation before
the device decides whether setup is complete.

The UI displays an accessible global notification when a local action or form
submission is sent, accepted, rejected, or cancelled. A `queued` notification
means the bounded device queue accepted the request; it does not claim that
background maintenance has already completed.

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

Query pairs use RFC 3986 unreserved encoding, sort by encoded key/value, and retain duplicates. Signature is lowercase hex HMAC-SHA256. Timestamp parsing rejects signed-integer overflow and the 300-second comparison avoids arithmetic overflow at both integer extremes.

The in-memory replay window holds 256 accepted nonce digests for the full 300
seconds measured from acceptance and never evicts a live entry. If more than
256 valid signed requests arrive inside that window, additional requests fail
with HTTP 429 `nonce_window_capacity_exceeded` until an entry expires. This is
an explicit signed-request rate guarantee, not a best-effort ring.

`pm-protocol/1.0.0` does not bind a server request to the device boot ID and has
no server nonce-reservation exchange. Consequently, a hard reboot clears the
RAM replay window and a captured request whose timestamp is still valid could
be replayed once after that reboot. Eliminating that cross-boot window requires
a protocol revision with boot-bound signatures or coordinated durable server
state. Firmware intentionally does not write every nonce to flash because that
would create unbounded wear. Executable examples are in
`shared/fixtures/auth-vectors.json`.

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

Outbound endpoints include enrollment claim,
`POST /api/v1/device-heartbeats`, `/device-readings/batch`, `/device-events/batch`,
`/device-config/report`, and `/device-firmware/report`; authenticated reads use
`GET /api/v1/device-config/effective`, `/device-firmware/manifest`, and the
manifest's same-origin relative firmware download path. Enrollment returns HTTP
201 and a URL-safe secret that is stored exactly as returned. Heartbeats use
`heartbeat/1.0.0`, reading batches use `reading-batch/1.0.0`, and configuration
reports carry the server configuration version independently of the sensor's
local configuration revision.

OTA v2 capability is reported at enrollment and in signed heartbeats as
`supported`, `protocol_version: 2`,
`authentication_mode: existing_device_hmac`, `rollback_supported`, and the
runtime update-partition size. The available `pm-ota-manifest/2` response is
canonical-HMAC authenticated for the exact device and attempt. The sensor
rejects cross-device, modified, future/expired, incompatible, replayed,
same-version, unauthorized-downgrade, wrong-origin, wrong-size, or wrong-hash
updates. Milestone reports are attempt-aware and idempotent; download and
partition write are not equivalent to server-confirmed completion. See
[OTA](OTA.md).

HTTPS public-CA and hostname validation are mandatory; current firmware rejects
fingerprint-only operation because the ESP32 client cannot safely pin before an
authenticated handshake. Sequence batches are idempotent: identical
retransmission succeeds, conflicting content is 409, and acknowledgement
advances only through contiguous sequences. Durable values outside the shared
0–400 V, 40–70 Hz, or 0–1 power-factor domains are sent as null measurements
with a gap/range quality flag so one bad interval cannot block the contiguous
cursor. Retained startup intervals that lack trustworthy UTC bounds remain
immutable on the card but are omitted from server batches;
`oldest_syncable_sequence` lets the server close that exact unsyncable prefix
without fabricating timestamps.

Errors use `application/problem+json` with RFC 9457 `type`, `title`, `status`, `detail`, `instance`, and optional `code`. Treat 409/422 as protocol/config faults; network/5xx failures retry with bounded exponential backoff plus jitter. Different protocol IDs are explicitly rejected.

Retained records without trustworthy UTC intervals remain immutable on the
card and are never submitted as fabricated history. The optional,
HMAC-signed `unavailable_sequence_ranges` field reports exact unsyncable
prefix or interspersed sequences. Synchronization covers at most 500 sequence
positions per batch and SD scans yield cooperatively so recovery work cannot
starve the meter and aggregation tasks.

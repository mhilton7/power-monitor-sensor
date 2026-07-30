# Server enrollment

Enrollment is an outbound HTTPS claim to `POST /api/v1/device-enrollment/claim`. It carries `protocol_version: pm-protocol/1.0.0`, a one-time `token`, privacy-preserving `hardware_id`, requested name, hardware target, PZEM model, mandatory-microSD state, and supported local endpoints. The token expires after success.

The server returns HTTP 201 with a lowercase device UUID, a high-entropy URL-safe enrollment secret, effective metadata, heartbeat/synchronization policy, and an optional OTA signing public key. The current server secret is stored exactly as returned; it is not base64-decoded. The sensor stores these values in NVS, clears the token, and derives separate RFC 5869 HKDF-SHA256 keys using `pm-device-to-server-v1` and `pm-server-to-device-v1`.

The sibling server currently returns `server_ota_signing_public_key: null`. This does not block enrollment, heartbeats, or data synchronization, but OTA remains fail-closed until an administrator provisions the independently verified Ed25519 public PEM and its signing-key ID through the sensor’s local setup/network-settings workflow. The available firmware response must also include the signed `release_notes` field; the current sibling implementation omits it and therefore cannot yet produce a verifiable device manifest.

The current sibling server has one unresolved recovery boundary: it commits the
new credential and consumes the one-time token before the HTTP 201 response
reaches the sensor. If that response is lost, the sensor correctly retains no
unknown secret, but a retry receives `hardware_exists` and cannot reconstruct
the committed secret. Firmware must not treat that response as enrollment
success. The required server/API repair is an idempotent claim operation: add a
client claim/idempotency identifier, bind it to the token and hardware ID, and
persist the complete successful response in the same transaction as token
consumption. An exact retry of that claim must return the same HTTP 201
credential response; a different token, hardware ID, or payload must still be
rejected. This preserves the normal one-time-token happy path without adding a
sensor-side bypass.

Heartbeats use `heartbeat/1.0.0`; durable uploads use `reading-batch/1.0.0`. The firmware translates immutable local SD records into the server wire shape without changing stored history, sequence numbers, or deduplication semantics. `oldest_stored_sequence` describes all retained local evidence, while the backward-compatible optional `oldest_syncable_sequence` identifies the first retained interval with trustworthy UTC bounds. Startup intervals without trustworthy time remain on the card but are not submitted as timestamped server history; the server records their prefix as permanent loss before advancing the contiguous cursor.

Secrets/keys are never exposed by reads or diagnostics. Re-enrollment requires the authenticated explicit reenrollment workflow or a factory reset, plus a new token; copying a flash image is not supported identity cloning. Revoke the old server identity after board replacement or suspected compromise.

When startup records without trustworthy UTC time are interspersed with
syncable readings, the sensor adds HMAC-signed
`unavailable_sequence_ranges` to the normal reading batch. The server records
only those exact sequences as permanent loss and advances its cursor across
their union with committed readings. No timestamp or historical reading is
invented.

The simulator implements the same flow in volatile memory. It is validation infrastructure, not a fleet server.

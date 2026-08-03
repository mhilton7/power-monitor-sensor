# Server enrollment

Enrollment is an outbound HTTPS claim to
`POST /api/v1/device-enrollment/claim`. It carries
`protocol_version: pm-protocol/1.0.0`, a one-time token,
privacy-preserving hardware identity, requested name, hardware target, PZEM
model, mandatory-microSD state, supported local endpoints, and capabilities.
The token expires after its successful single use.

The server returns HTTP 201 with a lower-case device UUID, a high-entropy
URL-safe enrollment secret, effective metadata, and heartbeat/synchronization
policy. The secret is stored exactly as returned; it is not base64-decoded. The
sensor commits the UUID and secret atomically to NVS, clears the token, and
derives separate RFC 5869 HKDF-SHA256 request keys using
`pm-device-to-server-v1` and `pm-server-to-device-v1`.

OTA manifest protocol v2 reuses this enrollment trust without re-enrollment.
Both peers independently derive another 32-byte HKDF-SHA256 key from the same
secret, with the lower-case hyphenated device UUID encoded as UTF-8 salt and
the exact info string `pm-ota-manifest-v2/server-to-device`. The derived key is
not stored, transmitted, logged, or returned to a browser. Enrollment and each
signed heartbeat report OTA support, protocol version, authentication mode,
rollback support, and actual inactive-partition size. An absent legacy
`server_ota_signing_public_key` does not block v2 OTA and does not require a
local public-key paste.

Older firmware that does not report protocol v2 must be shown as requiring a
one-time non-erasing USB bootstrap. Writing the verified application image at
`0x20000` without `erase_flash` preserves NVS, Wi-Fi, device UUID/secret, public
CA, microSD history, and sequence state. A bootstrap does not consume a new
token and must not silently create another identity. See [OTA](OTA.md).

The claim response crosses an unavoidable delivery boundary: the server may
commit the credential and consume the token before HTTP 201 reaches the sensor.
The sensor must never treat a lost response as enrollment success and must
never invent or log an unknown secret. A server that supports idempotent claim
recovery binds a client claim identifier to the exact token, hardware identity,
and payload, persists the successful response in the same transaction, and
returns that same response only for an exact retry. A mismatched retry remains
rejected.

Heartbeats use `heartbeat/1.0.0`; durable uploads use
`reading-batch/1.0.0`. Firmware translates immutable local SD records into the
server wire shape without changing stored history, sequence numbers, or
deduplication semantics. `oldest_stored_sequence` describes all retained local
evidence, while optional `oldest_syncable_sequence` identifies the first
retained interval with trustworthy UTC bounds. Startup intervals without
trustworthy time remain on the card but are not submitted as timestamped
history; the server records their exact prefix as permanent loss before
advancing the contiguous cursor.

When unsyncable intervals are interspersed with valid history, the sensor adds
HMAC-signed `unavailable_sequence_ranges` to the normal reading batch. The
server records only those exact sequences as permanent loss and advances its
cursor across their union with committed readings. No timestamp or historical
reading is fabricated.

Secrets and keys are never exposed by reads or diagnostics. Re-enrollment
requires the authenticated explicit reenrollment workflow or a factory reset
plus a new token; copying a flash image is not supported identity cloning.
Revoke the old server identity after board replacement or suspected compromise.

The simulator implements the same flow in volatile memory. It is validation
infrastructure, not a fleet server.

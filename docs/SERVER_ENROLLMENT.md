# Server enrollment

Enrollment is an outbound HTTPS claim to `POST /api/v1/device-enrollment/claim`. It carries `protocol_version: pm-protocol/1.0.0`, a one-time `token`, privacy-preserving `hardware_id`, requested name, hardware target, PZEM model, mandatory-microSD state, and supported local endpoints. The token expires after success.

The server returns HTTP 201 with a lowercase device UUID, a high-entropy URL-safe enrollment secret, effective metadata, heartbeat/synchronization policy, and an optional OTA signing public key. The current server secret is stored exactly as returned; it is not base64-decoded. The sensor stores these values in NVS, clears the token, and derives separate RFC 5869 HKDF-SHA256 keys using `pm-device-to-server-v1` and `pm-server-to-device-v1`.

Heartbeats use `heartbeat/1.0.0`; durable uploads use `reading-batch/1.0.0`. The firmware translates immutable local SD records into the server wire shape without changing stored history, sequence numbers, or deduplication semantics.

Secrets/keys are never exposed by reads or diagnostics. Re-enrollment requires explicit factory reset and a new token; copying a flash image is not supported identity cloning. Revoke the old server identity after board replacement or suspected compromise.

The simulator implements the same flow in volatile memory. It is validation infrastructure, not a fleet server.

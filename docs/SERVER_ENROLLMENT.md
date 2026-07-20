# Server enrollment

Enrollment is an outbound HTTPS claim to `POST /api/v1/device-enrollment/claim`. It carries `pm-protocol/1.0.0`, a one-time token, local UUID, privacy-preserving hardware ID, friendly name, firmware/hardware target, and capabilities. The token expires after success.

The server returns a lowercase device UUID, at least 32 random secret bytes in base64, current policy, and the P-256 OTA public key. The sensor stores these in NVS, clears the token, and derives separate RFC 5869 HKDF-SHA256 keys using `pm-device-to-server-v1` and `pm-server-to-device-v1`.

Secrets/keys are never exposed by reads or diagnostics. Re-enrollment requires explicit factory reset and a new token; copying a flash image is not supported identity cloning. Revoke the old server identity after board replacement or suspected compromise.

The simulator implements the same flow in volatile memory. It is validation infrastructure, not a fleet server.

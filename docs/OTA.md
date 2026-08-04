# Existing-trust central-server OTA

Firmware 1.0.12 implements `pm-ota-manifest/2`, a device-authenticated HMAC OTA
flow that reuses trust already established during enrollment. The ordinary
administrator workflow is one file: select `firmware.bin` in the central Power
Monitor dashboard, review the server's parsed metadata, and install it on an
explicitly selected sensor. The sensor's local WebUI reports status only; it is
not a second firmware uploader.

## Security boundaries

The protections remain independent:

- validated HTTPS authenticates the configured server hostname and protects the
  manifest and binary in transit;
- the normal device request HMAC authenticates manifest, download, and report
  requests to the server;
- a device-specific OTA manifest HMAC authenticates the release instructions;
  and
- streaming SHA-256 plus exact byte count proves the inactive partition received
  the binary named by the authenticated manifest.

The input key material is the existing enrollment secret. Both server and
sensor derive a transient 32-byte key with HKDF-SHA256:

```text
salt = lower-case hyphenated device UUID encoded as UTF-8
info = pm-ota-manifest-v2/server-to-device
length = 32 bytes
```

The raw enrollment secret is not used directly for the manifest. The derived
key is never persisted, returned, logged, or placed in a diagnostic bundle and
is wiped after use. It is distinct from both ordinary request-signing
directions. The normative Python/C++ vector is
`shared/auth-test-vectors/ota-manifest-v2.json`.

The sensor continues to require its configured public CA and hostname/SNI.
Production code never calls `setInsecure()`. Existing-trust OTA neither reads
nor requires `cert.key`, `root.key`, `tls.key`, a Caddy private key, a new OTA
certificate, an Ed25519 private-key file, or a browser-supplied hash. Historical
Ed25519 releases may remain identifiable as legacy evidence, but that workflow
is not required or the default for v2-capable sensors.

## Authenticated manifest

The sensor polls the configured server's HMAC-authenticated
`GET /api/v1/device-firmware/manifest`. No eligible deployment returns
`available: false`. An available `pm-ota-manifest/2` binds the deployment,
release, device UUID, semantic version, project, hardware target, protocol
range, byte size, lowercase SHA-256, build hash, validity window, downgrade
policy, attempt, HMAC algorithm/context, and same-origin relative download path.

HMAC-SHA256 covers every field except `manifest_hmac`. Canonical JSON is UTF-8,
uses sorted keys and no insignificant whitespace, has stable JSON number/
Boolean representation, and rejects duplicate or unexpected fields. The HMAC
is base64url without padding and is compared in constant time. A manifest for
one sensor therefore fails on every other sensor even when both target the same
binary.

The sensor rejects a missing/invalid HMAC, cross-device manifest, replayed or
stale attempt, untrusted time, future/expired validity window, wrong project,
wrong ESP32-S3 target, incompatible `pm-protocol/1.0.0` range, same version,
unauthorized downgrade, unavailable partition, oversize image, non-relative or
cross-origin download path, and inconsistent release metadata.

## Install, confirmation, and rollback

One serialized high-memory lease protects TLS/OTA work from overlapping
diagnostics, exports, password work, or other large operations. If safe memory
is temporarily unavailable, OTA waits and reports that state; it does not
weaken TLS or mark the server offline. The image is streamed directly to the
inactive 6 MiB application partition while counting bytes and calculating
SHA-256. The implementation checks exact `Content-Length`, rejects truncation
and extra bytes, validates the ESP application descriptor/project/version/build
and protocol marker, and calls final partition activation only after every check
passes.

Persistent recovery state records deployment/release IDs, attempt, target hash
and version, prior firmware identity, state, failure code, and an unsigned
per-attempt `evidence_sequence`. The sequence resets only for a genuinely new
attempt, increments in the same atomic commit as each durable evidence
transition, never wraps, and is repeated unchanged for network retries. It is
also sent in signed heartbeat `resources.ota_recovery` evidence alongside the
matching deployment ID and attempt, so the server can reject stale same-boot
reports without mixing attempts. The record contains no secret. Every state
change uses atomic commit, typed result handling, immediate
readback, and full-record identity comparison. The device does not select or
reboot into a candidate unless the final `rebooting` record is durably readable
and exactly matches the intended deployment, release, attempt, image identity,
byte count, partition-written state, and pending-reboot flag. Progress reports
are request-HMAC authenticated and attempt-aware.
Expected states include manifest authentication, the distinct optional
`waiting_for_schedule` state, download, binary verification, partition write,
reboot, post-boot validation, success, failure, rollback detection, and rollback
completion. A successful report leaves the report queue pending while any later
durable milestone remains, so a reboot or network outage cannot silently skip
intermediate evidence.

After `Update.end(true)`, the firmware verifies the selected boot partition's
address, label, application type/subtype, capacity, non-running identity, ESP-IDF
OTA state, project, version, and build hash against both the intended partition
and authenticated manifest. A failure restores the original running boot
partition, persists the exact primary/restore outcome, exposes recovery status,
and does not blindly restart.

The pending image is not accepted merely because it boots. Before production
services start, a PENDING_VERIFY image with missing/corrupt recovery evidence or
a target version/build mismatch requests ESP-IDF rollback. A non-rebooting
rollback failure remains fail closed and never falls through into the normal
runtime. It enters a restricted local recovery surface with network, Web UI,
authenticated diagnostics/configuration, OTA rollback/update maintenance, and
serial access only. No meter, aggregation, microSD record/retention, server-sync,
or healthy-boot task is created. Failure evidence is committed and read back
through an independent atomic incident journal because an unreadable OTA record
does not provide a trustworthy deployment ID to report; the implementation
never fabricates that identity. `/api/v1/ota/status` reports both the restricted
mode and whether the independent incident is durable and pending operator
reporting. On the two-slot layout, a restricted candidate cannot install over
the other slot while ESP-IDF says rollback remains possible; the operator must
rollback first so the last known-good image is not destroyed. Authenticated
verified OTA remains available if no rollback image exists. Network and Web UI
availability are reported only after network initialization, while the serial
recovery surface remains available independently. A watchdog-safe
30–60 second local observation window checks running-image identity, task
progress, heap integrity, and required local initialization before marking the
image valid. microSD recovery, a successful PZEM poll, and network-subsystem
initialization remain retryable local gates through the 60-second deadline. If
one remains unavailable, the candidate is left unvalidated with a typed local
blocker and the recovery UI available; firmware does not reboot or request
rollback for that blocker. Wi-Fi, DNS, time synchronization, and server
reachability are external/degraded evidence that cannot reject an otherwise
locally healthy image. A fatal local runtime failure requests typed ESP-IDF
rollback; if rollback marking fails, firmware reports that exact state and does
not issue an unverified restart. The server
calls an installation complete only after the target version/build is reported
on one boot through its healthy-heartbeat window and a durable reading succeeds
without a critical alert or rollback.

OTA writes only the inactive application partition and its small recovery
journal. It does not erase NVS, overwrite the Wi-Fi configuration, enrollment
UUID/secret, CA trust, local administrator verifier, microSD history, or
sequence/cursor state.

## Capability and one-time bootstrap

Enrollment and signed heartbeats report:

```json
{
  "ota": {
    "supported": true,
    "protocol_version": 2,
    "authentication_mode": "existing_device_hmac",
    "rollback_supported": true,
    "partition_size_bytes": 6291456
  }
}
```

Firmware that does not contain protocol v2 cannot install v2 through that
missing implementation. The server must report **One-time bootstrap required**
rather than pretending OTA is ready. Download the server-verified bootstrap
`firmware.bin`, independently compare its displayed SHA-256, disconnect all
mains/PZEM wiring, and use the exact non-erasing command displayed by the
readiness API. The application-only form is:

```powershell
python -m esptool --chip esp32s3 --port COM5 write_flash 0x20000 firmware.bin
```

Use the actual port and generated filename. Never add `erase_flash` and never
flash a merged image for this migration. Writing only the application offset
preserves NVS, Wi-Fi, enrollment, CA trust, microSD data, and sequence state; it
does not require re-enrollment. After reboot, verify firmware 1.0.16 (or the
actual generated version), an authenticated heartbeat, OTA protocol 2,
`existing_device_hmac`, and the expected partition size. Future releases can
then be installed from the central dashboard.

## Physical validation boundary

Native, simulated, contract, and release builds prove deterministic software
behavior, not a physical update. A physical pass requires an actual enrolled
ESP32-S3 on low-voltage USB, the production CA/hostname, a real install into the
inactive slot, post-boot heartbeat confirmation, configuration/microSD/sequence
checks, an induced failure demonstrating automatic rollback, and a sustained
memory/network observation. Never claim those results when no device was
connected.

The exact Phase 4 state machine, fault boundaries, and acceptance evidence are
documented in [OTA_PHASE4_FAIL_CLOSED.md](OTA_PHASE4_FAIL_CLOSED.md).

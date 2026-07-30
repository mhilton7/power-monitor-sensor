# Wi-Fi and configuration persistence

The authoritative Wi-Fi/server configuration is the firmware's own atomic
NVS record. Arduino Wi-Fi credential persistence is disabled with
`WiFi.persistent(false)`, and automatic reconnect is disabled so the firmware
state machine owns every attempt. `WiFi.begin()` receives the verified
in-memory SSID/password pair loaded by `ConfigService`.

## Storage layout

The 16 MB partition table reserves a dedicated `data/nvs` partition:

```text
0x009000..0x010FFF  nvs       0x8000  preserved legacy/framework state
0x011000..0x012FFF  otadata   0x2000  OTA selection metadata
0x013000..0x013FFF  phy_init  0x1000  radio calibration data
0x014000..0x01FFFF  pmconfig  0xC000  atomic configuration/identity
0x020000..            ota_0            first application slot
```

The `pmconfig` namespace is `pm-state`.

The previous partition table kept legacy NVS through `0x10FFF`, but the
Arduino PlatformIO integration normally hard-codes `boot_app0.bin` at
`0xE000`. A normal upload therefore overwrote part of NVS before firmware
could load it. Shrinking NVS is not a safe migration: the Arduino core
initializes default NVS before `setup()` and may erase a layout it considers
incompatible.

This release preserves the complete legacy NVS address range and places
OTA-data at `0x11000`. The post-build
`tools/relocate_ota_selector.py` hook rewrites both PlatformIO's extra-image
metadata and the already-flattened executable uploader flags, then fails the
build unless exactly one `boot_app0.bin` entry resolves to `0x11000`.
`tools/check_repo.py` verifies the partition and upload-hook agreement. The
dedicated `pmconfig` partition then occupies the remaining space before the
fixed `ota_0` offset.

Configuration uses:

```text
cfg_a
cfg_b
cfg_active
```

Enrollment identity uses a separate pair in the same dedicated namespace:

```text
enroll_a
enroll_b
enroll_active
```

The ordinary `nvs` partition retains bounded operational state and legacy
`pm-agent` keys needed for one-time migration, local password hashes/salts,
boot-health counters, cursors, and the pending one-time enrollment token.
Those keys are not a second source of truth for Wi-Fi/server settings after
migration.

The configuration payload has `persistence_format: 1` and contains schema-1
runtime configuration, the complete Wi-Fi password, public server CA PEM, and
a legacy read-only fingerprint metadata field. A configured server URL always
requires the CA PEM; fingerprint-only TLS is rejected. Secret fields are
write-only to the API and
redacted from logs/config reads. CRC protects accidental corruption; it is not
encryption or an authenticity boundary against physical flash access.

## Dual-slot record format

Each slot is a bounded binary record with:

- magic `PMCF`;
- record format version `1`;
- monotonically increasing 64-bit generation;
- 32-bit payload length;
- CRC-32 over generation, length, and payload;
- the serialized payload, limited to 24 KiB.

The active marker has independent magic `PMAC`, format version, slot letter,
generation, and CRC-32. A commit:

1. validates schema, lengths, HTTPS requirements, CA material, and the
   SSID/password pair;
2. serializes all related settings into one owned payload;
3. writes the inactive slot with the next generation;
4. reads the complete encoded slot back and compares it byte-for-byte;
5. decodes and verifies magic, version, length, generation, and CRC;
6. writes and reads back the active marker;
7. reloads through the normal selection path and compares the complete
   non-secret configuration plus the password in constant time;
8. publishes the new in-memory snapshot only after verification.

If any step fails, the previous active slot remains selected. The local API
returns a safe commit/readback error rather than claiming that settings were
saved.

## Boot and recovery

At boot, both slots and the active marker are validated. A valid marker selects
only the slot with its exact generation. If the marker is corrupt, interrupted,
or names an invalid slot, the newest valid slot is selected and
`CONFIG/ATOMIC_SLOT_FALLBACK` is logged. If the selected payload fails semantic
validation, the other valid slot is tried.

If slot keys exist but neither slot is valid, startup fails closed with
`CONFIG/PERSISTED_CONFIG_UNRECOVERABLE`; firmware does not overwrite evidence
with defaults. Defaults are created only when neither atomic nor legacy
configuration exists.

Existing firmware is migrated once from the legacy `pm-agent` namespace:

- legacy `cfg`, `cfg_prev`, `wifi_pwd`, `server_ca*`, and `server_fp*` are
  loaded with the old recovery rules;
- an incomplete, malformed, or fingerprint-only legacy server target is
  quarantined by clearing only its unusable server URL/trust while preserving
  the Wi-Fi pair for station operation;
- the SSID/password pair is validated together;
- the result is committed and read back through the new atomic store;
- legacy values remain intact until that verification succeeds.

Enrollment UUID, device secret, and OTA public key use the same dual-slot
algorithm. A reenrollment tombstone is also an atomic enrollment record, so an
interrupted revocation cannot produce a half-written identity.

## Provisioning and update behavior

First-run setup copies the HTTP body before leaving the request callback.
Password hashing and persistence execute in a bounded worker. Wi-Fi, server
URL, port, CA PEM, enrollment token, administrator hash, and meter settings
are validated as a unit. On failure, the previous slot and the separately
snapshotted one-time/local-authentication values are retained.

The normal Settings update preserves the current password when the SSID is
unchanged and the password field is omitted. Changing the SSID requires a new
password. TLS trust is retained only for an explicit `keep` action; replacement
requires a complete public CA. The response includes safe `saved`, `verified`,
generation, and network-apply fields.

## Boot-mode decision

Station mode is selected only when the active record has:

- a nonempty SSID of at most 32 bytes; and
- a password of 8–63 bytes.

Missing or invalid paired credentials select `unconfigured` and the setup AP.
Server URL, DNS, NTP, TLS, enrollment, microSD, and PZEM health do not affect
that decision. A server outage must therefore lead to degraded server state,
not provisioning mode.

There is no boot-button factory-reset path. Pressing the ESP32 RESET button,
a watchdog reset, or removing power does not clear configuration.

## Wi-Fi state machine

The timed/event-driven phases are:

```text
unconfigured -> provisioning
idle -> connecting -> waiting_for_ip -> connected -> time_sync
time_sync -> server_validation -> online
connected failure -> retry_wait -> connecting
server failure while Wi-Fi remains up -> degraded
```

`scanning` is a diagnostic side path and `failed` records an unrecoverable
driver/setup-AP failure. Driver callbacks publish short event diagnostics;
long DNS, TLS, HTTP, NVS, password, microSD, and PZEM work is not performed in
AsyncTCP callbacks.

Reconnect uses exponential backoff with random jitter, including the jitter
inside a strict five-minute cap; each station attempt gets at least 15
seconds. `NO_AP_FOUND`, DHCP delay, weak signal, a temporary access-point
outage, and every server/TLS/enrollment failure keep the device in station
retry/degraded operation and do not start provisioning. After at least 60
seconds, a driver result that specifically proves authentication failure may
expose a recovery AP so an administrator can correct the password. The saved
credentials remain intact while that AP is active. It closes immediately
after a station address is acquired and otherwise has a 15-minute inactive
session TTL.

The connection path uses:

```cpp
WiFi.disconnect(false, false);
```

It does not request driver credential erasure. A reconnect, scan, NTP retry,
server error, certificate error, enrollment rejection, or OTA does not call
NVS clear/remove for Wi-Fi settings.

## Explicit erasure

Only an authorized, confirmed action removes settings:

- **Reset network** commits a new atomic configuration with an empty Wi-Fi
  pair and clears the temporary setup-AP credential. Server and device
  identity remain.
- **Factory reset** clears the dedicated `pmconfig` namespace and legacy/local
  NVS state, creates a new local identity/default configuration, and commits
  an enrollment tombstone.

The UI requires the exact destructive confirmation phrase and queues the work
outside the network callback. Export redacted diagnostics and coordinate
server-side revocation before factory reset.

## Retention verification

For release acceptance, provision once and record the committed generation.
Verify the same non-secret SSID/server/CA-presence state after:

1. ordinary software restart;
2. RESET-button restart;
3. complete power removal;
4. watchdog-reset injection in a diagnostic build;
5. reflash without erase;
6. temporary AP outage;
7. server/TLS/enrollment failure;
8. at least 25 host-model reboot/load cycles.

The final hardware test must also show automatic association, DHCP, trusted
time, verified TLS, successful enrollment, and a signed heartbeat. Simulator
or native persistence success alone is not hardware acceptance.

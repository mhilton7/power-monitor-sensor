# TLS and heartbeat troubleshooting

The production transport always requires HTTPS, a stored public CA, trusted
time, certificate-chain validation, hostname/SAN validation, and SNI. It never
uses `setInsecure()`, fingerprint-only insecure negotiation, HTTP fallback, or
an IP substitution for the configured hostname.

## Safe triage order

1. Confirm Wi-Fi and trusted time in `GET /api/local/health`.
2. Confirm the configured URL uses the certificate hostname and HTTPS port.
3. Confirm DNS resolves that hostname to the intended server address.
4. Confirm the stored CA is the issuer/root needed by the server certificate.
5. Confirm the server listens on the configured port.
6. Capture serial diagnostics through a full automatic attempt.
7. Decode a reset only with the ELF from the exact flashed build.

Do not paste Wi-Fi passwords, enrollment tokens, device credentials, HMAC
headers, private keys, or complete signatures into a ticket or log.

## Diagnostic categories

| Category | Meaning | Corrective action |
|---|---|---|
| `CA_MISSING` | No public CA is stored | Install the correct public CA through the local settings flow |
| `CA_PEM_INVALID` | Stored PEM cannot be parsed | Preserve PEM header/footer and newlines |
| `TIME_NOT_TRUSTED` | Certificate dates cannot be checked safely | Repair NTP/DNS/gateway reachability |
| `DNS_FAILED` | Hostname did not resolve within the bound | Repair LAN DNS or `.local` mDNS |
| `CONNECTION_REFUSED` | Host resolved but the port rejected TCP | Start the HTTPS listener or correct the port |
| `TLS_HANDSHAKE_TIMEOUT` | Secure negotiation exceeded its bound | Inspect server load, firewall, and packet loss |
| `UNKNOWN_CA` / `CERT_CHAIN_INVALID` | The chain does not lead to the stored CA | Install the correct CA or repair the served chain |
| `HOSTNAME_MISMATCH` | Certificate SAN does not match the configured host | Use a certificate containing that hostname |
| `CERT_NOT_YET_VALID` / `CERT_EXPIRED` | Certificate validity check failed | Repair clock or renew the certificate |
| `MEMORY_EXHAUSTED` | Internal heap reserve or a TLS allocation was unavailable | Inspect `HEAP_LOW` and batch/response bounds; do not weaken TLS |
| `CONNECTION_CLOSED` | Peer closed or truncated a bounded response | Repair the server/proxy and allow normal retry |

The TLS client connects to the resolved IP while passing the original hostname
to the secure-client overload. This preserves SNI and hostname validation for
private DNS names.

After one successful lookup, `DNS_SUCCESS method=cache` is expected for the
unchanged endpoint. The cache is volatile, contains no credential, and is
discarded after two consecutive cached-address transport failures. A fresh
lookup then follows automatically. `DNS_CACHE_INVALIDATED` therefore indicates
address recovery, not a TLS downgrade. Station power saving remains disabled
so local ICMP and AsyncTCP traffic can continue while the dedicated worker is
inside a bounded server operation.

## Expected serial sequence

A successful operation contains:

```text
[...][INFO ][SYNC     ][SYNC_BEGIN] ...
[...][DEBUG][DNS      ][DNS_BEGIN] ...
[...][INFO ][DNS      ][DNS_SUCCESS] ...
[...][INFO ][TCP      ][TCP_BEGIN] ...
[...][INFO ][TLS      ][TLS_BEGIN] ...
[...][INFO ][TCP      ][TCP_CONNECTED] ...
[...][INFO ][TLS      ][TLS_SUCCESS] ...
[...][INFO ][HTTP     ][HTTP_BEGIN] ...
[...][INFO ][HTTP     ][HTTP_HEADERS_RECEIVED] ...
[...][INFO ][HTTP     ][HTTP_COMPLETE] ...
[...][DEBUG][SYNC     ][SYNC_CLEANUP_COMPLETE] ...
[...][INFO ][SYNC     ][SYNC_COMPLETE] ...
```

A failed attempt must still end with `SYNC_CLEANUP_COMPLETE` and either
`SYNC_FAILED` or `SYNC_TIMEOUT`, followed by `SYNC_RETRY_SCHEDULED`. Ping,
`/`, and `/api/local/health` must remain responsive.

## Server-outage verification

First record a successful automatic heartbeat. Temporarily stop or firewall
only the server's HTTPS listener; do not change the sensor configuration or
enrollment. Leave it unavailable for several automatic attempts while the
heartbeat-soak script runs. Verify bounded failures, continuing microSD
writes, stable uptime, and responsive local probes. Restore the same listener
and verify a later automatic heartbeat succeeds and the durable cursor
continues forward. No factory reset or reenrollment is part of this test.

The COM6 verification stopped only the TrueNAS application for six automatic
attempts. Retry delays increased with jitter from approximately 1, 2, 4, 9,
19, and 38 seconds. All 186 local samples retained ping, WebUI, health, Wi-Fi,
and writable-storage availability; uptime did not reset and the stack margin
remained 32 percent. After the same application restarted, 13 consecutive
heartbeats succeeded during the remainder of the test and reading-batch work
resumed. Enrollment and sensor configuration were unchanged.

## Backtrace matching

Record the serial `git_commit`, build timestamp, and ELF SHA-256 before
decoding. Use the exact environment ELF:

```powershell
Get-FileHash .pio\build\esp32-s3-release\firmware.elf -Algorithm SHA256
& "$env:USERPROFILE\.platformio\packages\toolchain-xtensa-esp32s3\bin\xtensa-esp32s3-elf-addr2line.exe" `
  -pfiaC -e .pio\build\esp32-s3-release\firmware.elf 0x42000000
```

Addresses decoded against another build are not evidence.

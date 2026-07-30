# Sensor-to-server connectivity

The sensor accepts only an HTTPS server origin and keeps the URL host as the
TLS identity. A working TCP port is necessary, but it does not prove DNS, CA
trust, certificate identity, enrollment, or HMAC authentication.

## Choose the server URL from the certificate

Inspect the deployed leaf certificate before entering the URL:

- If its DNS SAN contains `power-monitor.local`, use
  `https://power-monitor.local:8443` and provide deterministic LAN DNS or a
  tested mDNS path for that name.
- If its IP SAN contains `192.168.0.175`, the IP-literal origin
  `https://192.168.0.175:8443` can be used.
- A DNS name does not match an IP SAN, and an IP address does not match a DNS
  SAN. A Common Name alone is not a substitute for the required SAN.

`-ConnectAddress` in the diagnostic scripts changes only the transport
destination. OpenSSL and curl still send the URL hostname as SNI and verify
that hostname. This is useful for separating DNS failure from certificate
failure; it is not a permanent DNS workaround.

## Public CA certificate

For the standard Caddy internal-CA deployment, export only:

```text
/mnt/Apps/Power/power-monitor/caddy-data/caddy/pki/authorities/local/root.crt
```

Never copy `root.key`, `tls.key`, or any other private key. Verify the public
root certificate fingerprint through an independent administrator channel.
The sensor stores the complete PEM and passes it to the verified TLS client.
It does not call `setInsecure()` or fall back to HTTP.

Prepare an exported CA on Windows:

```powershell
.\tools\prepare_server_ca.ps1 `
  -CertificatePath C:\secure-transfer\root.crt
```

## Windows preflight

Run these commands from a trusted Windows client on the same routed network:

```powershell
Test-NetConnection -ComputerName 192.168.0.175 -Port 8443
Resolve-DnsName power-monitor.local
ping power-monitor.local
```

`TcpTestSucceeded : True` proves only that a listener accepted TCP. Ping may
be blocked, but the name-resolution result must be understood. Record whether
the answer came from LAN DNS, a hosts entry, or mDNS. The ESP32 must have an
equivalent deterministic route; a Windows-only hosts entry does not help it.

Run the repository checks with the real public CA:

```powershell
.\tools\diagnostics\Test-Certificate.ps1 `
  -ServerUrl https://power-monitor.local:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt `
  -ConnectAddress 192.168.0.175

.\tools\diagnostics\Test-PowerMonitorServer.ps1 `
  -ServerUrl https://power-monitor.local:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt
```

For a certificate containing the IP SAN instead:

```powershell
.\tools\diagnostics\Test-PowerMonitorServer.ps1 `
  -ServerUrl https://192.168.0.175:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt
```

Both scripts bypass configured HTTP proxies. They write timestamped logs under
`%USERPROFILE%\PowerMonitorDiagnostics` and return a nonzero exit code if a
required check fails. They never use curl `-k`.

## Sensor connection sequence

The expected order is:

1. Load verified configuration and Wi-Fi credentials from NVS.
2. Associate with the 2.4 GHz access point and acquire an IPv4 address.
3. Resolve the server host while retaining the original URL host for SNI and
   SAN verification.
4. Synchronize trusted UTC time with bounded NTP retries.
5. Parse the saved public CA and perform verified TLS.
6. Claim a one-time enrollment token, or load existing device credentials.
7. Send an HMAC-authenticated heartbeat and synchronize durable records.

Do not diagnose a TLS error until serial output shows trusted time. Certificate
validity dates and signed-request timestamps are unsafe before that point.
The firmware accepts absolute UTC only within 2024 through 2100. A suspicious
large forward or backward SNTP step remains untrusted until three
monotonic-consistent callbacks confirm it; the persisted trusted-time anchor
also constrains rollback. Serial diagnostics report
`NTP_STEP_PENDING_CONFIRMATION` or `NTP_CANDIDATE_REJECTED` while TLS and
signed requests remain deliberately paused.

## Device-facing routes

The server must preserve these `pm-protocol/1.0.0` routes through Caddy:

```text
POST /api/v1/device-enrollment/claim
POST /api/v1/device-heartbeats
POST /api/v1/device-readings/batch
POST /api/v1/device-events/batch
GET  /api/v1/device-config/effective
POST /api/v1/device-config/report
GET  /api/v1/device-firmware/manifest
GET  /api/v1/time
```

After enrollment, the device derives distinct RFC 5869
HKDF-SHA256 direction keys using `pm-device-to-server-v1` and
`pm-server-to-device-v1`. Requests bind method, canonical path/query,
timestamp, unique nonce, content SHA-256, and the exact body bytes. Safe logs
may include request ID, endpoint, byte count, status, elapsed time, and a
sanitized problem code; they must not contain signatures or credentials.

The deployed server must make enrollment claims idempotent across a lost HTTP
201 response. It must persist a client claim identifier and the complete
credential response atomically with token consumption, then replay that same
201 only for an exact retry with the same token, hardware ID, and payload.
Returning only `hardware_exists` after committing an unseen secret is not
recoverable by firmware; do not weaken the sensor to accept it as success.

## Interpreting failures

| Observation | Meaning | Next check |
|---|---|---|
| `connection refused` | The resolved/addressed host actively refused the TCP connection; CA validation did not get far enough to decide trust | Listener binding, port `8443`, Caddy status, firewall and ingress policy |
| DNS lookup failure | No usable answer was obtained | LAN DNS/mDNS design, DHCP DNS server, spelling and suffix |
| `TIME_NOT_TRUSTED` | TLS/HMAC was intentionally deferred | DHCP DNS, NTP reachability and UTC |
| `CA_MISSING` or `CA_EMPTY` | No trust anchor was saved | Reinstall the verified public root PEM |
| `CA_PEM_INVALID` | Saved text is not a usable public certificate | Export/normalize `root.crt`; never paste HTML or a key |
| `UNKNOWN_CA` or chain failure | The leaf does not chain to the supplied root | Inspect Caddy issuer and the complete deployed chain |
| `HOSTNAME_MISMATCH` | URL host is absent from the matching SAN type | Correct DNS/certificate deployment; do not suppress validation |
| HTTP `401`/`403` after TLS | Device authentication or ingress policy rejected the request | UUID, server record, signed-request time, policy and server audit log |
| HTTP `409`/`422` during enrollment | Token/protocol/request state is invalid | Token use/expiry, `pm-protocol/1.0.0`, site selection and problem code |

Server, TLS, or enrollment failure must not erase Wi-Fi configuration or force
provisioning mode. Meter acquisition and microSD history remain independent.

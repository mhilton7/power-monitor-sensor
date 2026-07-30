# Sensor troubleshooting

Start with evidence, not reset. Keep the exact firmware ELF and its SHA-256,
capture a full redacted boot log, and correlate sensor `request_id` values with
the server audit log. Do not connect live mains to reproduce software faults.

## Fast triage

| Symptom or serial evidence | Likely layer | Safe action |
|---|---|---|
| Boot says `wifi_ssid=<missing>` | No valid persisted configuration was selected, or migration/integrity validation failed | Capture `CONFIG` and `NVS` lines from reset; do not factory reset; compare generation/slot decisions |
| Saved SSID is present but setup AP returns | The driver specifically reported an authentication failure, so local credential recovery opened without erasing the saved pair | Capture `WIFI/CONNECT_ATTEMPT`, `DISCONNECTED`, `CREDENTIAL_RECOVERY_REQUIRED`, reason number, scan result and `RECONNECT_SCHEDULED` |
| `AUTH_FAIL` | Wi-Fi passphrase/security negotiation failed | Re-enter the exact password; verify WPA2-compatible 2.4 GHz service |
| `NO_AP_FOUND` | SSID was not visible at that attempt | Check spelling, 2.4 GHz availability and signal; configuration must remain saved |
| Waiting for IP/DHCP timeout | Association succeeded but addressing failed | Inspect DHCP pool, VLAN, static settings and gateway/subnet |
| `power-monitor.local` does not resolve | DNS/mDNS | Add a real LAN DNS record or validate the deliberate mDNS path; a Windows hosts entry does not configure ESP32 DNS |
| `connection refused` with a TLS category | TCP failed before certificate validation completed | Test `192.168.0.175:8443`, Caddy listener, firewall and sensor ingress |
| `TIME_NOT_TRUSTED` | NTP prerequisite | Restore DNS/NTP; do not bypass certificate date or HMAC time checks |
| CA missing/invalid | Saved trust material | Re-export public `root.crt`, normalize it and replace the CA |
| Hostname mismatch | URL host and SAN type differ | Use a hostname with a DNS SAN or an IP with an IP SAN; do not use insecure TLS |
| Enrollment HTTP `409`/`422` | Token already used/expired or request state invalid | Read safe server problem code, generate a new token only when prior use is understood |
| Heartbeat HTTP `401`/`403` | Credential, HMAC time/canonicalization, or ingress policy | Check server device record, UTC, UUID and audit log; never print the signature |
| `PZEM/READ_FAILED pzem_wrong_address` | Meter UART/address | Inspect de-energized PZEM V4 wiring/address separately; it does not explain Wi-Fi/TLS loss |
| `SD/MOUNT_FAILED` | Card, SPI wiring, power, or FAT32 | Repair microSD separately; missing SD must not erase Wi-Fi settings |
| `HISTORY_TIMEOUT` while SD is absent | Historical API cannot reach mandatory storage | Stop refreshing history during diagnosis; fix SD; health/config pages remain available |
| `async_tcp` or `PasswordHash` watchdog | Blocking/starving authentication work | Record the complete panic and exact ELF; install the bounded worker firmware; do not disable the watchdog |

## Windows diagnostics

Use the real public CA:

```powershell
.\tools\diagnostics\Test-Certificate.ps1 `
  -ServerUrl https://power-monitor.local:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt `
  -ConnectAddress 192.168.0.175

.\tools\diagnostics\Test-PowerMonitorServer.ps1 `
  -ServerUrl https://power-monitor.local:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt
```

The first command can prove that the address presents a chain valid for the
original hostname. The second intentionally fails overall if normal DNS is
broken, even if `-ConnectAddress` lets the remaining transport/TLS diagnosis
continue. Fix name resolution instead of retaining the override.

Capture serial without retaining secret values:

```powershell
.\tools\diagnostics\Capture-SensorSerial.ps1 `
  -Port COM6 `
  -DurationSeconds 180 `
  -ResetDevice
```

The helper auto-detects a single likely ESP32 port when `-Port` is omitted,
timestamps each line, and redacts password/token/cookie/signature-style
key/value fields before both display and storage. Close PuTTY and PlatformIO
first because only one process can own a COM port.

## Wi-Fi recovery without erasing identity

1. Leave the device powered long enough to observe at least one full
   association timeout and scheduled retry.
2. Use the serial `wifi` command for one explicit scan and `network` for the
   saved-state summary.
3. If the recovery AP is active, open the local Settings page and correct only
   the Wi-Fi/network group. Leaving the password blank retains it only when the
   SSID is unchanged.
4. Watch for persistence readback success before reconnecting the computer to
   the normal LAN.
5. Confirm the setup AP closes only after station IP acquisition.

Do not use network reset for a transient AP outage. Do not use factory reset
for DNS, NTP, TLS, server, enrollment, microSD, or PZEM errors.

## TLS and enrollment recovery

1. Confirm `wifi=connected`, a valid IP/gateway/DNS, and trusted UTC.
2. Inspect the certificate with `Test-Certificate.ps1`.
3. Confirm the configured origin host is present in the matching SAN type.
4. Trigger **Test server TLS** once. It bypasses only scheduled retry delay,
   not certificate verification.
5. Capture one request from `DNS/LOOKUP_BEGIN` through
   `HTTP/REQUEST_COMPLETE` or `REQUEST_FAILED`.
6. Check Caddy and application audit logs for the same time/request context.
7. For enrollment rejection, determine whether the token was expired, already
   consumed, assigned to a different site, or blocked by ingress policy before
   generating a replacement.

A server-side HTTP `401`, `403`, `409`, `422`, `429`, or `503` is not a reason
to erase NVS. Automatic retry follows the bounded policy where safe.

## Complete bug report

Collect:

- firmware commit and environment;
- firmware ELF SHA-256 and the exact `.elf`;
- ESP32 model/revision, flash/PSRAM sizes and reset reason;
- partition table;
- redacted initial/save/software-reset/hard-reset logs;
- redacted configuration-presence and generation/slot decisions;
- Windows DNS, TCP, CA, SAN and verified HTTPS results;
- sensor NTP/TLS/enrollment/heartbeat request IDs and statuses;
- matching server/Caddy audit excerpts with credentials removed;
- microSD and PZEM state, even when unrelated.

Before sharing, remove Wi-Fi names if site-sensitive, local addressing if
required by policy, and every password, token, cookie, CSRF value, private key,
authorization header, signature, device secret, salt, and hash. Never attach a
raw flash/NVS backup: it contains credentials.

Factory reset is the last resort. It destroys enrollment identity and local
configuration, requires a new one-time token, and may require server-side
revocation of the old device.

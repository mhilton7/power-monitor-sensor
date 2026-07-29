# Troubleshooting

| Symptom | Safe checks | Recovery |
|---|---|---|
| Setup AP absent | Serial boot; stored Wi-Fi; low-voltage USB only | Network reset and reboot only when the deployment can securely provision the replacement setup credential out of band; firmware never prints it |
| Setup AP remains or returns after save | Read the redacted serial disconnect reason; verify exact SSID/password, 2.4 GHz, DHCP/static values, and RSSI | Reopen Settings on the recovery AP and correct Wi-Fi; for a combined Wi-Fi 7 SSID, enable a legacy-compatible 2.4 GHz radio with WPA2-AES or WPA2/WPA3 transition mode; do not erase history |
| Wi-Fi loops | SSID/password, 2.4 GHz, DHCP, RSSI | Network reset/setup; do not erase history |
| Time untrusted | DNS/NTP and UDP 123 | Monotonic records continue with flags |
| TLS fails | UTC, URL, DNS, CA, chain/hostname | Install the correct CA PEM; never disable validation |
| Enrollment rejected | New unexpired token and protocol | Issue another token; reset only if identity must change |
| PZEM timeout/CRC | De-energized UART crossing, translator, ground, labels, 9600 8N1 | Run test; never treat failure as zero |
| SD fault | Storage warning/metrics | Follow [STORAGE_RECOVERY.md](STORAGE_RECOVERY.md) |
| Backlog grows | TLS/heartbeat, ack/newest | Restore server; automatic idempotent backfill |
| Safe mode | Download diagnostics; OTA/config/storage state | Rollback OTA or correct config |
| Upload fails | Port, driver, cable | BOOT+RESET recovery in build guide |

Download a redacted diagnostics bundle before destructive reset when possible. It excludes credentials.
For structured event names, stable `PM-*` codes, Wi-Fi reason translations,
serial commands, exact-ELF backtrace decoding, and capture procedures, see
[SERIAL_DIAGNOSTICS.md](SERIAL_DIAGNOSTICS.md). Fingerprint-only TLS is a
legacy configuration field but is rejected by firmware because this framework
cannot validate it without an insecure handshake; install a CA PEM instead.

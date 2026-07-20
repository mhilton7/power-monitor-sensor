# Troubleshooting

| Symptom | Safe checks | Recovery |
|---|---|---|
| Setup AP absent | Serial boot; stored Wi-Fi; low-voltage USB only | Network reset, reboot, capture new password once |
| Wi-Fi loops | SSID/password, 2.4 GHz, DHCP, RSSI | Network reset/setup; do not erase history |
| Time untrusted | DNS/NTP and UDP 123 | Monotonic records continue with flags |
| TLS fails | UTC, URL, DNS, CA/fingerprint, chain/hostname | Correct trust; never disable validation |
| Enrollment rejected | New unexpired token and protocol | Issue another token; reset only if identity must change |
| PZEM timeout/CRC | De-energized UART crossing, translator, ground, labels, 9600 8N1 | Run test; never treat failure as zero |
| SD fault | Storage warning/metrics | Follow [STORAGE_RECOVERY.md](STORAGE_RECOVERY.md) |
| Backlog grows | TLS/heartbeat, ack/newest | Restore server; automatic idempotent backfill |
| Safe mode | Download diagnostics; OTA/config/storage state | Rollback OTA or correct config |
| Upload fails | Port, driver, cable | BOOT+RESET recovery in build guide |

Download a redacted diagnostics bundle before destructive reset when possible. It excludes credentials.

# Troubleshooting

| Symptom | Safe checks | Recovery |
|---|---|---|
| Setup AP absent | Serial boot; stored Wi-Fi; low-voltage USB only | Network reset and reboot; wait for non-secret `SETUP_AP_READY`, close the serial monitor, then run `.\tools\diagnostics\Set-SensorSetupPassword.ps1 -Port COM6`. The helper exits nonzero unless firmware verifies the password and emits `SETUP_AP_PASSWORD_APPLIED` |
| Setup-password helper cannot open the port | PuTTY, PlatformIO Monitor, and flashing tools must be closed; confirm the current Device Manager COM number | Rerun the helper with the current port. Enter the password only at its hidden prompts; never place it in a command argument, terminal command, transcript, or support log |
| Administrator password unavailable | The first-run password is stored only as a salted verifier and cannot be displayed or extracted. Physical USB is the recovery authorization boundary; the password is never printed | Follow [ADMIN_PASSWORD_RECOVERY.md](ADMIN_PASSWORD_RECOVERY.md). Flash the temporary offline recovery build without erasing, then use its begin/`ADMIN_PASSWORD_RECOVERY_READY` handshake. It allows one successful replacement per boot and preserves Wi-Fi, server URL, public CA, and enrollment state. It does not reboot; immediately flash `esp32-s3-release` without erasing. Secure-boot devices require an organization-signed recovery image |
| Setup AP remains or returns after save | `CREDENTIAL_RECOVERY_REQUIRED` means the Wi-Fi driver specifically rejected authentication; an unavailable SSID, DHCP delay, or server failure does not open it | Reopen Settings on the recovery AP and correct Wi-Fi; for a combined Wi-Fi 7 SSID, enable a legacy-compatible 2.4 GHz radio with WPA2-AES or WPA2/WPA3 transition mode; do not erase history |
| Setup appears to save but boot reports `config_version=1` and `wifi_ssid=<missing>` | Look for `PROVISIONING_COMMIT_ROLLED_BACK failed_step=` and `PASSWORD JOB_COMPLETE code=` | Install the current firmware, which yields during the full 120,000-round password hash and verifies the NVS copy before reporting success; submit setup again |
| Wi-Fi settings disappear after reboot and the device immediately starts the setup AP | Look for `PERSISTED_CONFIG_REJECTED`, `PERSISTED_CONFIG_RECOVERED`, and `NVS_OPEN_COMPLETE source=` | Install firmware containing the persisted-CA load-order fix. It restores `cfg_prev` automatically when an orphaned Wi-Fi password proves the reset was not intentional; re-enter settings only if no recoverable previous configuration remains |
| Wi-Fi loops | SSID/password, 2.4 GHz, DHCP, RSSI | Network reset/setup; do not erase history |
| Time untrusted | DNS/NTP and UDP 123 | Monotonic records continue with flags |
| TLS fails | UTC, URL, DNS, CA, chain/hostname | Install the correct CA PEM; never disable validation |
| `CONNECTION_MODE_REJECTED` | A legacy pull/hybrid setting was loaded | Save Wi-Fi/server settings in push mode; current server polling expects HTTPS while the sensor local API is HTTP-only |
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

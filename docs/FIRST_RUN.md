# First run

1. Read [SAFETY.md](SAFETY.md) and finish the enclosure/wiring review. Where practical, power only the low-voltage ESP32/SD section. Do not energize PZEM mains merely to configure Wi-Fi.
2. Back up a reputable high-endurance card, format one FAT32 partition, safely eject it, and install it before boot. The sensor creates `/POWERMON` and recovers automatically.
3. Read the one-time setup SSID/password from the local serial console. The SSID is `PowerMonitor-Setup-xxxxxx`. The random password prints only when generated; a network reset creates another if lost.
4. Join the WPA2 AP and open `http://192.168.4.1/`. Sign in with the setup password.
5. Create a single-use token at the central server. The loopback simulator (`python -m simulator.server`) prints a local token.
6. Enter Wi-Fi credentials, central HTTPS URL, private CA PEM or SHA-256 fingerprint, token, local administrator password, friendly name, mode, and CT nameplate rating. Confirm the installed rating.
7. Submit once. Settings and credentials are staged, committed with rollback, and the device reboots. Secrets are write-only.
8. Confirm a unique device enrolls, an authenticated heartbeat arrives, and DHCP/mDNS addresses are current.
9. Run SD, DNS, NTP, TLS, heartbeat, and PZEM tests. PZEM may remain unavailable while mains hardware is deliberately disconnected; do not bypass safety to make a test pass.
10. Before commissioning, a qualified person confirms CT scope, voltage circuit/phase, labels/rating, barriers, and enclosure closure.

See [SERVER_ENROLLMENT.md](SERVER_ENROLLMENT.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

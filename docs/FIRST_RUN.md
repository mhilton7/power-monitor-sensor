# First run

1. Read [SAFETY.md](SAFETY.md) and finish the enclosure/wiring review. Where practical, power only the low-voltage ESP32/SD section. Do not energize PZEM mains merely to configure Wi-Fi.
2. Back up a reputable high-endurance card, format one FAT32 partition, safely eject it, and install it before boot. The sensor creates `/POWERMON` and recovers automatically.
3. Obtain the device-specific setup-AP credential through the deployment's
   secure out-of-band provisioning channel. Firmware serial diagnostics never
   print Wi-Fi or setup credentials at any log level. The SSID is
   `PowerMonitor-Setup-xxxxxx`.
4. Join the WPA2 AP and open `http://192.168.4.1/`. The local interface opens
   directly; the setup credential is only the Wi-Fi password for joining the
   setup AP.
5. Create a single-use token at the central server. The loopback simulator (`python -m simulator.server`) prints a local token.
6. Enter the exact SSID and 8–63 character password for a 2.4 GHz Wi-Fi network, central HTTPS URL, public server CA PEM, token, local administrator password, friendly name, mode, and CT nameplate rating. For the standard TrueNAS deployment, follow [SERVER_CA_CERTIFICATE.md](SERVER_CA_CERTIFICATE.md) to export Caddy's public `root.crt`; never use `root.key`. DHCP is the default; if the installation requires static IPv4, provide address, gateway, subnet mask, and DNS together. Confirm the installed CT rating.
7. Submit once. Settings and credentials are staged and committed with rollback, then the device applies the network configuration without interrupting the connection attempt with a reboot. Secrets are write-only.
8. Confirm a unique device enrolls, an authenticated heartbeat arrives, and the selected DHCP/static and mDNS addresses are current. The setup AP closes immediately after a successful station connection. If station Wi-Fi does not connect within 60 seconds, the same temporary network reappears as a recovery path so the credentials can be corrected.
9. Run SD, DNS, NTP, TLS, heartbeat, and PZEM tests. PZEM may remain unavailable while mains hardware is deliberately disconnected; do not bypass safety to make a test pass.
10. Before commissioning, a qualified person confirms CT scope, voltage circuit/phase, labels/rating, barriers, and enclosure closure.

After enrollment, select **Settings** in the local UI to change the Wi-Fi SSID/password, switch between DHCP and static IPv4, replace the server URL or public TLS CA certificate, or change pull/push/hybrid mode. The Settings button is kept near the start of the navigation, and the same form is linked from **Network status**. Leaving the Wi-Fi password blank retains the saved password; changing the SSID requires entering the password. TLS trust is also retained unless an explicit replacement option is selected. Saving this group commits it atomically and restarts the Wi-Fi connection without rebooting the sensor, so reconnect through its new network address afterward.

See [SERVER_ENROLLMENT.md](SERVER_ENROLLMENT.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

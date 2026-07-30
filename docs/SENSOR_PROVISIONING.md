# Sensor provisioning

Provision the ESP32-S3 on a de-energized bench. Software setup does not require
the PZEM-004T to be connected to live mains.

## Before setup

1. Build and flash the intended ESP32-S3 N16R8 environment without an erase if
   existing NVS must be preserved.
2. Open serial at `115200`, reset once, and record the boot/config decision.
3. If configuration is genuinely absent, wait for `SETUP_AP_READY`, record its
   non-secret `PowerMonitor-Setup-xxxxxx` SSID, and close the monitor. Run
   `.\tools\diagnostics\Set-SensorSetupPassword.ps1 -Port COM6`, replacing the
   port as needed. Enter a temporary 12-63 character printable ASCII password
   only at the hidden prompts. After `SETUP_AP_PASSWORD_APPLIED`, join the
   temporary 2.4 GHz network using that password. Firmware and the helper never
   print it.
4. Export and independently verify the server's public CA `root.crt`. Never
   copy a private key.
5. Run the certificate and server checks in
   [SENSOR_SERVER_CONNECTIVITY.md](SENSOR_SERVER_CONNECTIVITY.md).
6. Generate a new, short-lived, single-use enrollment token in the server.

The setup form owns copies of all submitted values and sends JSON with the
field names defined by the `FirstRunSetup` schema. Multiline CA PEM line breaks
are preserved. Password hashing and persistence run in a bounded worker, not
an AsyncTCP callback.

## Browser workflow

Open `http://192.168.4.1/` while joined to the temporary access point. Enter:

- a friendly name;
- the exact 1–32 character Wi-Fi SSID and 8–63 character password;
- DHCP, or all four required static IPv4 values;
- an HTTPS server origin whose host matches the deployed certificate SAN;
- the complete public CA PEM;
- the unused enrollment token;
- a new local administrator password of at least 12 characters;
- outbound push connection mode (the v1 pull/hybrid names are retained only
  for contract compatibility and are rejected by this firmware);
- the installed CT nameplate rating.

The UI first reports that work is pending. Success is displayed only after the
background job validates the values and verifies persistent readback. The
network is then applied without an intervening reboot. The setup AP closes
after the station obtains an address; reconnect the computer to the normal LAN
before opening the station address.

Do not resubmit the same one-time token after an uncertain result. Check the
server audit record and sensor serial log first.

## PowerShell provisioning test

The helper prompts for secrets with hidden input when secure values are not
provided. To keep secrets out of command history, create `SecureString`
variables interactively:

```powershell
$wifiPassword = Read-Host "Wi-Fi password" -AsSecureString
$enrollmentToken = Read-Host "Enrollment token" -AsSecureString
$administratorPassword = Read-Host "Administrator password" -AsSecureString

.\tools\diagnostics\Test-SensorProvisioning.ps1 `
  -SensorUrl http://192.168.4.1 `
  -ServerUrl https://power-monitor.local:8443 `
  -CaCertificatePath C:\secure-transfer\root.crt `
  -FriendlyName "Panel monitor" `
  -WifiSsid "Example-2.4GHz" `
  -WifiPassword $wifiPassword `
  -EnrollmentToken $enrollmentToken `
  -AdministratorPassword $administratorPassword `
  -CtRatingA 100 `
  -ConnectionMode push

Remove-Variable wifiPassword,enrollmentToken,administratorPassword
```

If the post-provisioning local address is already reserved in DHCP, add:

```powershell
-PostProvisioningSensorUrl http://power-monitor-e156b7.local
```

That option waits for station-mode reachability and checks the redacted
configuration, `pm-protocol/1.0.0`, Wi-Fi state, and server reachability. The
script disables proxies for local requests, logs only non-secret results, and
returns nonzero on a rejected or unverifiable operation. It never writes the
submitted payload to its timestamped log.

For static IPv4, also pass:

```powershell
-UseStaticIpv4 `
-StaticIp 192.168.0.210 `
-StaticGateway 192.168.0.1 `
-StaticSubnet 255.255.255.0 `
-StaticDns 192.168.0.1
```

Do not select a static address until it is reserved outside the DHCP pool.

## Enrollment result

The sensor calls `POST /api/v1/device-enrollment/claim` with
`pm-protocol/1.0.0`, hardware identity, capabilities, requested name, and the
one-time token. A successful server response is HTTP `201`. The sensor must
then:

1. persist the returned UUID and high-entropy device secret;
2. read them back and verify that both are complete;
3. clear the one-time token;
4. derive separate HMAC direction keys;
5. send the first `heartbeat/1.0.0` heartbeat.

Tokens, UUID credentials, HMAC values, cookies, CSRF values, passwords, salts,
and hashes are never included in diagnostics.

## Retention acceptance test

After the UI/API reports verified persistence:

1. capture a redacted boot log;
2. issue one ordinary software restart and confirm station mode;
3. press RESET once and confirm station mode;
4. remove USB power completely, wait several seconds, restore it, and confirm
   station mode;
5. reflash the same firmware without erase and confirm station mode;
6. verify the saved server origin still includes port `8443` and CA trust is
   present;
7. confirm trusted time, verified TLS, enrollment `201`, heartbeat `200`, and
   server online status.

Only explicit network reset removes Wi-Fi provisioning material. Only explicit
factory reset removes the full device identity/configuration. A Wi-Fi outage,
server outage, TLS error, enrollment rejection, watchdog reset, or normal OTA
must not clear settings.

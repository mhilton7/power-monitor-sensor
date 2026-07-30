# Reset and data ownership

**Network reset** removes Wi-Fi/setup-AP credentials and creates a new setup
password next boot. Enrollment, admin password, server config, cursor, energy
offset, and SD history remain. Firmware reports the non-secret SSID in
`SETUP_AP_READY` but never displays the password. Close the serial monitor and
run `.\tools\diagnostics\Set-SensorSetupPassword.ps1 -Port COM6`; enter the new
temporary password only through its hidden prompts.

**Factory reset** clears the NVS namespace: Wi-Fi, enrollment/device ID, password/setup verifiers, trust/config, acknowledgements, energy offset, and boot state. It creates a new local identity. It does not erase microSD, whose records still carry the old identity/sequences.

Before factory reset, export diagnostics/history and revoke the old server device. Type exact `FACTORY RESET`. Re-enroll with a new token. Explicitly archive, securely erase, or replace the old card; never silently mix old identity records into the new one.

Neither reset de-energizes equipment or makes enclosure access safe.

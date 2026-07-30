# Administrator password recovery

The administrator password is chosen during first-run provisioning. Firmware
stores only a salted PBKDF2 verifier, so neither serial diagnostics nor the
local API can reveal the original password.

If the password is unavailable, use the temporary physical-USB recovery build.
It replaces only the administrator verifier. Wi-Fi credentials, friendly name,
server URL, public CA, enrollment state, synchronization cursors, and microSD
history are preserved.

Physical access to the USB serial port is the authorization boundary for this
procedure. The recovery firmware keeps Wi-Fi, HTTP, server synchronization,
microSD, and meter services disabled; it has no network password-reset path.
Keep the PZEM and all mains wiring disconnected.

The helper uses a two-step handshake. It first sends a non-secret
`admin-recovery-begin` request with a random request ID and waits for the
matching `ADMIN_PASSWORD_RECOVERY_READY` control record. Only then does it send
the new password over the exclusively opened USB serial port. The password is
entered through hidden prompts and is never printed, echoed, or written to a
command argument or log. The firmware permits only one successful replacement
per recovery-firmware boot.

## Recovery procedure

1. Close PuTTY, PlatformIO Monitor, and any other program using the ESP32 COM
   port.
2. Build and flash the temporary recovery environment without erasing flash:

   ```powershell
   python -m platformio run -e esp32-s3-admin-recovery
   python -m platformio run -e esp32-s3-admin-recovery -t upload --upload-port COM6
   ```

   Do not use an erase target. Erasing would defeat the configuration-preserving
   recovery procedure. On a secure-boot deployment, the organization must sign
   the recovery image with a key trusted by that device before it can be
   flashed; a generic developer recovery image will not be accepted.

3. Run the hidden-input helper:

   ```powershell
   .\tools\diagnostics\Set-SensorAdminPassword.ps1 -Port COM6
   ```

   Enter the new 12-63 character printable ASCII password twice. The helper
   accepts no password argument. It performs the begin/READY handshake, binds
   the READY and result records to the same random request ID, and clears its
   mutable buffers.

4. Wait for `ADMIN_PASSWORD_RECOVERY_APPLIED`. Firmware writes and reads back
   the new verifier through a rollback journal and locks recovery against a
   second successful replacement during this boot. The temporary firmware
   remains running offline; it does not reboot into production firmware.
5. Immediately restore the normal production firmware without erasing:

   ```powershell
   python -m platformio run -e esp32-s3-release
   python -m platformio run -e esp32-s3-release -t upload --upload-port COM6
   ```

6. Confirm the next boot does not contain
   `PHYSICAL_ADMIN_RECOVERY_BUILD`, sign in only when a sensitive local action
   requests verification, and verify that the stored Wi-Fi/server settings are
   unchanged. Reflashing `esp32-s3-release` is mandatory: do not leave the
   temporary recovery image installed.

The recovery command is compiled only when
`PM_PHYSICAL_ADMIN_RECOVERY=1`. A compile-time guard forbids that flag in a
release build, and `esp32-s3-release` explicitly sets it to zero.

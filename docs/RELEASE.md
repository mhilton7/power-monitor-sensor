# Release procedure

1. Determine the next unused semantic version and update the embedded firmware
   version. Never reuse a published version for different bytes.
2. Review pinned dependencies, advisories, licenses, partition sizing, and
   protocol compatibility.
3. Run the complete test/build matrix in [Testing](TESTING.md) from the exact
   source revision. Confirm release/debug/simulated builds, native/sanitized
   tests, local UI, contracts, repository policy, memory regressions, rollback,
   and accelerated soaks.
4. Confirm the release environment excludes `PM_SIMULATED_METER` and the
   production image fits either 6 MiB OTA slot with documented margin.
5. Generate the existing-trust bundle, for example:

   ```sh
   python tools/generate_release.py --skip-build --version 1.0.16 --channel canary
   ```

   The generator verifies current source/build provenance and strict embedded
   ESP32-S3 application metadata. It writes `firmware-metadata.json` for audit;
   the central OTA workflow still accepts only `firmware.bin` from the user.
   Keep hardware-sensitive candidates on `canary`; promote metadata to
   `stable` only after the physical gates pass, without changing the verified
   firmware bytes or reusing a version for a rebuild.
6. Independently verify `SHA256SUMS`, `firmware-metadata.json`,
   `build-provenance.json`, `flash-layout.json`, `size-margin.json`,
   dependencies, target, project, protocol, semantic version, application/ELF
   build hash, and notes. Record the source commit and final firmware and ELF
   SHA-256 values.
7. In the server dashboard, select the release `firmware.bin`. Confirm the
   server independently parses it, calculates the same hash, identifies
   `power-monitor-sensor` and ESP32-S3, and records
   `trust_mode=existing_device_hmac`. Do not provide a manifest, hash, signing
   key, certificate, or private-key file.
8. On a low-voltage target, test manifest authentication, wrong-device replay,
   expiry, target/project/protocol/version policy, interrupted/truncated/extra
   bytes, SHA-256 mismatch, inactive-slot write, post-boot confirmation,
   configuration/microSD/sequence preservation, and automatic rollback.
9. Use one canary first. Promote another sensor only after the server confirms
   the target version/build, the healthy-heartbeat window, a durable reading,
   and absence of rollback or a critical alert.
10. Retain the binary, ELF/map, flash layout, artifact metadata, source commit,
    hashes, dependency inventory, server verification evidence, deployment
    state/audit, and physical-validation result.

Generated serial-flash components are `bootloader.bin`, `partitions.bin`,
`boot_app0.bin`, and `firmware.bin`. `flash-layout.json` binds each component to
its offset and SHA-256; `build-provenance.json` binds required artifacts to the
exact source fingerprint. Component flashing is preferred because secure boot,
flash encryption, NVS identity, and organizational key ceremony are deployment-
specific; no universal pre-provisioned factory image is shipped.

For serial component flashing, use the packaged layout: `bootloader.bin` at
`0x0`, `partitions.bin` at `0x8000`, `boot_app0.bin` at `0x11000`, and
`firmware.bin` at `0x20000`. Never write the OTA selector at Arduino's default
`0xE000`; that corrupts the preserved legacy NVS range. A one-time v2 bootstrap
writes only `firmware.bin` at `0x20000` and never erases flash. The PlatformIO
upload target applies and verifies the same relocation automatically.

`--legacy-signing-key-id` may emit an unsigned compatibility manifest for a
deliberately supported Ed25519-only sensor. It is optional, is not the v2
release path, and does not justify putting a legacy private key on the sensor,
server, or in source control.

When physical hardware was not connected, report the OTA/authentication/
rollback/memory implementation as deterministically validated and physical
deployment validation as pending. Do not claim a real flash, rollback, or soak.

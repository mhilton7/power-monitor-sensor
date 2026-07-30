# Release procedure

1. Review dependencies/advisories/licenses and update the audit date.
2. Run the full build on a clean clone; record frontend/native/contract results and all firmware size reports.
3. Confirm release excludes simulated meter and both 6 MB OTA slots have margin.
4. Run `python tools/generate_release.py --skip-build --version X.Y.Z --channel stable --signing-key-id KEY-ID`. The command refuses a build whose recorded source fingerprint differs from the current tree, whose sources changed during compilation, or whose required image hash no longer matches its build provenance. Use `--overwrite` only for a deliberate exact-version replacement before publication.
5. Verify `SHA256SUMS`, `build-provenance.json`, `flash-layout.json`, dependencies, target, protocol, version, size/hash, and notes independently.
6. Sign the server-compatible sorted compact JSON manifest with an external protected Ed25519 key; verify with the corresponding public key before publication.
7. On a low-voltage target bench test valid update, corruption, invalid signature, wrong target/protocol, interrupted download, rollback, and confirmation.
8. Upload the signed manifest and matching binary through the server's operator firmware workflow. Retain binaries, ELF/map, source commit, hashes, dependency inventory, and signing audit record.

Generated images are `bootloader.bin`, `partitions.bin`, `boot_app0.bin`, `firmware.bin`, and an identical `ota.bin`. `flash-layout.json` binds each serial-flash component to its offset and SHA-256; `build-provenance.json` binds every required build artifact to the exact source fingerprint. Component flashing is preferred because secure boot, flash encryption, NVS identity, and key ceremony are deployment-specific; no universal pre-provisioned factory image is shipped.

For serial component flashing, use the packaged layout: `bootloader.bin` at
`0x0`, `partitions.bin` at `0x8000`, `boot_app0.bin` at `0x11000`, and
`firmware.bin` at `0x20000`. Never write the OTA selector at the Arduino
default `0xE000`; that corrupts the preserved legacy NVS range. The PlatformIO
upload target applies and verifies the same relocation automatically.

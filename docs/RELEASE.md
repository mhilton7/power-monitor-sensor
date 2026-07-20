# Release procedure

1. Review dependencies/advisories/licenses and update the audit date.
2. Run the full build on a clean clone; record frontend/native/contract results and all firmware size reports.
3. Confirm release excludes simulated meter and both 6 MB OTA slots have margin.
4. Run `python tools/generate_release.py --skip-build --version X.Y.Z --image-url https://.../firmware.bin`.
5. Verify `SHA256SUMS`, dependencies, target, protocol, version, size/hash, and notes independently.
6. Sign with an external protected ECDSA P-256 key; verify with the corresponding public key before publication.
7. On a low-voltage target bench test valid update, corruption, invalid signature, wrong target/protocol, interrupted download, rollback, and confirmation.
8. Publish immutable HTTPS URLs. Retain binaries, ELF/map, source commit, hashes, dependency inventory, and signing audit record.

Generated images are `bootloader.bin`, `partitions.bin`, `firmware.bin`, and identical `ota.bin`. Component flashing is preferred because secure boot, flash encryption, NVS identity, and key ceremony are deployment-specific; no universal pre-provisioned factory image is shipped.

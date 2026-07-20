#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


def canonical(manifest: dict) -> bytes:
    notes_hash = hashlib.sha256(manifest["release_notes"].encode()).hexdigest()
    fields = [
        "PM-OTA-MANIFEST-V1", str(manifest["schema_version"]), manifest["firmware_version"],
        manifest["protocol"], manifest["hardware_target"], manifest["image_url"],
        str(manifest["image_size"]), manifest["image_sha256"], manifest["minimum_rollback_version"],
        notes_hash, "true" if manifest.get("allow_downgrade", False) else "false",
    ]
    return "\n".join(fields).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign an OTA manifest with an external ECDSA P-256 private key")
    parser.add_argument("unsigned_manifest", type=Path)
    parser.add_argument("--private-key", required=True, type=Path, help="PEM key outside this repository")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:
        raise SystemExit("install the pinned release dependency 'cryptography' in an isolated environment") from error
    manifest = json.loads(args.unsigned_manifest.read_text(encoding="utf-8"))
    manifest.pop("signature", None)
    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
        raise SystemExit("the external signing key must be ECDSA P-256")
    signature = private_key.sign(canonical(manifest), ec.ECDSA(hashes.SHA256()))
    manifest["signature"] = base64.b64encode(signature).decode("ascii")
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"signed manifest written to {args.output}; private key was not copied")


if __name__ == "__main__":
    main()


#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

SIGNED_FIELDS = {
    "version",
    "channel",
    "hardware_target",
    "protocol_min",
    "protocol_max",
    "sha256",
    "signing_key_id",
    "release_notes",
}


def canonical(manifest: dict) -> bytes:
    signed_manifest = {
        name: value for name, value in manifest.items() if name != "signature"
    }
    if set(signed_manifest) != SIGNED_FIELDS:
        missing = sorted(SIGNED_FIELDS - set(signed_manifest))
        unexpected = sorted(set(signed_manifest) - SIGNED_FIELDS)
        raise ValueError(
            f"manifest fields do not match central-server contract; "
            f"missing={missing}, unexpected={unexpected}"
        )
    return json.dumps(signed_manifest, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sign a central-server OTA manifest with an external Ed25519 private key"
    )
    parser.add_argument("unsigned_manifest", type=Path)
    parser.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help="PEM key outside this repository",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as error:
        raise SystemExit(
            "install the pinned release dependency 'cryptography' in an isolated environment"
        ) from error
    manifest = json.loads(args.unsigned_manifest.read_text(encoding="utf-8"))
    manifest.pop("signature", None)
    private_key = serialization.load_pem_private_key(
        args.private_key.read_bytes(), password=None
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SystemExit("the external signing key must be Ed25519")
    signed_bytes = canonical(manifest)
    signature = private_key.sign(signed_bytes)
    private_key.public_key().verify(signature, signed_bytes)
    manifest["signature"] = base64.b64encode(signature).decode("ascii")
    args.output.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"signed manifest written to {args.output}; private key was not copied")


if __name__ == "__main__":
    main()

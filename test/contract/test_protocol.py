from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from simulator.protocol import (  # noqa: E402
    body_sha256,
    canonical_path_query,
    canonical_string,
    hkdf_sha256,
    sign,
    verify,
)


class ProtocolContractTests(unittest.TestCase):
    def test_shared_hkdf_and_hmac_vectors(self) -> None:
        vectors = json.loads((ROOT / "shared/fixtures/auth-vectors.json").read_text())
        hkdf = vectors["hkdf"]
        secret = bytes.fromhex(hkdf["enrollment_secret_hex"])
        self.assertEqual(
            hkdf_sha256(secret, hkdf["device_to_server_info"].encode()).hex(),
            hkdf["device_to_server_key_hex"],
        )
        self.assertEqual(
            hkdf_sha256(secret, hkdf["server_to_device_info"].encode()).hex(),
            hkdf["server_to_device_key_hex"],
        )
        request = vectors["requests"][0]
        target = request["path"] + "?tag=z&tag=a"
        body = request["body_utf8"].encode()
        self.assertEqual(canonical_path_query(target), request["canonical_path_query"])
        self.assertEqual(body_sha256(body), request["content_sha256"])
        self.assertEqual(
            canonical_string(request["method"], target, request["timestamp"], request["nonce"], request["content_sha256"]),
            request["canonical"],
        )
        headers = sign(bytes.fromhex(request["key_hex"]), request["method"], target,
                       request["timestamp"], request["nonce"], body)
        self.assertEqual(headers["X-PM-Signature"], request["signature"])

    def test_replay_timestamp_hash_and_protocol_rejections(self) -> None:
        key = bytes(range(32))
        body = b'{"ok":true}'
        now = 1_700_000_000
        headers = sign(key, "POST", "/path?b=2&a=1", str(now), "ab" * 16, body)
        seen: set[str] = set()

        def nonce_seen(nonce: str, _timestamp: int) -> bool:
            existed = nonce in seen
            seen.add(nonce)
            return existed

        self.assertEqual(verify(key, "POST", "/path?b=2&a=1", headers, body, now, nonce_seen), (True, "ok"))
        self.assertEqual(verify(key, "POST", "/path?b=2&a=1", headers, body, now, nonce_seen), (False, "nonce_replayed"))
        changed = dict(headers)
        changed["X-PM-Nonce"] = "cd" * 16
        self.assertEqual(verify(key, "POST", "/path?b=2&a=1", changed, body, now, lambda *_: False)[1], "signature_invalid")
        changed = sign(key, "POST", "/path", str(now - 301), "ef" * 16, body)
        self.assertEqual(verify(key, "POST", "/path", changed, body, now, lambda *_: False)[1], "timestamp_outside_window")
        changed = sign(key, "POST", "/path", str(now), "01" * 16, body)
        changed["X-PM-Protocol"] = "pm-protocol/2.0.0"
        self.assertEqual(verify(key, "POST", "/path", changed, body, now, lambda *_: False)[1], "protocol_mismatch")

    def test_json_schema_fixtures(self) -> None:
        pairs = [
            ("reading.schema.json", "valid-reading.json", "invalid-reading.json"),
            ("heartbeat.schema.json", "valid-heartbeat.json", "invalid-heartbeat.json"),
        ]
        for schema_name, valid_name, invalid_name in pairs:
            schema = json.loads((ROOT / "shared/schemas" / schema_name).read_text())
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            valid = json.loads((ROOT / "shared/fixtures" / valid_name).read_text())
            invalid = json.loads((ROOT / "shared/fixtures" / invalid_name).read_text())
            self.assertEqual(list(validator.iter_errors(valid)), [], valid_name)
            self.assertNotEqual(list(validator.iter_errors(invalid)), [], invalid_name)

    def test_openapi_documents_and_path_item_references(self) -> None:
        for path in (ROOT / "shared/openapi").glob("*.yaml"):
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(document["openapi"], "3.1.0")
            self.assertTrue(document["paths"])
            for route, item in document["paths"].items():
                self.assertTrue("$ref" in item or any(method in item for method in ("get", "post", "put", "delete")), route)
        device = yaml.safe_load((ROOT / "shared/openapi/device-api.yaml").read_text())
        self.assertIn("post", device["components"]["pathItems"]["QueuedAction"])

    def test_negotiation_and_pagination_fixtures_are_unambiguous(self) -> None:
        negotiation = json.loads((ROOT / "shared/fixtures/protocol-negotiation.json").read_text())
        self.assertEqual(negotiation["supported"], ["pm-protocol/1.0.0"])
        self.assertEqual([case["status"] for case in negotiation["cases"]], [200, 409, 400])
        page = json.loads((ROOT / "shared/fixtures/pagination.json").read_text())
        self.assertEqual(page["response"]["next_after_sequence"], page["response"]["last_sequence"])
        self.assertEqual(page["gone_problem"]["status"], 410)


if __name__ == "__main__":
    unittest.main()

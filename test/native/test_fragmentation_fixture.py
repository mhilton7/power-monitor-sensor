import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class FragmentationIncidentFixtureTests(unittest.TestCase):
    def test_outdoor_ac_incident_is_exact_and_self_consistent(self) -> None:
        fixture = json.loads(
            (ROOT / "test/fixtures/outdoor_ac_fragmentation_incident.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(fixture["duration_seconds"], 2_100)
        self.assertEqual(fixture["status_requests"], 341)
        self.assertEqual(fixture["heartbeat_interval_seconds"], 15)
        self.assertEqual(fixture["duration_seconds"] // 15, 140)
        self.assertEqual(fixture["initial_free_internal_bytes"], 72_280)
        self.assertEqual(fixture["initial_largest_internal_block_bytes"], 24_564)
        self.assertEqual(fixture["tls_required_largest_block_bytes"], 32_768)
        self.assertGreater(
            fixture["initial_free_internal_bytes"],
            fixture["tls_required_largest_block_bytes"],
        )
        self.assertLess(
            fixture["initial_largest_internal_block_bytes"],
            fixture["tls_required_largest_block_bytes"],
        )
        self.assertTrue(fixture["wifi_connected"])
        self.assertEqual(fixture["authentication_failures"], 0)
        self.assertEqual(fixture["network_failures"], 0)


if __name__ == "__main__":
    unittest.main()

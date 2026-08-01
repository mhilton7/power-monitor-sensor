from __future__ import annotations

import unittest
from dataclasses import dataclass


UINT64_MAX = 2**64 - 1


def required_floor(*values: int) -> int:
    floor = max(values)
    if floor == UINT64_MAX:
        raise OverflowError("sequence space exhausted")
    return floor


def recover_journal(target: int | None, temporary: int | None, backup: int | None) -> int:
    valid = [value for value in (target, temporary, backup) if value is not None]
    if not valid:
        return 0
    return max(valid)


@dataclass(frozen=True)
class Manifest:
    device_id: str
    hardware_fingerprint: str

    def accepts(self, device_id: str, hardware_fingerprint: str) -> bool:
        return self.device_id == device_id and self.hardware_fingerprint == hardware_fingerprint


class ReplacedCardSequenceTests(unittest.TestCase):
    def test_exact_blank_card_ack_785_resumes_at_786(self) -> None:
        floor = required_floor(0, 0, 785, 785, 785, 0)
        self.assertEqual(floor, 785)
        self.assertEqual(floor + 1, 786)

    def test_maximum_seen_790_wins_over_contiguous_785(self) -> None:
        floor = required_floor(0, 0, 785, 790, 790, 0)
        self.assertEqual(floor + 1, 791)

    def test_server_outage_uses_persisted_recovery_cursor_until_reconnect(self) -> None:
        # A replacement card can boot while the server is unavailable.  The
        # trusted NVS recovery cursor still prevents reuse, and a higher
        # maximum-seen cursor learned after reconnect only moves the floor up.
        offline_floor = required_floor(0, 0, 785, 790, 0, 0)
        self.assertEqual(offline_floor + 1, 791)

        reconnected_floor = required_floor(791, 791, 785, 790, 795, 0)
        self.assertEqual(reconnected_floor + 1, 796)
        self.assertGreater(reconnected_floor, offline_floor)

    def test_interrupted_journal_uses_highest_verified_copy(self) -> None:
        self.assertEqual(recover_journal(785, 790, 785), 790)
        self.assertEqual(recover_journal(None, 790, 785), 790)
        self.assertEqual(recover_journal(None, None, 785), 785)

    def test_power_loss_at_each_atomic_journal_stage_never_regresses(self) -> None:
        stages = {
            "before temporary write": (785, None, None),
            "after temporary verify": (785, 790, None),
            "after target moved to backup": (None, 790, 785),
            "after temporary installed": (790, None, 785),
            "after backup cleanup": (790, None, None),
        }
        for stage, copies in stages.items():
            with self.subTest(stage=stage):
                recovered = recover_journal(*copies)
                self.assertGreaterEqual(recovered, 785)
                if 790 in copies:
                    self.assertEqual(recovered, 790)

    def test_corrupt_copy_does_not_hide_higher_verified_copy(self) -> None:
        self.assertEqual(recover_journal(None, 790, 785), 790)
        self.assertEqual(recover_journal(790, None, 785), 790)
        self.assertEqual(recover_journal(785, 790, None), 790)

    def test_overflow_fails_closed(self) -> None:
        with self.assertRaises(OverflowError):
            required_floor(0, UINT64_MAX, 0)

    def test_card_from_another_sensor_is_rejected(self) -> None:
        manifest = Manifest("outdoor-device", "outdoor-hardware")
        self.assertTrue(manifest.accepts("outdoor-device", "outdoor-hardware"))
        self.assertFalse(manifest.accepts("indoor-device", "indoor-hardware"))


if __name__ == "__main__":
    unittest.main()

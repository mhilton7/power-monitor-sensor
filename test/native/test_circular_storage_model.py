from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_TEMP_ROOT = PROJECT_ROOT / ".test-tmp" / "circular-storage"
TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class Segment:
    token: str
    first_sequence: int
    last_sequence: int
    day: int
    size: int = 128 * 1024
    trusted: bool = True
    complete: bool = True
    index_valid: bool = True
    active: bool = False


class InjectedPowerLoss(RuntimeError):
    pass


class StorageHarness:
    """Temporary-filesystem model of the production cleanup journal contract."""

    def __init__(self, root: Path, capacity: int = 16 * 1024 * 1024) -> None:
        self.root = root
        self.capacity = capacity
        self.records = root / "POWERMON" / "records"
        self.indexes = root / "POWERMON" / "indexes"
        self.state = root / "POWERMON" / "state"
        self.trash = root / "POWERMON" / ".trash"
        for path in (self.records, self.indexes, self.state, self.trash):
            path.mkdir(parents=True, exist_ok=True)
        self.journal = self.state / "cleanup.journal"
        self.segments: list[Segment] = []
        self.sequence_floor = 0
        self.gaps: list[tuple[int, int]] = []

    def paths(self, segment: Segment) -> tuple[Path, Path, Path, Path]:
        record = self.records / f"{segment.token}.pmr"
        index = self.indexes / f"{segment.token}.idx"
        return (
            record,
            index,
            self.trash / f"{segment.token}.pmr.trash",
            self.trash / f"{segment.token}.idx.trash",
        )

    def add(self, segment: Segment) -> None:
        record, index, _, _ = self.paths(segment)
        record.write_bytes(b"R" * segment.size)
        index.write_bytes(b"I" * 256)
        self.segments.append(segment)
        self.sequence_floor = max(self.sequence_floor, segment.last_sequence)

    def used(self) -> int:
        return sum(
            path.stat().st_size
            for path in self.root.rglob("*")
            if path.is_file()
        )

    def free(self) -> int:
        return max(0, self.capacity - self.used())

    def eligible(
        self,
        segment: Segment,
        *,
        ack: int,
        today: int,
        retention_days: int,
        minimum_days: int,
        continuous: bool,
        emergency: bool,
        minimum_file_tokens: set[str],
    ) -> bool:
        if (
            segment.active
            or not segment.complete
            or not segment.index_valid
            or segment.first_sequence <= 0
            or segment.last_sequence > ack
            or segment.token in minimum_file_tokens
        ):
            return False
        if segment.trusted and segment.day < today - retention_days:
            return True
        if not continuous or not emergency:
            return False
        return not segment.trusted or segment.day < today - minimum_days

    def write_journal(self, segment: Segment, stage: str) -> None:
        record, index, record_trash, index_trash = self.paths(segment)
        temporary = self.journal.with_suffix(".journal.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "stage": stage,
                    "record": str(record),
                    "index": str(index),
                    "record_trash": str(record_trash),
                    "index_trash": str(index_trash),
                    "first_sequence": segment.first_sequence,
                    "last_sequence": segment.last_sequence,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        temporary.replace(self.journal)

    @staticmethod
    def power_loss(point: str | None, actual: str) -> None:
        if point == actual:
            raise InjectedPowerLoss(actual)

    def remove_transaction(
        self, segment: Segment, power_loss_after: str | None = None
    ) -> None:
        record, index, record_trash, index_trash = self.paths(segment)
        self.write_journal(segment, "planned")
        self.power_loss(power_loss_after, "planned")
        record.replace(record_trash)
        self.power_loss(power_loss_after, "record_moved")
        index.replace(index_trash)
        self.power_loss(power_loss_after, "index_moved")
        self.write_journal(segment, "files_moved")
        self.power_loss(power_loss_after, "files_moved")
        record_trash.unlink()
        self.write_journal(segment, "record_deleted")
        self.power_loss(power_loss_after, "record_deleted")
        index_trash.unlink()
        self.write_journal(segment, "complete")
        self.power_loss(power_loss_after, "complete")
        self.journal.unlink()

    def recover(self) -> str:
        if not self.journal.exists():
            return "clean"
        try:
            data = json.loads(self.journal.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "blocked"
        stage = data.get("stage")
        record = Path(data.get("record", ""))
        index = Path(data.get("index", ""))
        record_trash = Path(data.get("record_trash", ""))
        index_trash = Path(data.get("index_trash", ""))
        safe_roots = (self.records.resolve(), self.indexes.resolve(), self.trash.resolve())
        paths = (record, index, record_trash, index_trash)
        if any(
            not path.is_absolute()
            or not any(path.resolve().is_relative_to(root) for root in safe_roots)
            for path in paths
        ):
            return "blocked"
        record_pair = (record.exists(), record_trash.exists())
        index_pair = (index.exists(), index_trash.exists())
        if record_pair == (True, True) or index_pair == (True, True):
            return "blocked"
        if stage == "planned":
            if record_pair == (False, False) or index_pair == (False, False):
                return "blocked"
            if record_trash.exists():
                record_trash.replace(record)
            if index_trash.exists():
                index_trash.replace(index)
            self.journal.unlink()
            return "reversed"
        if stage in {"files_moved", "record_deleted", "complete"}:
            if record.exists() or index.exists():
                return "blocked"
            record_trash.unlink(missing_ok=True)
            index_trash.unlink(missing_ok=True)
            self.journal.unlink()
            return "completed"
        return "blocked"

    def cleanup(
        self,
        *,
        ack: int,
        today: int,
        retention_days: int = 730,
        minimum_days: int = 30,
        continuous: bool = True,
        emergency: bool = False,
        target_free: int = 0,
    ) -> list[int]:
        closed = sorted(
            (segment for segment in self.segments if not segment.active),
            key=lambda segment: segment.last_sequence,
            reverse=True,
        )
        minimum_file_tokens = {segment.token for segment in closed[:2]}
        deleted: list[int] = []
        for segment in sorted(self.segments, key=lambda item: item.first_sequence):
            if target_free and self.free() >= target_free:
                break
            if not self.eligible(
                segment,
                ack=ack,
                today=today,
                retention_days=retention_days,
                minimum_days=minimum_days,
                continuous=continuous,
                emergency=emergency,
                minimum_file_tokens=minimum_file_tokens,
            ):
                continue
            self.remove_transaction(segment)
            deleted.extend(range(segment.first_sequence, segment.last_sequence + 1))
        return deleted

    def append_or_gap(self, payload_bytes: int, reserve_bytes: int = 384 * 1024) -> bool:
        next_sequence = self.sequence_floor + 1
        if self.free() < payload_bytes + reserve_bytes:
            self.sequence_floor = next_sequence
            self.gaps.append((next_sequence, next_sequence))
            return False
        segment = Segment(
            token=f"append-{next_sequence}",
            first_sequence=next_sequence,
            last_sequence=next_sequence,
            day=0,
            size=payload_bytes,
            active=True,
        )
        self.add(segment)
        return True


class CircularStorageFilesystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="pm-storage-", dir=TEST_TEMP_ROOT
        )
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def harness(self, capacity: int = 16 * 1024 * 1024) -> StorageHarness:
        return StorageHarness(self.root, capacity)

    def test_power_loss_at_every_transaction_stage_is_recoverable(self) -> None:
        for point in (
            "planned",
            "record_moved",
            "index_moved",
            "files_moved",
            "record_deleted",
            "complete",
        ):
            case = self.root / point
            case.mkdir()
            harness = StorageHarness(case)
            segment = Segment("segment", 1, 10, day=1)
            harness.add(segment)
            with self.assertRaises(InjectedPowerLoss):
                harness.remove_transaction(segment, point)
            result = harness.recover()
            record, index, record_trash, index_trash = harness.paths(segment)
            self.assertFalse(harness.journal.exists(), point)
            self.assertFalse(record_trash.exists(), point)
            self.assertFalse(index_trash.exists(), point)
            if point in {"planned", "record_moved", "index_moved"}:
                self.assertEqual(result, "reversed", point)
                self.assertTrue(record.exists(), point)
                self.assertTrue(index.exists(), point)
            else:
                self.assertEqual(result, "completed", point)
                self.assertFalse(record.exists(), point)
                self.assertFalse(index.exists(), point)

    def test_corrupt_unsafe_and_ambiguous_journals_block(self) -> None:
        harness = self.harness()
        harness.journal.write_text("{corrupt", encoding="utf-8")
        self.assertEqual(harness.recover(), "blocked")
        harness.journal.write_text(
            json.dumps(
                {
                    "stage": "planned",
                    "record": "C:/outside/record",
                    "index": "C:/outside/index",
                    "record_trash": "C:/outside/trash",
                    "index_trash": "C:/outside/trash-index",
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(harness.recover(), "blocked")
        segment = Segment("ambiguous", 1, 2, day=1)
        harness.add(segment)
        harness.write_journal(segment, "planned")
        record, _, record_trash, _ = harness.paths(segment)
        shutil.copy2(record, record_trash)
        self.assertEqual(harness.recover(), "blocked")
        self.assertTrue(record.exists())
        self.assertTrue(record_trash.exists())

    def test_unacknowledged_active_corrupt_recent_and_minimum_segments_survive(self) -> None:
        harness = self.harness()
        candidates = [
            Segment("eligible", 1, 10, day=1),
            Segment("unacked", 11, 20, day=1),
            Segment("corrupt", 21, 30, day=1, index_valid=False),
            Segment("recent", 31, 40, day=995),
            Segment("minimum-a", 41, 50, day=1, trusted=False),
            Segment("minimum-b", 51, 60, day=1, trusted=False),
            Segment("active", 61, 70, day=1, active=True),
        ]
        for segment in candidates:
            harness.add(segment)
        deleted = harness.cleanup(
            ack=10,
            today=1000,
            retention_days=730,
            minimum_days=30,
            continuous=True,
            emergency=True,
        )
        self.assertEqual(deleted, list(range(1, 11)))
        for segment in candidates[1:]:
            self.assertTrue(harness.paths(segment)[0].exists(), segment.token)

    def test_strict_age_never_uses_untrusted_time(self) -> None:
        harness = self.harness()
        trusted = Segment("trusted", 1, 10, day=1)
        untrusted = Segment("untrusted", 11, 20, day=1, trusted=False)
        newest_a = Segment("newest-a", 21, 30, day=999)
        newest_b = Segment("newest-b", 31, 40, day=999)
        for segment in (trusted, untrusted, newest_a, newest_b):
            harness.add(segment)
        deleted = harness.cleanup(
            ack=40,
            today=1000,
            retention_days=730,
            continuous=False,
            emergency=True,
        )
        self.assertEqual(deleted, list(range(1, 11)))
        self.assertTrue(harness.paths(untrusted)[0].exists())

    def test_full_card_prewrite_reserve_creates_explicit_gap_without_partial_file(self) -> None:
        harness = self.harness(capacity=512 * 1024)
        harness.add(Segment("existing", 1, 1, day=1, size=200 * 1024))
        self.assertFalse(harness.append_or_gap(64 * 1024))
        self.assertEqual(harness.sequence_floor, 2)
        self.assertEqual(harness.gaps, [(2, 2)])
        self.assertFalse((harness.records / "append-2.pmr").exists())

    def test_cleanup_is_oldest_first_and_stops_at_target(self) -> None:
        harness = self.harness(capacity=2 * 1024 * 1024)
        for index in range(1, 8):
            harness.add(Segment(f"segment-{index}", index, index, day=index, size=200 * 1024))
        target = harness.free() + 350 * 1024
        deleted = harness.cleanup(
            ack=7,
            today=1000,
            retention_days=100,
            emergency=True,
            target_free=target,
        )
        self.assertEqual(deleted, [1, 2])
        self.assertGreaterEqual(harness.free(), target)

    def test_accelerated_seven_day_outage_and_recovery_has_no_sequence_reuse(self) -> None:
        harness = self.harness(capacity=64 * 1024 * 1024)
        seen: set[int] = set()
        server_ack = 0
        for hour in range(7 * 24):
            first = hour * 60 + 1
            last = first + 59
            segment = Segment(
                f"hour-{hour:03d}", first, last, day=hour // 24, size=192 * 1024
            )
            harness.add(segment)
            interval = set(range(first, last + 1))
            self.assertTrue(seen.isdisjoint(interval))
            seen.update(interval)
            if hour >= 72:
                server_ack = last
            harness.cleanup(
                ack=server_ack,
                today=1000 + hour // 24,
                retention_days=730,
                minimum_days=2,
                continuous=True,
                emergency=harness.free() < 12 * 1024 * 1024,
                target_free=16 * 1024 * 1024,
            )
            self.assertFalse(harness.journal.exists())
            self.assertEqual(list(harness.trash.iterdir()), [])
        self.assertEqual(harness.sequence_floor, 7 * 24 * 60)
        self.assertEqual(len(seen), harness.sequence_floor)
        for segment in harness.segments:
            if segment.last_sequence > server_ack:
                self.assertTrue(harness.paths(segment)[0].exists())


if __name__ == "__main__":
    unittest.main()

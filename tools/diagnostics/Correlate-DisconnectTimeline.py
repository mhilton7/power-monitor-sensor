#!/usr/bin/env python3
"""Merge sensor/server JSONL captures into one chronological safe timeline."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path


def sort_key(item: dict[str, object]) -> tuple[datetime, str]:
    text = str(item.get("captured_utc") or item.get("captured_at") or "")
    try:
        timestamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        timestamp = datetime.min.replace(tzinfo=UTC)
    return timestamp, str(item.get("source", ""))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records: list[dict[str, object]] = []
    for path in args.inputs:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if line.strip():
                record = json.loads(line)
                record["input_file"] = path.name
                records.append(record)
    records.sort(key=sort_key)
    args.output.write_text(
        "\n".join(json.dumps(item, separators=(",", ":"), default=str) for item in records)
        + ("\n" if records else ""),
        encoding="utf-8",
    )
    print(f"Correlated {len(records)} records into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

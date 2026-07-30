#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from sd_format import decode


def records(paths: list[Path]):
    for path in paths:
        with path.open("rb") as stream:
            for line_number, line in enumerate(stream, 1):
                try:
                    yield path, line_number, decode(line).record
                except ValueError as error:
                    raise SystemExit(f"{path}:{line_number}: {error}") from error


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate and decode PMR1 microSD history"
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--format", choices=["ndjson", "csv"], default="ndjson")
    args = parser.parse_args()
    paths: list[Path] = []
    for path in args.paths:
        paths.extend(sorted(path.rglob("*.pmr")) if path.is_dir() else [path])
    decoded = list(records(paths))
    if args.format == "ndjson":
        for _, _, record in decoded:
            print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
    else:
        fields = [
            "device_id",
            "sequence",
            "start_utc",
            "end_utc",
            "interval_energy_wh",
            "energy_method",
            "quality_flags",
        ]
        writer = csv.DictWriter(sys.stdout, fields, extrasaction="ignore")
        writer.writeheader()
        for _, _, record in decoded:
            writer.writerow(record)


if __name__ == "__main__":
    main()

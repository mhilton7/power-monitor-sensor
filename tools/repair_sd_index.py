#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sd_format import decode


def rebuild(path: Path, repair_tail: bool) -> tuple[int, Path]:
    index_path = Path(str(path).replace("/records/", "/indexes/").replace("\\records\\", "\\indexes\\")).with_suffix(".idx")
    entries: list[str] = []
    valid_end = 0
    offset = 0
    with path.open("rb") as stream:
        while True:
            line = stream.readline()
            if not line:
                break
            try:
                decoded = decode(line)
            except ValueError as error:
                if not line.endswith(b"\n") and repair_tail:
                    with path.open("r+b") as repair:
                        repair.truncate(valid_end)
                    break
                raise SystemExit(f"refusing to alter complete corrupt record at offset {offset}: {error}") from error
            sequence = int(decoded.record["sequence"])
            utc_ms = int(decoded.record.get("start_utc_ms", 0))
            entries.append(f"{sequence},{utc_ms},{offset},{decoded.crc32:08x}\n")
            offset += len(line)
            valid_end = offset
    index_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = index_path.with_suffix(".idx.tmp")
    temporary.write_text("".join(entries), encoding="ascii", newline="\n")
    temporary.replace(index_path)
    return len(entries), index_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Rebuild PMR1 indexes; preserve complete corrupt records")
    parser.add_argument("record_file", type=Path)
    parser.add_argument("--repair-incomplete-tail", action="store_true")
    args = parser.parse_args()
    count, output = rebuild(args.record_file.resolve(), args.repair_incomplete_tail)
    print(f"wrote {count} index entries to {output}")


if __name__ == "__main__":
    main()


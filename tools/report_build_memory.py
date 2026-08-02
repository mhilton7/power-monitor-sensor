#!/usr/bin/env python3
"""Create reproducible ESP32 firmware/map and fixed-buffer reports."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DEFAULT_ENVIRONMENTS = (
    "esp32-s3-release",
    "esp32-s3-debug",
    "esp32-s3-simulated-meter",
)


@dataclass(frozen=True)
class MapMetrics:
    static_dram_bytes: int
    iram_bytes: int
    flash_bytes: int
    psram_related_lines: tuple[str, ...]
    large_sections: tuple[dict[str, Any], ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    return {
        "path": path.as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def parse_map(path: Path) -> MapMetrics | None:
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    output_sections: list[tuple[str, int]] = []
    large_sections: list[dict[str, Any]] = []
    psram_lines: list[str] = []
    section_pattern = re.compile(
        r"^(?P<indent>\s*)(?P<name>\.[A-Za-z0-9_.$+-]+)\s+"
        r"0x[0-9a-fA-F]+\s+0x(?P<size>[0-9a-fA-F]+)(?:\s+(?P<object>\S.*))?$"
    )
    pending_section: tuple[str, bool] | None = None
    continuation_pattern = re.compile(
        r"^\s+0x[0-9a-fA-F]+\s+0x(?P<size>[0-9a-fA-F]+)"
        r"(?:\s+(?P<object>\S.*))?$"
    )
    for raw_line in text.splitlines():
        match = section_pattern.match(raw_line)
        if match is not None:
            size = int(match.group("size"), 16)
            name = match.group("name")
            if not match.group("indent"):
                output_sections.append((name, size))
            elif size >= 512 and not name.startswith((".literal", ".text")):
                large_sections.append(
                    {
                        "section": name,
                        "bytes": size,
                        "object": (match.group("object") or "").strip(),
                    }
                )
            pending_section = None
        else:
            continuation = continuation_pattern.match(raw_line)
            if pending_section is not None and continuation is not None:
                name, output_section = pending_section
                size = int(continuation.group("size"), 16)
                if output_section:
                    output_sections.append((name, size))
                elif size >= 512 and not name.startswith((".literal", ".text")):
                    large_sections.append(
                        {
                            "section": name,
                            "bytes": size,
                            "object": (continuation.group("object") or "").strip(),
                        }
                    )
                pending_section = None
            else:
                name_only = re.match(
                    r"^(?P<indent>\s*)(?P<name>\.[A-Za-z0-9_.$+-]+)\s*$",
                    raw_line,
                )
                pending_section = (
                    (name_only.group("name"), not bool(name_only.group("indent")))
                    if name_only is not None
                    else None
                )
        lowered = raw_line.lower()
        if ("spiram" in lowered or "ext_ram" in lowered) and len(psram_lines) < 40:
            psram_lines.append(raw_line.strip())

    def total(prefixes: tuple[str, ...]) -> int:
        return sum(size for name, size in output_sections if name.startswith(prefixes))

    return MapMetrics(
        static_dram_bytes=total((".dram0.", ".noinit")),
        iram_bytes=total((".iram0.",)),
        flash_bytes=total((".flash.",)),
        psram_related_lines=tuple(dict.fromkeys(psram_lines)),
        large_sections=tuple(
            sorted(large_sections, key=lambda item: int(item["bytes"]), reverse=True)[
                :30
            ]
        ),
    )


def _safe_integer(expression: str) -> int:
    cleaned = re.sub(r"(?<=\d)[uUlL]+\b", "", expression)
    tree = ast.parse(cleaned, mode="eval")

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.LShift)
        ):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.FloorDiv):
                return left // right
            return left << right
        raise ValueError(f"unsupported integer expression: {expression}")

    return evaluate(tree)


def task_stacks(root: Path) -> dict[str, Any]:
    path = root / "include" / "app" / "TaskConfig.h"
    text = path.read_text(encoding="utf-8")
    stacks: dict[str, int] = {}
    pattern = re.compile(
        r"inline\s+constexpr\s+std::uint32_t\s+"
        r"(?P<name>k\w+StackBytes)\s*=\s*(?P<value>[^;]+);"
    )
    for match in pattern.finditer(text):
        stacks[match.group("name")] = _safe_integer(match.group("value").strip())
    return {"configured_bytes": stacks, "total_bytes": sum(stacks.values())}


def fixed_buffers(root: Path) -> list[dict[str, Any]]:
    buffers: list[dict[str, Any]] = []
    http_header = (root / "src" / "api" / "HttpApi.h").read_text(encoding="utf-8")
    constants = {
        name: int(value)
        for name, value in re.findall(
            r"constexpr\s+std::size_t\s+(\w+)\s*=\s*(\d+)U?\s*;",
            http_header,
        )
    }
    pool = re.search(r"StatusResponsePool\s*<\s*(\w+)\s*,\s*(\w+)\s*>", http_header)
    if pool is not None:
        resolved = [
            int(value.rstrip("U")) if value.rstrip("U").isdigit() else constants[value]
            for value in pool.groups()
        ]
        slots, slot_bytes = resolved
        buffers.append(
            {
                "name": "compact_status_response_pool",
                "count": slots,
                "bytes_each": slot_bytes,
                "total_payload_bytes": slots * slot_bytes,
                "placement": "long_lived_internal_heap",
                "reason": "Async response leases require stable storage",
            }
        )

    scratch_path = root / "src" / "network" / "ServerSyncScratch.h"
    if scratch_path.is_file():
        scratch = scratch_path.read_text(encoding="utf-8")
        for name, label in (
            ("kRequestCapacity", "server_sync_request_scratch"),
            ("kResponseCapacity", "server_sync_response_scratch"),
            ("kCanonicalCapacity", "server_sync_canonical_scratch"),
            ("kUrlCapacity", "server_sync_url_scratch"),
        ):
            match = re.search(rf"{name}\s*=\s*([^;]+);", scratch)
            if match is not None:
                buffers.append(
                    {
                        "name": label,
                        "count": 1,
                        "bytes_each": _safe_integer(match.group(1).strip()),
                        "total_payload_bytes": _safe_integer(match.group(1).strip()),
                        "placement": "long_lived_psram_heap",
                        "reason": "allocated with MALLOC_CAP_SPIRAM and reused by one owner",
                    }
                )
    return buffers


def web_assets(root: Path) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    distribution = root / "web" / "dist"
    if distribution.is_dir():
        for path in sorted(item for item in distribution.rglob("*") if item.is_file()):
            assets.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": path.stat().st_size,
                    "placement": "flash_PROGMEM_after_embedding",
                }
            )
    embedded = root / "src" / "ui" / "embedded_assets.h"
    if embedded.is_file():
        assets.append(
            {
                "path": embedded.relative_to(root).as_posix(),
                "bytes": embedded.stat().st_size,
                "placement": "generated_source_not_runtime_size",
            }
        )
    return assets


def environment_report(root: Path, environment: str) -> dict[str, Any]:
    build = root / ".pio" / "build" / environment
    map_metrics = parse_map(build / "firmware.map")
    return {
        "environment": environment,
        "artifacts": {
            "firmware_bin": _artifact(build / "firmware.bin"),
            "firmware_elf": _artifact(build / "firmware.elf"),
            "firmware_map": _artifact(build / "firmware.map"),
        },
        "map": asdict(map_metrics) if map_metrics is not None else None,
    }


def create_report(root: Path, environments: tuple[str, ...]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "method": (
            "GNU linker output-section totals; large input sections are advisory and "
            "may include library-owned storage"
        ),
        "environments": [environment_report(root, value) for value in environments],
        "task_stacks": task_stacks(root),
        "fixed_buffers": fixed_buffers(root),
        "web_assets": web_assets(root),
        "placement_notes": {
            "internal_dram": "linker .dram0 and .noinit output sections",
            "psram": "map symbols plus explicitly MALLOC_CAP_SPIRAM-backed scratch",
            "flash": "linker .flash sections and embedded WebUI assets",
            "stack": "configured/static evidence only; not a physical high-water measurement",
        },
    }


def compare_reports(
    current: dict[str, Any], baseline: dict[str, Any]
) -> dict[str, Any]:
    previous = {item["environment"]: item for item in baseline.get("environments", [])}
    comparison: dict[str, Any] = {"environments": []}
    for item in current["environments"]:
        old = previous.get(item["environment"])
        if old is None:
            continue
        deltas: dict[str, int | None] = {}
        for artifact in ("firmware_bin", "firmware_elf", "firmware_map"):
            before = old.get("artifacts", {}).get(artifact)
            after = item.get("artifacts", {}).get(artifact)
            deltas[f"{artifact}_bytes"] = (
                int(after["bytes"]) - int(before["bytes"])
                if before is not None and after is not None
                else None
            )
        for metric in ("static_dram_bytes", "iram_bytes", "flash_bytes"):
            before_map, after_map = old.get("map"), item.get("map")
            deltas[metric] = (
                int(after_map[metric]) - int(before_map[metric])
                if before_map is not None and after_map is not None
                else None
            )
        comparison["environments"].append(
            {"environment": item["environment"], "deltas": deltas}
        )
    before_stack = baseline.get("task_stacks", {}).get("total_bytes")
    after_stack = current.get("task_stacks", {}).get("total_bytes")
    comparison["configured_task_stack_bytes"] = (
        int(after_stack) - int(before_stack)
        if before_stack is not None and after_stack is not None
        else None
    )
    return comparison


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--environment", action="append", dest="environments")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--require-artifacts", action="store_true")
    arguments = parser.parse_args()
    environments = tuple(arguments.environments or DEFAULT_ENVIRONMENTS)
    report = create_report(arguments.root.resolve(), environments)
    if arguments.baseline is not None:
        baseline_path = arguments.baseline
        if not baseline_path.is_absolute():
            baseline_path = arguments.root.resolve() / baseline_path
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        report["comparison_to_baseline"] = compare_reports(report, baseline)
    if arguments.require_artifacts:
        missing = [
            item["environment"]
            for item in report["environments"]
            if any(value is None for value in item["artifacts"].values())
        ]
        if missing:
            raise SystemExit(f"missing firmware artifacts/maps: {', '.join(missing)}")
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(encoded, end="")
    else:
        output = arguments.output
        if not output.is_absolute():
            output = arguments.root.resolve() / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

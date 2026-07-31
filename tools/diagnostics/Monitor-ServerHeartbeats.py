#!/usr/bin/env python3
"""Poll the server's device and fleet views without logging session secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


def masked(value: object) -> str | None:
    if not value:
        return None
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def fetch(url: str, cookie: str, context: ssl.SSLContext) -> object:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "Cookie": cookie},
    )
    with urllib.request.urlopen(request, timeout=15, context=context) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--cookie-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--duration-minutes", type=int, default=30)
    parser.add_argument("--interval-seconds", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cookie = args.cookie_file.read_text(encoding="utf-8").strip()
    context = ssl.create_default_context(cafile=str(args.ca_file) if args.ca_file else None)
    base = args.base_url.rstrip("/")
    query = urllib.parse.urlencode({"site_id": args.site_id})
    deadline = time.monotonic() + args.duration_minutes * 60
    with args.output.open("a", encoding="utf-8") as output:
        while time.monotonic() < deadline:
            captured = datetime.now(UTC).isoformat()
            try:
                devices = fetch(f"{base}/api/v1/devices?{query}", cookie, context)
                fleet = fetch(f"{base}/api/v1/fleet/summary?{query}", cookie, context)
                rows = devices if isinstance(devices, list) else []
                record = {
                    "captured_utc": captured,
                    "source": "server_heartbeat_monitor",
                    "ok": True,
                    "fleet": fleet,
                    "devices": [
                        {
                            **{key: row.get(key) for key in (
                                "status", "current_watts", "latest_measurement_at",
                                "last_seen_at", "measurement_freshness",
                            )},
                            "id_hash": masked(row.get("id")),
                        }
                        for row in rows
                    ],
                }
            except Exception as error:  # diagnostics must continue through outages
                record = {
                    "captured_utc": captured,
                    "source": "server_heartbeat_monitor",
                    "ok": False,
                    "category": error.__class__.__name__,
                    "detail": str(error),
                }
            output.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
            output.flush()
            time.sleep(max(5, args.interval_seconds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Summarize a redacted sensor diagnostic bundle without printing secrets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def nested(document: dict, *path: str, default: object = None) -> object:
    value: object = document
    for key in path:
        if not isinstance(value, dict):
            return default
        value = value.get(key, default)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    document = json.loads(args.bundle.read_text(encoding="utf-8-sig"))
    metrics = document.get("metrics", document)
    summary = {
        "generated_utc": document.get("generated_utc"),
        "firmware": nested(document, "health", "firmware_version"),
        "heap_free": nested(metrics, "free_heap_bytes"),
        "heap_minimum": nested(metrics, "minimum_free_heap_bytes"),
        "heartbeat_successes": nested(metrics, "sync", "heartbeat_successes", default=0),
        "heartbeat_failures": nested(metrics, "sync", "heartbeat_failures", default=0),
        "batch_successes": nested(metrics, "sync", "batch_successes", default=0),
        "batch_failures": nested(metrics, "sync", "batch_failures", default=0),
        "tls_heap_deferrals": nested(metrics, "sync", "tls_requests_rejected_heap", default=0),
        "local_signature_rejections": nested(metrics, "http", "rejected_signatures", default=0),
        "browser_session_rejections": nested(metrics, "http", "browser_session_rejections", default=0),
        "sd_reads": nested(metrics, "sd", "reads", default=0),
        "sd_writes": nested(metrics, "sd", "writes", default=0),
    }
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

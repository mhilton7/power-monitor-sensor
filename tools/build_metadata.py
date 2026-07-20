"""Inject traceable, SOURCE_DATE_EPOCH-compatible firmware metadata."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

Import("env")  # type: ignore[name-defined]  # PlatformIO/SCons global

ROOT = Path(env.subst("$PROJECT_DIR"))  # type: ignore[name-defined]


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "--short=12", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "uncommitted"


epoch = os.environ.get("SOURCE_DATE_EPOCH")
if epoch is not None:
    timestamp = datetime.fromtimestamp(int(epoch), timezone.utc)
else:
    timestamp = datetime.now(timezone.utc)
build_timestamp = timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")

env.Append(  # type: ignore[name-defined]
    CPPDEFINES=[
        ("PM_GIT_COMMIT", env.StringifyMacro(git_commit())),  # type: ignore[name-defined]
        ("PM_BUILD_TIMESTAMP", env.StringifyMacro(build_timestamp)),  # type: ignore[name-defined]
    ]
)

"""Inject traceable, SOURCE_DATE_EPOCH-compatible firmware metadata."""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

Import("env")  # type: ignore[name-defined]  # PlatformIO/SCons global

ROOT = Path(env.subst("$PROJECT_DIR"))  # type: ignore[name-defined]


def git_commit() -> str:
    executable = shutil.which("git")
    if executable is not None:
        result = subprocess.run(
            [executable, "rev-parse", "--short=12", "HEAD"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    head_path = ROOT / ".git" / "HEAD"
    if head_path.is_file():
        head = head_path.read_text(encoding="ascii").strip()
        if head.startswith("ref: "):
            reference = ROOT / ".git" / head[5:]
            if reference.is_file():
                return reference.read_text(encoding="ascii").strip()[:12]
        elif len(head) >= 12:
            return head[:12]
    return "uncommitted"


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
        ("PM_BUILD_UNIX_SECONDS", int(timestamp.timestamp())),
    ]
)

#!/usr/bin/env python3
"""Filesystem I/O (single responsibility: safe JSON read/write)."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def resolve_writable_dir(preferred: str | Path, *, label: str = "reports") -> Path:
    """Return a directory we can actually write into, preferring `preferred`.

    Report persistence is best-effort: a CI gate's verdict is its exit code, so a scan that
    completed must never crash because it couldn't save its report. This tries `preferred`,
    then a shared temp dir, confirming each with a real write probe — a directory can exist
    yet be unwritable for the current user (e.g. a host bind-mount under a non-root container
    user), which `mkdir(exist_ok=True)` alone wouldn't catch. On a fallback it warns once on
    stderr (naming both paths) and never raises.
    """
    preferred = Path(preferred)
    for candidate in (preferred, Path(tempfile.gettempdir()) / "stayawake-reports"):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            # mkdir(exist_ok=True) succeeds on a dir owned by another uid; prove we can
            # actually create a file before trusting it.
            fd, probe = tempfile.mkstemp(dir=str(candidate), prefix=".probe-")
            os.close(fd)
            os.remove(probe)
        except OSError:
            continue
        if candidate != preferred:
            print(f"warning: {label} directory {preferred} is not writable; "
                  f"writing to {candidate} instead", file=sys.stderr)
        return candidate
    # Last resort: a unique, current-user-owned dir (always writable, never collides).
    last = Path(tempfile.mkdtemp(prefix="stayawake-reports-"))
    print(f"warning: {label} directory {preferred} is not writable; "
          f"writing to {last} instead", file=sys.stderr)
    return last


def read_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_json(path: str | Path, data: Any) -> None:
    """Atomic JSON write (temp file + rename) — never leaves a half-written file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

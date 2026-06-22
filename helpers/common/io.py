#!/usr/bin/env python3
"""Shared I/O helpers (atomic JSON write, backups, UTC timestamp).

Single responsibility: safe filesystem reads/writes reused by both the
availability and security subtasks (DRY). Stdlib only.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_iso_now() -> str:
    """ISO-8601 UTC timestamp, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default


def write_json_atomic(path: str | Path, data: Any) -> None:
    """Write JSON via a temp file + atomic rename (no half-written reports)."""
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

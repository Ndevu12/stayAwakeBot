#!/usr/bin/env python3
"""What the watcher remembers about itself: event counts and times, never what it saw."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from stayawake.utils import atomicwrite, env

STALE_AFTER_SECONDS = 600


def record_path() -> Path:
    """Find where the watcher keeps its record. Returns the path in saw's state folder."""
    return Path(env.xdg_state_home()) / "saw" / "watch-events.json"


def load(path: Path | None = None) -> dict:
    """Read the watcher's record. Takes an optional path. Returns the record, or an empty one
    when there is none or it cannot be read."""
    where = path or record_path()
    try:
        if where.is_symlink():
            return {}
        data = json.loads(where.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def save(record: dict, path: Path | None = None) -> bool:
    """Write the watcher's record. Takes the record and an optional path. Returns whether it was
    written."""
    where = path or record_path()
    try:
        where.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    if where.is_symlink():
        return False
    return atomicwrite.replace(where, json.dumps(record, sort_keys=True), mode=0o600)


def acknowledge(path: Path | None = None, *, now=time.time) -> bool:
    """Mark code that came back as dealt with. Takes an optional path. Returns whether the record
    holds no unacknowledged return afterwards."""
    record = load(path)
    if not record.get("unacknowledged"):
        return True
    record["unacknowledged"] = None
    record["reminded"] = None
    record["acknowledged"] = now()
    return save(record, path)


def heartbeat_age(record: dict, now: float) -> float | None:
    """Tell how long ago the watcher last completed a pass. Takes the record and the time now.
    Returns the age in seconds, or None when it has never completed one."""
    last = record.get("last_good")
    return now - last if isinstance(last, (int, float)) else None


def stale(record: dict, now: float) -> bool:
    """Tell whether the watcher has stopped completing passes. Takes the record and the time now.
    Returns True when it never completed one or the last was too long ago."""
    age = heartbeat_age(record, now)
    return age is None or age > STALE_AFTER_SECONDS


def placed_here() -> bool:
    """Tell whether this user has a watcher record at all. Returns the answer."""
    try:
        return os.path.exists(record_path())
    except OSError:
        return False

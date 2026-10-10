#!/usr/bin/env python3
"""What the watcher remembers about itself: event counts and times, never what it saw."""
from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path

from stayawake.utils import atomicwrite, env

STALE_AFTER_SECONDS = 600
_TIMES = ("last_good", "unacknowledged", "reminded", "acknowledged", "saved")


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
    return well_formed(data)


def well_formed(data) -> dict:
    """Keep the fields of a record that have the expected type. Takes what was read. Returns the
    record with every other field dropped."""
    if not isinstance(data, dict):
        return {}
    kept = {k: data[k] for k in _TIMES if is_time(data.get(k))}
    if isinstance(data.get("failures"), int) and data["failures"] >= 0:
        kept["failures"] = data["failures"]
    if isinstance(data.get("daily_for"), str):
        kept["daily_for"] = data["daily_for"][:16]
    for name in ("since", "sent"):
        held = data.get(name)
        if isinstance(held, dict):
            wanted = _is_count if name == "since" else is_time
            kept[name] = {str(k)[:32]: v for k, v in list(held.items())[:32] if wanted(v)}
    if isinstance(data.get("recent"), list):
        kept["recent"] = [t for t in data["recent"][-64:] if is_time(t)]
    return kept


def is_time(value) -> bool:
    """Tell whether a value is a usable timestamp. Takes the value. Returns the answer."""
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _is_count(value) -> bool:
    """Tell whether a value is a usable count. Takes the value. Returns the answer."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


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


def stale(record: dict, now: float, placed_since: float | None = None) -> bool:
    """Tell whether the watcher has stopped completing passes. Takes the record, the time now and
    when the watcher was placed, if known. Returns True when the last pass is too old or is dated
    in the future, or when there is none and the watcher was placed too long ago or at a time not
    known."""
    last = record.get("last_good")
    if not is_time(last):
        return placed_since is None or now - placed_since > STALE_AFTER_SECONDS
    return not 0 <= now - last <= STALE_AFTER_SECONDS


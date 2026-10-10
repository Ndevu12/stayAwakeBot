#!/usr/bin/env python3
"""What the watcher remembers about itself: event counts and times, never what it saw."""
from __future__ import annotations

import json
import math
import time
from pathlib import Path

from stayawake.utils import atomicwrite, env, pathsafe

STALE_AFTER_SECONDS = 600
MOST_BYTES = 64 << 10
MOST_COUNT = 10 ** 9
_TIMES = ("last_good", "unacknowledged", "reminded", "acknowledged", "saved", "undelivered")
_FLAGS = ("returned_unsent", "left_unsent")


def record_path() -> Path:
    """Find where the watcher keeps its record. Returns the path in saw's state folder."""
    return Path(env.xdg_state_home()) / "saw" / "watch-events.json"


def load(path: Path | None = None) -> dict:
    """Read the watcher's record. Takes an optional path. Returns the record, or an empty one
    when there is none or it cannot be read; never waits on anything that is not a file."""
    raw = pathsafe.read_regular_no_follow(path or record_path(), MOST_BYTES)
    if raw is None:
        return {}
    try:
        return well_formed(json.loads(raw.decode("utf-8", errors="replace")))
    except Exception:
        return {}


def well_formed(data) -> dict:
    """Keep the fields of a record that have the expected type. Takes what was read. Returns the
    record with every other field dropped."""
    if not isinstance(data, dict):
        return {}
    kept = {k: data[k] for k in _TIMES if is_time(data.get(k))}
    kept.update({k: True for k in _FLAGS if data.get(k) is True})
    if is_count(data.get("failures")):
        kept["failures"] = data["failures"]
    if isinstance(data.get("daily_for"), str):
        kept["daily_for"] = data["daily_for"][:16]
    for name in ("since", "sent"):
        held = data.get(name)
        if isinstance(held, dict):
            wanted = is_count if name == "since" else is_time
            kept[name] = {str(k)[:32]: v for k, v in list(held.items())[:32] if wanted(v)}
    if isinstance(data.get("recent"), list):
        kept["recent"] = [t for t in data["recent"][-64:] if is_time(t)]
    return kept


def is_time(value) -> bool:
    """Tell whether a value is a usable timestamp. Takes the value. Returns the answer."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def is_count(value) -> bool:
    """Tell whether a value is a usable count. Takes the value. Returns the answer."""
    return (isinstance(value, int) and not isinstance(value, bool)
            and 0 <= value <= MOST_COUNT)


def save(record: dict, path: Path | None = None) -> bool:
    """Write the watcher's record. Takes the record and an optional path. Returns whether it was
    written."""
    where = path or record_path()
    try:
        where.parent.mkdir(parents=True, exist_ok=True)
        if where.is_symlink():
            return False
        return atomicwrite.replace(where, json.dumps(record, sort_keys=True), mode=0o600)
    except Exception:
        return False


def acknowledge(path: Path | None = None, *, now=time.time) -> bool:
    """Mark code that came back as dealt with. Takes an optional path. Returns whether the record
    holds no unacknowledged return afterwards."""
    record = load(path)
    if not record.get("unacknowledged"):
        return True
    for name in ("unacknowledged", "reminded", "returned_unsent"):
        record.pop(name, None)
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

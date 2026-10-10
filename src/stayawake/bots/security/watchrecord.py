#!/usr/bin/env python3
"""What the watcher remembers about itself: event counts and times, never what it saw."""
from __future__ import annotations

import json
import math
import re
import secrets
from pathlib import Path

from stayawake.utils import atomicwrite, pathsafe

STALE_AFTER_SECONDS = 600
MOST_BYTES = 64 << 10
MOST_COUNT = 10 ** 9
_TIMES = ("last_good", "unacknowledged", "reminded", "saved", "undelivered")
_FLAGS = ("returned_unsent", "left_unsent", "window_reopened")
_EPOCH = re.compile(r"[0-9a-f]{1,32}")


def shared_folder() -> Path:
    """Find the folder the scheduled watcher and the user's own commands both read and write.
    Returns it under the home folder, whatever either environment sets for state."""
    return Path.home() / ".local" / "state" / "saw"


def record_path() -> Path:
    """Find where the watcher keeps its record. Returns the path."""
    return shared_folder() / "watch-events.json"


def new_epoch() -> str:
    """Name a new record, so an acknowledgement for an earlier one never applies to it. Returns
    the name."""
    return secrets.token_hex(8)


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
    for name in ("failures", "returns_seen"):
        if is_count(data.get(name)):
            kept[name] = data[name]
    if is_epoch(data.get("epoch")):
        kept["epoch"] = data["epoch"]
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


def is_epoch(value) -> bool:
    """Tell whether a value names a record. Takes the value. Returns the answer."""
    return isinstance(value, str) and _EPOCH.fullmatch(value) is not None


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


def acknowledgement_path() -> Path:
    """Find where `saw harden` records that it dealt with code that came back. Returns the path."""
    return shared_folder() / "watch-acknowledged.json"


def returns_so_far(record: dict) -> tuple[str, int] | None:
    """Say which returns a record has counted. Takes the record. Returns its name and how many
    returns it has seen, or None when it names none."""
    epoch = record.get("epoch")
    return (epoch, record.get("returns_seen", 0)) if is_epoch(epoch) else None


def acknowledge(through: tuple[str, int], path: Path | None = None) -> bool:
    """Record that a `saw harden` run dealt with every return the watcher had counted when it
    started. Takes the record's name and that count, and an optional path. Returns whether it was
    written."""
    epoch, count = through
    return save({"epoch": epoch, "through": count}, path or acknowledgement_path())


def load_acknowledgement(path: Path | None = None) -> tuple[str, int] | None:
    """Read the last acknowledgement `saw harden` recorded. Takes an optional path. Returns the
    record's name and the count of returns dealt with, or None when there is none to use."""
    raw = pathsafe.read_regular_no_follow(path or acknowledgement_path(), MOST_BYTES)
    try:
        data = json.loads(raw.decode("utf-8")) if raw is not None else None
        epoch, through = data.get("epoch"), data.get("through")
        if is_epoch(epoch) and is_count(through):
            return epoch, through
    except Exception:
        pass
    return None


def settled(record: dict, acknowledgement) -> dict:
    """Apply `saw harden`'s acknowledgement to the watcher's record. Takes the record and the
    acknowledgement, or None. Returns the record with its returns marked as dealt with when the
    acknowledgement names this record and covers every return it has counted; a return counted
    after that run started stays open."""
    rec = dict(record)
    if not acknowledgement or not rec.get("unacknowledged"):
        return rec
    epoch, through = acknowledgement
    if rec.get("epoch") == epoch and rec.get("returns_seen", 0) <= through:
        for name in ("unacknowledged", "reminded", "returned_unsent"):
            rec.pop(name, None)
        rec["window_reopened"] = True
    return rec


def stale(record: dict, now: float, placed_since: float | None = None) -> bool:
    """Tell whether the watcher has stopped completing passes. Takes the record, the time now and
    when the watcher was placed, if known. Returns True when the last pass is too old or is dated
    in the future, or when there is none and the placement is too old, dated in the future or not
    known."""
    last = record.get("last_good")
    if not is_time(last):
        return placed_since is None or not 0 <= now - placed_since <= STALE_AFTER_SECONDS
    return not 0 <= now - last <= STALE_AFTER_SECONDS

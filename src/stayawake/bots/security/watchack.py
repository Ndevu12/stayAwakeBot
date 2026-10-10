#!/usr/bin/env python3
"""`saw harden`'s acknowledgement that code which came back was dealt with, and how it settles
the watcher's record."""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security import watchrecord
from stayawake.bots.security.watchstate import CAME_BACK


def acknowledgement_path() -> Path:
    """Find where `saw harden` records that it dealt with code that came back. Returns the path."""
    return watchrecord.shared_folder() / "watch-acknowledged.json"


def returns_so_far(record: dict) -> tuple[str, int] | None:
    """Say which returns a record has counted. Takes the record. Returns its name and how many
    returns it has seen, or None when it names none."""
    epoch = record.get("epoch")
    return (epoch, record.get("returns_seen", 0)) if watchrecord.is_epoch(epoch) else None


def acknowledge(through: tuple[str, int], path: Path | None = None) -> bool:
    """Record that a `saw harden` run dealt with every return the watcher had counted when it
    started. Takes the record's name and that count, and an optional path. Returns whether it was
    written."""
    epoch, count = through
    return watchrecord.write_state(path or acknowledgement_path(),
                                   {"epoch": epoch, "through": count})


def load_acknowledgement(path: Path | None = None) -> tuple[str, int] | None:
    """Read the last acknowledgement `saw harden` recorded. Takes an optional path. Returns the
    record's name and the count of returns dealt with, or None when there is none to use."""
    data = watchrecord.read_state(path or acknowledgement_path())
    if not isinstance(data, dict):
        return None
    epoch, through = data.get("epoch"), data.get("through")
    if watchrecord.is_epoch(epoch) and watchrecord.is_count(through):
        return epoch, through
    return None


def settled(record: dict, acknowledgement) -> dict:
    """Apply `saw harden`'s acknowledgement to the watcher's record. Takes the record and the
    acknowledgement, or None. Returns the record with code that came back marked as dealt with when
    the acknowledgement names this record and the exact count of returns it holds; a return counted
    after that run started stays open."""
    rec = dict(record)
    if not acknowledgement or "unacknowledged" not in rec:
        return rec
    epoch, through = acknowledgement
    if rec.get("epoch") == epoch and rec.get("returns_seen", 0) == through:
        rec.pop("unacknowledged", None)
        rec["pending"] = {k: v for k, v in rec.get("pending", {}).items() if k != CAME_BACK}
        rec["window_reopened"] = True
    return rec

#!/usr/bin/env python3
"""`saw harden`'s acknowledgement that the code the watcher found was dealt with, and how it
settles the watcher's record."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security import watchrecord
from stayawake.bots.security.watchstate import CAME_BACK, NOT_STOPPED


@dataclass(frozen=True)
class Counted:
    """What the watcher's record held when a `saw harden` run started: the record's name, how many
    returns it had counted, and when the current streak of code that could not be stopped began."""
    epoch: str
    returns: int
    not_stopped: float | None = None


def acknowledgement_path() -> Path:
    """Find where `saw harden` records what it dealt with. Returns the path."""
    return watchrecord.shared_folder() / "watch-acknowledged.json"


def counted_so_far(record: dict) -> Counted | None:
    """Say what a record holds for `saw harden` to deal with. Takes the record. Returns what it
    counted, or None when it names no record."""
    epoch = record.get("epoch")
    if not watchrecord.is_epoch(epoch):
        return None
    return Counted(epoch, record.get("returns_seen", 0), record.get("not_stopped"))


def acknowledge(counted: Counted, path: Path | None = None) -> bool:
    """Record that a `saw harden` run dealt with what the watcher had counted when it started.
    Takes that count and an optional path. Returns whether it was written."""
    data = {"epoch": counted.epoch, "through": counted.returns}
    if counted.not_stopped is not None:
        data["not_stopped"] = counted.not_stopped
    return watchrecord.write_state(path or acknowledgement_path(), data)


def load_acknowledgement(path: Path | None = None) -> Counted | None:
    """Read the last acknowledgement `saw harden` recorded. Takes an optional path. Returns what it
    dealt with, or None when there is none to use."""
    data = watchrecord.read_state(path or acknowledgement_path())
    if not isinstance(data, dict):
        return None
    epoch, through, not_stopped = data.get("epoch"), data.get("through"), data.get("not_stopped")
    if not (watchrecord.is_epoch(epoch) and watchrecord.is_count(through)):
        return None
    return Counted(epoch, through, not_stopped if watchrecord.is_time(not_stopped) else None)


def settled(record: dict, acknowledgement: Counted | None) -> dict:
    """Apply `saw harden`'s acknowledgement to the watcher's record. Takes the record and the
    acknowledgement, or None. Returns the record with what that run dealt with marked as such:
    code that came back when it names this record and the exact count of returns it holds, and
    code that could not be stopped when it names the same streak; anything counted after that run
    started stays open."""
    rec = dict(record)
    if not acknowledgement or rec.get("epoch") != acknowledgement.epoch:
        return rec
    dealt_with = []
    if "unacknowledged" in rec and rec.get("returns_seen", 0) == acknowledgement.returns:
        rec.pop("unacknowledged")
        dealt_with.append(CAME_BACK)
    if "not_stopped" in rec and rec["not_stopped"] == acknowledgement.not_stopped:
        rec.pop("not_stopped")
        dealt_with.append(NOT_STOPPED)
    if dealt_with:
        rec["pending"] = {k: v for k, v in rec.get("pending", {}).items() if k not in dealt_with}
        rec["window_reopened"] = True
    return rec

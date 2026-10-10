#!/usr/bin/env python3
"""The watcher's record: event counts and times, never what it saw, kept where the scheduled
watcher and the user's own commands both find it."""
from __future__ import annotations

import json
import math
import os
import pwd
import re
import secrets
from pathlib import Path

from stayawake.utils import atomicwrite, pathsafe

MOST_BYTES = 64 << 10
MOST_COUNT = 10 ** 9
_TIMES = ("last_good", "unacknowledged", "not_stopped", "saved", "undelivered", "urgent_at",
          "backoff_until", "watching_since")
_COUNTS = ("failures", "returns_seen", "backoff")
_FLAGS = ("window_reopened",)
_EPOCH = re.compile(r"[0-9a-f]{1,32}")
_NAME = re.compile(r"[a-z][a-z-]{0,31}")


def shared_folder() -> Path:
    """Find the folder the scheduled watcher and the user's own commands both read and write.
    Returns it under the home folder of the account saw acts for, whatever either environment
    sets."""
    try:
        home = Path(pwd.getpwuid(acting_for()[0]).pw_dir)
    except (KeyError, OSError):
        home = Path.home()
    return home / ".local" / "state" / "saw"


def acting_for() -> tuple[int, int]:
    """Name the account saw acts for: the user who ran `sudo` when saw runs as root through it,
    else the account running saw. Returns its user and group ids."""
    if os.geteuid() == 0:
        try:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            if uid > 0:
                return uid, gid
        except (KeyError, ValueError):
            pass
    return os.getuid(), os.getgid()


def record_path() -> Path:
    """Find where the watcher keeps its record. Returns the path."""
    return shared_folder() / "watch-events.json"


def new_epoch() -> str:
    """Name a new record, so an acknowledgement for an earlier one never applies to it. Returns
    the name."""
    return secrets.token_hex(8)


def load(path: Path | None = None) -> dict:
    """Read the watcher's record. Takes an optional path. Returns the record with every field of
    the wrong shape dropped, or an empty one when there is none or it cannot be read."""
    return well_formed(read_state(path or record_path()))


def save(record: dict, path: Path | None = None) -> bool:
    """Write the watcher's record. Takes the record and an optional path. Returns whether it was
    written."""
    return write_state(path or record_path(), record)


def read_state(where: Path):
    """Read one of the watcher's state files, never waiting on anything that is not a file and
    never failing. Takes the path. Returns the parsed content, or None."""
    raw = pathsafe.read_regular_no_follow(where, MOST_BYTES)
    try:
        return json.loads(raw.decode("utf-8")) if raw is not None else None
    except Exception:
        return None


def write_state(where: Path, data: dict) -> bool:
    """Write one of the watcher's state files privately and atomically, never through a link and
    never failing; written for another account (under `sudo`), it is handed to that account and
    no folder is created. Takes the path and the content. Returns whether it was written."""
    uid, gid = acting_for()
    for_another = uid != os.geteuid()
    try:
        if for_another and not where.parent.is_dir():
            return False
        where.parent.mkdir(parents=True, exist_ok=True)
        if where.is_symlink():
            return False
        if not atomicwrite.replace(where, json.dumps(data, sort_keys=True), mode=0o600):
            return False
        if for_another:
            os.lchown(where, uid, gid)
        return True
    except Exception:
        return False


def well_formed(data) -> dict:
    """Keep the fields of a record that have the expected type. Takes what was read. Returns the
    record with every other field dropped."""
    if not isinstance(data, dict):
        return {}
    kept = {k: data[k] for k in _TIMES if is_time(data.get(k))}
    kept.update({k: data[k] for k in _COUNTS if is_count(data.get(k))})
    kept.update({k: True for k in _FLAGS if data.get(k) is True})
    if is_epoch(data.get("epoch")):
        kept["epoch"] = data["epoch"]
    if isinstance(data.get("daily_for"), str):
        kept["daily_for"] = data["daily_for"][:16]
    for name, wanted in (("since", is_count), ("told", is_time), ("pending", lambda v: v is True)):
        held = data.get(name)
        if isinstance(held, dict):
            kept[name] = {k: v for k, v in list(held.items())[:32]
                          if isinstance(k, str) and _NAME.fullmatch(k) and wanted(v)}
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

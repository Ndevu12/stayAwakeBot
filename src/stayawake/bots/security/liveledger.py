#!/usr/bin/env python3
"""What this machine has seen running, kept between runs.

A ledger of code fingerprints: when each was first and last seen, how often, whether the corpus
identified it, and whether it was ended.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from stayawake.utils import env, pathsafe


ABSENT, LOADED, CORRUPT, EDITED = "absent", "loaded", "corrupt", "edited"

_MAX_ENTRIES = 512
_MOST_BYTES = 4 << 20


def ledger_path() -> Path:
    """Where the record is kept."""
    return Path(env.xdg_state_home()) / "saw" / "live-code.json"


def _self_hash(entries: dict, last_pass: str | None = None) -> str:
    """Hash what the record holds. Takes its rows and, from version 2, its last pass. Returns the
    hash."""
    held = entries if last_pass is None else {"entries": entries, "last_pass": last_pass}
    return sha256(json.dumps(held, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass
class Seen:
    """What the record holds about one code fingerprint."""
    first: str = ""
    last: str = ""
    times: int = 0
    identified: bool = False
    ended: int = 0
    last_ended: str = ""


@dataclass
class Ledger:
    """The record as read, and how far it can be trusted."""
    entries: dict[str, Seen] = field(default_factory=dict)
    status: str = ABSENT
    last_pass: str = ""

    @property
    def trusted(self) -> bool:
        """Whether this run may say anything about what came before."""
        return self.status == LOADED

    def returning(self, key: str) -> int:
        """How many earlier runs saw `key`. Zero when the record is not trusted."""
        return self.entries[key].times if self.trusted and key in self.entries else 0

    def came_back(self, key: str) -> bool:
        """Tell whether code seen now had gone and is running again. Takes the fingerprint.
        Returns True when the trusted record saw it before and it was ended at its last sighting,
        or was missing from the last pass; never when the record cannot say."""
        seen = self.entries.get(key) if self.trusted else None
        if seen is None or not seen.last:
            return False
        ended_then = seen.last_ended == seen.last
        missing_since = bool(self.last_pass) and seen.last != self.last_pass
        return ended_then or missing_since


def load(path: Path | None = None) -> Ledger:
    """Read the record. Every failure is a STATE, never an exception and never an empty all-clear."""
    where = path or ledger_path()
    try:
        if not os.path.lexists(where):
            return Ledger(status=ABSENT)
    except (OSError, ValueError):
        return Ledger(status=CORRUPT)
    raw = pathsafe.read_regular_following(where, _MOST_BYTES)
    if raw is None:
        return Ledger(status=CORRUPT)
    try:
        return _parsed(raw)
    except Exception:
        return Ledger(status=CORRUPT)


def _parsed(raw: bytes) -> Ledger:
    """Turn the record's bytes into a ledger. Takes the bytes. Returns the ledger, CORRUPT when it
    is not one; it may raise on input built to make it."""
    data = json.loads(raw.decode("utf-8", errors="replace"))
    held = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(held, dict):
        return Ledger(status=CORRUPT)
    entries = {}
    current = data.get("version") == 2
    for key, row in held.items():
        if not isinstance(row, dict):
            return Ledger(status=CORRUPT)
        last, ended = str(row.get("last", ""))[:64], int(row.get("ended", 0) or 0)
        last_ended = str(row.get("last_ended", ""))[:64] if current else (last if ended else "")
        entries[str(key)] = Seen(first=str(row.get("first", ""))[:64], last=last,
                                 times=int(row.get("times", 0) or 0),
                                 identified=bool(row.get("identified")), ended=ended,
                                 last_ended=last_ended)
    last_pass = str(data.get("last_pass", ""))[:64] if data.get("version") == 2 else ""
    hashed = _self_hash(held, last_pass if data.get("version") == 2 else None)
    status = LOADED if data.get("self_hash") == hashed else EDITED
    return Ledger(entries=entries, status=status, last_pass=last_pass)


def record(ledger: Ledger, seen, ended_keys=(), now=None) -> Ledger:
    """Fold this run's sightings into `ledger` and return the result.

    Takes the ledger read at the start of the run, the `LiveCode` results, and the fingerprints that
    were ended. Returns a new ledger holding at most `_MAX_ENTRIES` identified and `_MAX_ENTRIES`
    other entries, the oldest of each dropped first.
    """
    from stayawake.bots.security.livecode import fingerprint
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    entries = dict(ledger.entries) if ledger.status in (LOADED, EDITED) else {}
    ended_keys = set(ended_keys)
    for item in seen:
        key = fingerprint(item.code) or f"noncode:{item.reason}"
        prior = entries.get(key, Seen(first=stamp))
        ended_now = key in ended_keys
        entries[key] = Seen(first=prior.first or stamp, last=stamp, times=prior.times + 1,
                            identified=prior.identified or bool(item.confirmed),
                            ended=prior.ended + (1 if ended_now else 0),
                            last_ended=stamp if ended_now else prior.last_ended)
    identified = {k: v for k, v in entries.items() if v.identified}
    others = {k: v for k, v in entries.items() if not v.identified}
    return Ledger(entries={**_newest(others), **_newest(identified)}, status=LOADED,
                  last_pass=stamp)


def _newest(entries: dict[str, Seen]) -> dict[str, Seen]:
    """Keep the most recently seen entries. Takes the entries. Returns at most `_MAX_ENTRIES`."""
    if len(entries) <= _MAX_ENTRIES:
        return entries
    return dict(sorted(entries.items(), key=lambda kv: kv[1].last, reverse=True)[:_MAX_ENTRIES])


def save(ledger: Ledger, path: Path | None = None) -> bool:
    """Write the record atomically. Returns whether it was written. Best effort by design."""
    where = path or ledger_path()
    rows = {k: {"first": v.first, "last": v.last, "times": v.times,
                "identified": v.identified, "ended": v.ended, "last_ended": v.last_ended}
            for k, v in ledger.entries.items()}
    payload = {"version": 2, "entries": rows, "last_pass": ledger.last_pass,
               "self_hash": _self_hash(rows, ledger.last_pass)}
    try:
        where.parent.mkdir(parents=True, exist_ok=True)
        if where.is_symlink():
            return False
        fd, tmp = tempfile.mkstemp(dir=str(where.parent), prefix=".live-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, where)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except OSError:
        return False
    return True

#!/usr/bin/env python3
"""What this machine has seen running, kept between runs.

A ledger of code fingerprints: when each was first and last seen, how often, whether the corpus
identified it, and whether it was ended.

TRAP: nothing here is load-bearing for safety, and the payload is never written to it.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from stayawake.utils import env


ABSENT, LOADED, CORRUPT, EDITED = "absent", "loaded", "corrupt", "edited"

_MAX_ENTRIES = 512


def ledger_path() -> Path:
    """Where the record is kept."""
    return Path(env.xdg_state_home()) / "saw" / "live-code.json"


def _self_hash(entries: dict) -> str:
    return sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass
class Seen:
    """What the record holds about one code fingerprint."""
    first: str = ""
    last: str = ""
    times: int = 0
    identified: bool = False
    ended: int = 0


@dataclass
class Ledger:
    """The record as read, and how far it can be trusted."""
    entries: dict[str, Seen] = field(default_factory=dict)
    status: str = ABSENT

    @property
    def trusted(self) -> bool:
        """Whether this run may say anything about what came before."""
        return self.status == LOADED

    def returning(self, key: str) -> int:
        """How many earlier runs saw `key`. Zero when the record is not trusted."""
        return self.entries[key].times if self.trusted and key in self.entries else 0


def load(path: Path | None = None) -> Ledger:
    """Read the record. Every failure is a STATE, never an exception and never an empty all-clear."""
    where = path or ledger_path()
    try:
        raw = where.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Ledger(status=ABSENT)
    except OSError:
        return Ledger(status=CORRUPT)
    try:
        data = json.loads(raw)
    except ValueError:
        return Ledger(status=CORRUPT)
    held = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(held, dict):
        return Ledger(status=CORRUPT)
    entries = {}
    for key, row in held.items():
        if not isinstance(row, dict):
            return Ledger(status=CORRUPT)
        entries[str(key)] = Seen(first=str(row.get("first", "")), last=str(row.get("last", "")),
                                 times=int(row.get("times", 0) or 0),
                                 identified=bool(row.get("identified")),
                                 ended=int(row.get("ended", 0) or 0))
    if data.get("self_hash") != _self_hash(held):
        return Ledger(entries=entries, status=EDITED)
    return Ledger(entries=entries, status=LOADED)


def record(ledger: Ledger, seen, ended_keys=(), now=None) -> Ledger:
    """Fold this run's sightings into `ledger` and return the result.

    Takes the ledger read at the start of the run, the `LiveCode` results, and the fingerprints that
    were ended. Returns a new ledger, bounded in size, with the oldest entries dropped first.
    """
    from stayawake.bots.security.livecode import fingerprint
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    entries = dict(ledger.entries) if ledger.status in (LOADED, EDITED) else {}
    ended_keys = set(ended_keys)
    for item in seen:
        key = fingerprint(item.code) or f"noncode:{item.reason}"
        prior = entries.get(key, Seen(first=stamp))
        entries[key] = Seen(first=prior.first or stamp, last=stamp, times=prior.times + 1,
                            identified=prior.identified or bool(item.confirmed),
                            ended=prior.ended + (1 if key in ended_keys else 0))
    if len(entries) > _MAX_ENTRIES:
        keep = sorted(entries.items(), key=lambda kv: kv[1].last, reverse=True)[:_MAX_ENTRIES]
        entries = dict(keep)
    return Ledger(entries=entries, status=LOADED)


def save(ledger: Ledger, path: Path | None = None) -> bool:
    """Write the record atomically. Returns whether it was written. Best effort by design."""
    where = path or ledger_path()
    rows = {k: {"first": v.first, "last": v.last, "times": v.times,
                "identified": v.identified, "ended": v.ended}
            for k, v in ledger.entries.items()}
    payload = {"version": 1, "entries": rows, "self_hash": _self_hash(rows)}
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

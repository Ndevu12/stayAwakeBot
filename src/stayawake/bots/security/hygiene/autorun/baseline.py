#!/usr/bin/env python3
"""Autorun BASELINE — cross-run state that adds a NOVELTY signal, and is never trusted for safety."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from stayawake.utils import env
from .surface import LOCATIONS, STAYS_REMOVED

VERSION = 2
NEW, CHANGED, KNOWN, RETURNED = "new", "changed", "known", "returned"
MAX_REMEMBERED = 256


def baseline_path() -> Path:
    override = env.autorun_baseline_path()
    if override:
        return Path(override)
    return Path(env.xdg_state_home()) / "saw" / "autorun-baseline.json"


def is_ephemeral() -> bool:
    """A disposable host (CI runner) where every run is a first run — no point reading/writing a
    longitudinal baseline. Ties to's environment distinction without depending on it."""
    return env.is_ci()


def _self_hash(entries: dict, removed: dict) -> str:
    return sha256(json.dumps({"entries": entries, "removed": removed},
                             sort_keys=True).encode("utf-8")).hexdigest()


def _hash_of_version_1(entries: dict[str, str]) -> str:
    return sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Seen:
    """What a run recorded about one entry: its content fingerprint, the surface it sits on, and
    whether that run actually enumerated it. A row restored from a version-1 snapshot has no
    location and carries the empty string."""
    digest: str
    location: str
    observed: bool = True


@dataclass
class Baseline:
    entries: dict[str, Seen] = field(default_factory=dict)
    removed: dict[str, str] = field(default_factory=dict)
    status: str = "absent"

    @property
    def trusted(self) -> bool:
        """Only a cleanly-loaded baseline contributes novelty. absent/corrupt/tampered → no novelty
        (never an all-clear — the other signals still grade every entry)."""
        return self.status == "loaded"


def _records(entries: dict) -> dict[str, Seen] | None:
    """Return the stored entry map as records, or None if any row is not one. A location outside the
    surface's own vocabulary makes the whole file untrustworthy rather than one row misfiled."""
    out: dict[str, Seen] = {}
    for key, value in entries.items():
        if not isinstance(value, dict):
            return None
        digest, location = value.get("digest"), value.get("location")
        observed = value.get("observed", True)
        if not isinstance(digest, str) or not isinstance(location, str):
            return None                        # an unhashable row would raise out of the membership test
        if location not in LOCATIONS or not isinstance(observed, bool):
            return None
        out[str(key)] = Seen(digest, location, observed)
    return out


def _restored_from_version_1(data: dict, entries: dict) -> Baseline:
    """Load a snapshot written before the removal record existed. Its entries still answer
    NEW/CHANGED/KNOWN, so a host that cannot rewrite its state file still tells new from known."""
    normalised = {str(k): str(v) for k, v in entries.items()}
    if data.get("self_hash") != _hash_of_version_1(normalised):
        return Baseline(status="tampered")
    return Baseline(entries={k: Seen(v, "") for k, v in normalised.items()}, status="loaded")


def load_baseline() -> Baseline:
    if is_ephemeral():
        return Baseline(status="absent")
    try:
        raw = baseline_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return Baseline(status="absent")
    except OSError:
        return Baseline(status="corrupt")
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return Baseline(status="corrupt")
    if not isinstance(data, dict):
        return Baseline(status="corrupt")
    entries, removed = data.get("entries"), data.get("removed", {})
    if not isinstance(entries, dict) or not isinstance(removed, dict):
        return Baseline(status="corrupt")
    if data.get("version") == 1:
        return _restored_from_version_1(data, entries)
    try:
        stamp = _self_hash(entries, removed)
    except (ValueError, RecursionError):
        return Baseline(status="corrupt")
    if data.get("version") != VERSION or data.get("self_hash") != stamp:
        return Baseline(status="tampered")     # lazy tamper, or a hand-edit → distrust the whole file
    seen = _records(entries)
    if seen is None or not all(isinstance(v, str) for v in removed.values()):
        return Baseline(status="corrupt")
    return Baseline(entries=seen, removed={str(k): v for k, v in removed.items()}, status="loaded")


def novelty(entries, baseline: Baseline) -> dict[str, str]:
    """Per-entry RETURNED / NEW / CHANGED / KNOWN — only when the baseline is trusted; otherwise every
    entry is KNOWN (novelty contributes nothing, so grading falls entirely to
    provenance/shape/correlation)."""
    if not baseline.trusted:
        return {e.key(): KNOWN for e in entries}
    out: dict[str, str] = {}
    for e in entries:
        key = e.key()
        if key in baseline.removed:
            out[key] = RETURNED
            continue
        prev = baseline.entries.get(key)
        if prev is None or not prev.observed:
            out[key] = NEW                     # a row no run enumerated cannot answer "known"
            continue
        out[key] = KNOWN if prev.digest == e.digest() else CHANGED
    return out


def _confirmed_gone(key: str, listing: dict) -> bool:
    """True only when this run listed the holding directory whole and the name is no longer an entry
    in it. Asked of the listing rather than of the path, so a name that is present but does not
    resolve — a symlink whose target is away — is never taken for a removal. A name held by a
    directory is the exception: that can never be an entry, however it got there."""
    path = Path(key)
    held = listing.get(path.parent)
    if held is None:
        return False
    if path.name not in held:
        return True
    try:
        return path.is_dir()
    except OSError:
        return False


def _bounded(fresh: dict[str, str], carried: dict[str, str]) -> dict[str, str]:
    """This run's removals first, then as many earlier ones as the bound allows — so a snapshot
    stuffed with removals cannot push out what this run actually saw."""
    out = dict(list(fresh.items())[:MAX_REMEMBERED])
    for key, when in carried.items():
        if len(out) >= MAX_REMEMBERED:
            break
        out.setdefault(key, when)
    return out


def _next_state(entries, base: Baseline, listing: dict,
                now: str) -> tuple[dict[str, Seen], dict[str, str]]:
    """The entry map and the removal record to write for the next run.

    Takes this run's entries, the baseline they were graded against, what each directory this run
    listed whole held, and the timestamp a removal is stamped with. Returns the two maps."""
    keep = {e.key(): Seen(e.digest(), e.location) for e in entries}
    if not base.trusted:
        return keep, {}
    fresh: dict[str, str] = {}
    carried_forward = 0
    for key, was in base.entries.items():
        if key in keep:
            continue
        # cloning a repository re-creates its git hooks, and so does `saw hook repair` — only a
        # surface nothing puts back on its own can answer whether something put this back
        if was.location not in STAYS_REMOVED:
            continue
        if _confirmed_gone(key, listing):
            fresh[key] = now
        elif carried_forward < MAX_REMEMBERED:
            keep[key] = Seen(was.digest, was.location, observed=False)
            carried_forward += 1
    carried = {k: t for k, t in base.removed.items() if k not in keep and k not in fresh}
    return keep, _bounded(fresh, carried)


def save_baseline(entries, base: Baseline, listing: dict) -> bool:
    """Snapshot the current surface, and what has gone from it, for the next run's novelty diff.
    Skipped on an ephemeral host. Atomic (mkstemp → os.replace). Returns whether it was written: a
    failure must not break the audit, but it must not pass unsaid either."""
    if is_ephemeral():
        return True
    now = datetime.now(timezone.utc).isoformat()
    keep, gone = _next_state(entries, base, listing, now)
    mapping = {k: {"digest": v.digest, "location": v.location, "observed": v.observed}
               for k, v in keep.items()}
    payload = {
        "version": VERSION,
        "captured": now,
        "entries": mapping,
        "removed": gone,
        "self_hash": _self_hash(mapping, gone),
    }
    try:
        path = baseline_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".autorun-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except OSError:
        return False
    return True

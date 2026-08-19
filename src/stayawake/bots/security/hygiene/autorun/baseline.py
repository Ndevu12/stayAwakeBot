#!/usr/bin/env python3
"""Autorun BASELINE — cross-run state that adds a NOVELTY signal, and is never trusted for safety.

The baseline records `{entry-path → content-digest}` from a prior run so a later run can tell what is
NEW or CHANGED. Crucially it is an ENHANCEMENT, not a trust boundary: a user-level worm runs as the
user and can write this file, so we treat it accordingly —

  * safety never depends on it — provenance + content-shape + correlation grade every entry regardless
    (see `grade`), so a tampered or first-run baseline cannot hide an unattributed foothold;
  * a lazily-tampered baseline (an entry added to launder it into "known" without fixing the integrity
    hash) is DETECTED and the whole baseline is treated as untrusted (novelty ignored);
  * a missing / corrupt / tampered baseline degrades to "no novelty" — never to a silent all-clear.

Stored under XDG state (`~/.local/state/saw/autorun-baseline.json`), overridable via
`SAW_AUTORUN_BASELINE`. On an ephemeral / CI host every run is a first run, so the baseline is neither
read nor written there (novelty is simply absent; the other three signals still run)."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from stayawake.utils import env

NEW, CHANGED, KNOWN = "new", "changed", "known"


def baseline_path() -> Path:
    override = env.autorun_baseline_path()
    if override:
        return Path(override)
    return Path(env.xdg_state_home()) / "saw" / "autorun-baseline.json"


def is_ephemeral() -> bool:
    """A disposable host (CI runner) where every run is a first run — no point reading/writing a
    longitudinal baseline. Ties to's environment distinction without depending on it."""
    return env.is_ci()


def _self_hash(entries: dict[str, str]) -> str:
    return sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass
class Baseline:
    entries: dict[str, str] = field(default_factory=dict)
    status: str = "absent"

    @property
    def trusted(self) -> bool:
        """Only a cleanly-loaded baseline contributes novelty. absent/corrupt/tampered → no novelty
        (never an all-clear — the other signals still grade every entry)."""
        return self.status == "loaded"


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
    except ValueError:
        return Baseline(status="corrupt")
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return Baseline(status="corrupt")
    entries = {str(k): str(v) for k, v in entries.items()}
    if data.get("self_hash") != _self_hash(entries):        # lazy tamper (or hand-edit) → distrust it
        return Baseline(entries=entries, status="tampered")
    return Baseline(entries=entries, status="loaded")


def novelty(entries, baseline: Baseline) -> dict[str, str]:
    """Per-entry NEW / CHANGED / KNOWN — only when the baseline is trusted; otherwise every entry is
    KNOWN (novelty contributes nothing, so grading falls entirely to provenance/shape/correlation)."""
    if not baseline.trusted:
        return {e.key(): KNOWN for e in entries}
    out: dict[str, str] = {}
    for e in entries:
        prev = baseline.entries.get(e.key())
        out[e.key()] = NEW if prev is None else (KNOWN if prev == e.digest() else CHANGED)
    return out


def save_baseline(entries) -> None:
    """Snapshot the current surface for the next run's novelty diff (best-effort; a write failure must
    never break the audit). Skipped on an ephemeral host. Atomic (mkstemp → os.replace)."""
    if is_ephemeral():
        return
    mapping = {e.key(): e.digest() for e in entries}
    payload = {
        "version": 1,
        "captured": datetime.now(timezone.utc).isoformat(),
        "entries": mapping,
        "self_hash": _self_hash(mapping),
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
        pass

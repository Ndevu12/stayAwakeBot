#!/usr/bin/env python3
"""A durable per-folder record of a govern check, keyed the way the editor keys it, so an editor can
read whether a check is going on and how it ended — checking, held, applied, or finished without
applying — without reading the stand-in's output or treating a successful exit as applied. It
outlives the holding directory system mode deletes when the check ends."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from stayawake.utils import atomicwrite

# The phases and verdicts the editor already reads (saw_ide_extension GovernPhase / FolderVerdict).
PHASES = ("checking", "held", "applied", "finished")


def _state_home() -> Path:
    base = os.environ.get("XDG_STATE_HOME", "").strip()
    return Path(base) if base else Path(os.path.expanduser("~")) / ".local" / "state"


def status_dir() -> Path:
    """The directory holding one record per open folder."""
    return _state_home() / "saw" / "govern" / "status"


def folder_key(repo: str | Path) -> str:
    """Key an open folder the way the editor does: the first 32 hex of sha256 of its absolute path."""
    return hashlib.sha256(os.path.abspath(repo).encode("utf-8")).hexdigest()[:32]


def status_path(repo: str | Path) -> Path:
    return status_dir() / f"{folder_key(repo)}.json"


def write(repo: str | Path, phase: str, *, verdict: str | None = None,
          reasons: list[str] | None = None, step: str | None = None) -> None:
    """Record where a check for `repo` is. Takes the open folder and the phase, with the verdict,
    reasons and step text when there are any. A write that fails is skipped."""
    try:
        status_dir().mkdir(parents=True, exist_ok=True)
        body: dict = {"repo": os.path.abspath(repo), "phase": phase,
                      "at": int(time.time() * 1000), "reasons": list(reasons or [])}
        if verdict:
            body["verdict"] = verdict
        if step:
            body["step"] = step
        atomicwrite.replace(status_path(repo), json.dumps(body))
    except OSError:
        pass


def read(repo: str | Path) -> dict | None:
    """Read the record for `repo`, or None when there is none."""
    try:
        return json.loads(status_path(repo).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

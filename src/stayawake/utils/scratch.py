#!/usr/bin/env python3
"""One root per run for everything it creates outside a repository, and its release."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT_PREFIX = "saw-run-"
RECORD = "run.json"
KEPT = "reports"

Teardown = Callable[[Path], str]


@dataclass(frozen=True)
class Area:
    """One directory a run created: where it is, what it is for, how it is torn down, and whether
    it outlives the run."""

    path: Path
    purpose: str
    teardown: Teardown | None = None
    kept: bool = False


_root: Path | None = None
_areas: list[Area] = []


def root() -> Path:
    """The directory this run puts everything under. Returns it, creating it on first use."""
    global _root
    if _root is None:
        _root = Path(tempfile.mkdtemp(prefix=ROOT_PREFIX))
        _write_record(_root)
    return _root


def _write_record(where: Path) -> None:
    """Record what this run is. Takes the root. Returns nothing."""
    try:
        (where / RECORD).write_text(json.dumps({
            "version": 1,
            "pid": os.getpid(),
            "uid": os.getuid(),
            "tmp_root": tempfile.gettempdir(),
        }, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def new_dir(purpose: str, *, teardown: Teardown | None = None) -> Path:
    """Make a directory under this run's root. Takes what it is for and how to tear it down.
    Returns the path."""
    base = root() / _slug(purpose)
    base.mkdir(parents=True, exist_ok=True)
    made = Path(tempfile.mkdtemp(dir=str(base)))
    _areas.append(Area(made, purpose, teardown))
    return made


def kept_dir(purpose: str) -> Path:
    """Make a directory the operator is given, which the run does not remove. Takes what it is for.
    Returns the path."""
    base = root() / KEPT / _slug(purpose)
    base.mkdir(parents=True, exist_ok=True)
    made = Path(tempfile.mkdtemp(dir=str(base)))
    _areas.append(Area(made, purpose, None, True))
    return made


def new_file(purpose: str, *, suffix: str = "", mode: int = 0o600) -> Path:
    """Make a file under this run's root. Takes what it is for, a suffix and the mode. Returns the
    path."""
    base = root() / _slug(purpose)
    base.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(base), suffix=suffix)
    os.close(fd)
    path = Path(name)
    os.chmod(path, mode)
    _areas.append(Area(path, purpose))
    return path


def release_path(path: Path) -> str:
    """Release one area this run made, before the run ends. Takes its path. Returns "" when it is
    gone, else why it is not."""
    for area in list(_areas):
        if area.path == path:
            _areas.remove(area)
            return _remove(area)
    return ""


def held() -> list[Area]:
    """Everything this run has made and not yet released. Returns them, newest first."""
    return list(reversed(_areas))


def release() -> list[str]:
    """Remove what this run made, newest first, keeping what the operator was given. Returns a
    reason for each one that could not be removed."""
    global _root
    reasons: list[str] = []
    for area in reversed(_areas):
        if area.kept:
            continue
        why = _remove(area)
        if why:
            reasons.append(f"{area.purpose} at {area.path}: {why}")
    _areas.clear()
    if _root is not None:
        reasons.extend(_drop_root(_root))
        _root = None
    return reasons


def _remove(area: Area) -> str:
    """Remove one area. Takes it. Returns "" when it is gone, else why it is not."""
    if area.teardown is not None:
        why = area.teardown(area.path)
        if why:
            return why
    if not area.path.exists():
        return ""
    return _rmtree(area.path)


def _drop_root(where: Path) -> list[str]:
    """Remove the run's own root once its areas are gone, unless the operator was given something
    under it. Takes the root. Returns a reason for each failure."""
    kept = where / KEPT
    if kept.is_dir() and any(kept.iterdir()):
        return []
    record = where / RECORD
    if record.exists():
        try:
            record.unlink()
        except OSError as exc:
            return [f"the run record at {record}: {exc}"]
    why = _rmtree(where)
    return [f"the run directory at {where}: {why}"] if why else []


def _rmtree(path: Path) -> str:
    """Remove a tree, reopening a directory that denies it once. Takes the path. Returns "" when it
    is gone, else why it is not."""
    problems: list[str] = []

    def reopen(func, target, exc):
        try:
            os.chmod(Path(target).parent, 0o700)
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            problems.append(f"{target}: {exc}")

    try:
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=reopen)
        else:
            shutil.rmtree(path, onerror=lambda f, t, ei: reopen(f, t, ei[1]))
    except OSError as exc:
        return str(exc)
    if path.exists():
        return problems[0] if problems else "still present"
    return ""


def _slug(purpose: str) -> str:
    """A directory name for a purpose. Takes the purpose. Returns the name."""
    out = "".join(c if c.isalnum() or c in "-_" else "-" for c in purpose.lower())
    return out.strip("-") or "scratch"

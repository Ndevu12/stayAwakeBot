#!/usr/bin/env python3
"""The repositories this process created, the only ones git may run in as SAW_OWNED. Held in memory
only."""
from __future__ import annotations

import os
from pathlib import Path

_owned: set[str] = set()


def _key(path: str | Path) -> str:
    return os.path.realpath(str(path))


def own(path: str | Path) -> None:
    """Record `path` as a repository this process created. Takes the path. Returns nothing."""
    _owned.add(_key(path))


def disown(path: str | Path) -> None:
    """Forget `path`. Takes the path. Returns nothing."""
    _owned.discard(_key(path))


def is_owned(path: str | Path) -> bool:
    """Whether `path` is a repository this process created. Takes the path. Returns the answer."""
    return _key(path) in _owned

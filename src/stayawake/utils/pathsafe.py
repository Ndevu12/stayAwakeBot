#!/usr/bin/env python3
"""Path safety and identity — refuse to write through a symlink, and tell whether two names
refer to one real object."""
from __future__ import annotations

import os
import stat
from pathlib import Path


def is_regular_file(path: Path) -> bool:
    """True iff `path` is a REGULAR file (follows symlinks; not a dir/FIFO/socket/device). Swallows
    OSError → False. The gate every "read an arbitrary file" path shares: opening a FIFO named like a
    real file read-BLOCKS forever, so callers must confirm regular-ness BEFORE `open()`."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except OSError:
        return False


def read_regular_bytes(path: Path) -> bytes | None:
    """The bytes of a regular file, or None if it is absent / non-regular / unreadable. NEVER opens a
    non-regular file (a FIFO would block forever —). One shared implementation for every probe
    that reads a possibly-adversarial path on disk."""
    if not is_regular_file(path):
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def read_regular_text(path: Path, *, errors: str = "replace") -> str | None:
    """The UTF-8 text of a regular file, or None (absent / non-regular / unreadable). Decodes
    tolerantly (`errors="replace"` by default) so a non-UTF-8 byte can't crash a read of an
    attacker-influenced file — the same evasion-safe decoding the scanner uses. Never opens a
    non-regular file."""
    if not is_regular_file(path):
        return None
    try:
        return path.read_text(encoding="utf-8", errors=errors)
    except OSError:
        return None


def is_safe_write_target(path: Path, root: Path) -> bool:
    """True only if writing to / deleting `path` stays inside `root` and does NOT go through a symlink.

    Refuses:
      * a symlinked LEAF — `write_text`/`rmtree` would follow it into a planted sink;
      * a path that RESOLVES outside `root` — a symlinked ancestor directory, or a `..` escape.
    Both operands are `resolve()`d, so a `root` that itself lives under a symlink (e.g. macOS
    `/tmp`→`/private/tmp`) does NOT cause a false refusal. Fails CLOSED (returns False) on any resolve
    error — e.g. a symlink loop — so an undecidable path is never treated as writable. Callers write
    only after this returns True (check-then-write; a same-process TOCTOU race on a static checkout is
    out of the threat model).

    NOTE: `root` must be a real (non-symlinked) directory the caller controls — do not pass a
    potentially attacker-planted directory as its OWN root, or a symlinked root would trivially contain
    itself. Pass the fixed parent the target is meant to stay under.
    """
    try:
        if path.is_symlink():
            return False
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return False


def canonical_id(path: str | Path) -> tuple | str:
    """An identity two names for the same object share.

    `(st_dev, st_ino)` only when `st_ino` is truthy — some mounts report 0, and collapsing on that
    would stop real directories being probed — then non-strict realpath (never `strict=True`: it
    raises on the missing/ELOOP/EACCES paths still worth probing), then the string. Fails OPEN, so
    an unresolvable path stays DISTINCT and means more probing, never less.
    """
    try:
        st = os.stat(path)
        if st.st_ino:
            return (st.st_dev, st.st_ino)
    except (OSError, ValueError):
        pass
    try:
        return os.path.realpath(path)
    except (OSError, ValueError):
        return str(path)


def distinct(paths) -> int:
    """How many of `paths` name genuinely different objects."""
    return len({canonical_id(p) for p in paths})

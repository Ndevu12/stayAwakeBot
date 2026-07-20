#!/usr/bin/env python3
"""Write-target safety — refuse to write/delete through a symlink or outside an intended root.

A tool that writes files inside a directory it does not fully control (a repository it is remediating,
a worktree it is proposing changes to) can be tricked by a planted **symlink** at a write target — or a
symlinked ancestor directory — into writing THROUGH the link into a sink outside the tree (`~/.bashrc`,
`.git/hooks/…`, `/etc/…`). This is the SymJacking / GhostApproval write-through vector (stayawakebot
#1161/#1218; the `saw fix` clean-text rewrite was first guarded in #1204). Factored out here as ONE
pure implementation every write/delete path shares.

Pure and stdlib-only (a `utils` leaf): `Path.resolve()` only CANONICALIZES a path — it never opens or
follows a target to read it — so it is safe to call on an attacker-controlled path; it turns a symlinked
ancestor or a `..` escape into a location outside the root, which the containment check then rejects.
"""
from __future__ import annotations

from pathlib import Path


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

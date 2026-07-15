#!/usr/bin/env python3
"""Synthesize the clean 3-way auto-merge tree of two commits — the baseline the recorded
merge is compared against to find review-evading deviation."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.run import run


def auto_merge_tree(repo: str | Path, a: str, b: str) -> str | None:
    """OID of the tree produced by a clean 3-way merge of commits `a` and `b` (their
    merge-base auto-detected). Returns the tree even when the auto-merge *conflicts* (so the
    recorded merge can be compared against the conflicted result). None when git lacks
    `merge-tree --write-tree` (pre-2.38) or the command errors.
    """
    res = run(repo, ["merge-tree", "--write-tree", a, b])
    if res is None or res.returncode not in (0, 1):   # 0 = clean, 1 = conflicts; else unsupported
        return None
    oid = res.stdout.split("\n", 1)[0].strip() if res.stdout else ""
    is_oid = bool(oid) and len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid)
    return oid if is_oid else None

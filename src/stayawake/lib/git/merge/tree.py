#!/usr/bin/env python3
"""Replay the merge git WOULD have produced — the only baseline an evil-merge claim can rest on."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import run


@dataclass(frozen=True)
class AutoMerge:
    """The tree a clean 3-way merge produces, and the paths where it CONFLICTED.

    The conflict set is load-bearing: where git merged cleanly its algorithm is deterministic, so a
    tree that differs there was hand-edited; where it conflicted, a resolution is expected to."""
    tree: str
    conflicted: frozenset[str]


def auto_merge(repo: str | Path, a: str, b: str) -> AutoMerge | None:
    """The clean 3-way auto-merge of `a` and `b`, or None when there ISN'T one (unrelated histories,
    octopus, pre-2.38 git). The caller must NOT substitute a parent tree: against a parent, every path
    the other side contributed reads as introduced — a whole sync merge reported as an attack."""
    res = run(repo, ["merge-tree", "--write-tree", "--name-only", a, b])
    if res is None or res.returncode not in (0, 1):   # 0 clean, 1 conflicts, 128 unrelated histories
        return None
    lines = (res.stdout or "").splitlines()
    oid = lines[0].strip() if lines else ""
    if not (oid and len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid)):
        return None
    # `<oid>`, the conflicted paths, a BLANK LINE, then git's own messages. Skipping blanks
    # instead of stopping at the first one put `Auto-merging f.txt` and `CONFLICT (content): ...`
    # in the conflict set — read as paths by anything that iterates it.
    conflicted = []
    for line in lines[1:]:
        if not line.strip():
            break
        conflicted.append(line.strip())
    return AutoMerge(oid, frozenset(conflicted))


def auto_merge_tree(repo: str | Path, a: str, b: str) -> str | None:
    """The auto-merge tree OID alone, for callers that do not need the conflict set."""
    merged = auto_merge(repo, a, b)
    return merged.tree if merged else None

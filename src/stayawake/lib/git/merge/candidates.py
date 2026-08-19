#!/usr/bin/env python3
"""Enumerate merge commits that are *candidates* for an evil merge — the cheap prefilter
before the per-candidate merge-tree confirm in `detect.evil_merge_paths`."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import stdout

_MERGE_REFS = ("--branches", "--tags", "--remotes")


def merge_commits(repo: str | Path, refs: tuple[str, ...] = _MERGE_REFS) -> list[str]:
    """SHAs of merge commits that are *candidates* for an evil merge — ALL of them,
    with no count cap (closes the G1 "merge buried behind N newer merges" miss).

    Enumeration is one git process: `git log --merges --diff-merges=first-parent
    --name-only` emits, per merge, the FIRST-PARENT diff (the change the merge brought
    onto the mainline a reviewer follows). A merge whose first-parent diff is EMPTY
    changed nothing relative to mainline (a redundant/ff-equivalent merge) and cannot
    smuggle content, so it is dropped here before any merge-tree cost is paid. Every
    other merge survives as a candidate for `evil_merge_paths` to confirm (and discard
    via the corroboration gate if benign).

    Why `--diff-merges=first-parent` and NOT `-m --first-parent`: `--first-parent`
    restricts *traversal* to the mainline chain, so an evil merge that lives INSIDE a
    merged side-branch (reachable only through a second parent) would never be
    enumerated. `--diff-merges=first-parent` sets only the per-merge DIFF FORMAT and
    leaves traversal walking every merge — closing that miss while keeping the
    first-parent (byte-identity-agnostic, see G2 below) diff. (Needs git >= 2.31; the
    precise `evil_merge_paths` path already needs >= 2.38.)

    G2 — why NOT the combined diff (`-c`): the combined diff lists only paths that
    differ from **every** parent, so it is EMPTY for an octopus that pulls in a
    payload-carrying head (the payload is byte-identical to that parent) and for a
    2-parent `-X theirs`/conflict resolution that takes one side's payload verbatim.
    Prefiltering on it silently dropped exactly those evil merges before confirmation.
    The first-parent diff is byte-identity-agnostic and keeps them.

    Cost: enumeration is one history walk; the per-candidate merge-tree confirm in
    `evil_merge_paths` then runs on the survivors. The first-parent diff is non-empty
    for nearly every real merge, so this trades the combined-diff prefilter's
    aggressive (but unsound) drop for correctness; the `_MAX_CANDIDATES` cap in the
    matcher bounds the confirm phase on pathological repositories.
    """
    out = stdout(repo, ["log", "--merges", *refs, "--diff-merges=first-parent",
                        "--name-only", "--format=%x01%H"])
    candidates: list[str] = []
    cur: str | None = None
    nonempty = False
    for line in out.splitlines():
        if line.startswith("\x01"):              # record boundary: start of a new merge
            if cur and nonempty:
                candidates.append(cur)
            cur, nonempty = line[1:].strip(), False
        elif line.strip():                       # a path in this merge's first-parent diff
            nonempty = True
    if cur and nonempty:
        candidates.append(cur)
    return candidates

#!/usr/bin/env python3
"""Enumerate merge commits that are *candidates* for an evil merge — the cheap prefilter
before the per-candidate merge-tree confirm in `detect.evil_merge_paths`."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import stdout

# Reachability scope for merge enumeration (G6 resolution).
#
# Chosen scope = local branches + tags + remote-tracking refs; deliberately:
#   - NOT `--all`: `--all` ALSO walks refs/stash (every `git stash` is a 2/3-parent merge
#     commit — the canonical FP), refs/notes, refs/replace and fetched forge PR refs
#     (refs/pull/*), none of which a legitimate publish surface uses; all inflate FPs/cost.
#   - WITH `--remotes`, NOT just `--branches --tags`: an evil merge can live ONLY on a
#     remote-tracking ref the user has FETCHED (refs/remotes/origin/*) without yet merging
#     it into a local branch. That object is already in the local store and is a genuine
#     local compromise; `--branches --tags` alone cannot reach it (no local branch contains
#     it) and would MISS it. `--remotes` reaches it.
#
# Why `--remotes` does NOT re-FP on unauthored origin merges: the evil-merge gate is
# CONTENT-keyed (`_corroborated`), not ref-keyed. A benign origin-only merge carries no
# worm signature / no new-vs-all-parents inject / no context-aware obfuscation, so it
# survives enumeration but produces ZERO findings. Breadth only adds *candidates*; benign
# candidates are silently discarded by the gate. (Empirically verified against benign vs
# evil remote-only merges; see tests/bots/security/test_evil_merge.py G6 cases.)
#
# Cost/dedup: `git log` deduplicates by commit SHA, so a merge reachable from both a local
# branch and a remote-tracking ref is enumerated exactly once — `--remotes` adds no
# duplicate cost in the common (local==origin) case; it only adds genuinely-extra
# remote-only commits, which is exactly the recall we want. The `_MAX_CANDIDATES` cap in
# the matcher bounds the confirm phase even on a busy upstream with many merges.
#
# One ref family per token.
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

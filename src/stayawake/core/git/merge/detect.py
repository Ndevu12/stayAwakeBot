#!/usr/bin/env python3
"""The evil-merge detector: which paths a merge introduced BEYOND a clean 3-way merge of its
parents, gated through corroboration so benign conflict resolutions don't false-positive."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.query import parents, changed_paths
from stayawake.core.git.merge.tree import auto_merge_tree
from stayawake.core.git.merge.corroborate import corroborated


def evil_merge_paths(repo: str | Path, merge_sha: str, content_sig=None,
                     obfuscation_reason=None) -> dict[str, str]:
    """Paths whose content the merge introduced BEYOND a clean 3-way merge of its parents
    AND for which that introduction is CORROBORATED as review-evading (see `corroborated`).

    An evil merge smuggles content in the merge commit itself, where a normal PR review —
    which shows each parent's diff — can't see it. The raw signal "deviates from the clean
    auto-merge" is necessary but NOT sufficient: a legitimate conflict resolution picking a
    valid third variant of a line also deviates. So every deviating path is gated through
    `corroborated`, which keeps the finding only when the introduction is structurally
    review-evading (new file unseen by any parent) or its INTRODUCED hunk is a worm
    signature or context-aware obfuscation. This dissolves the conflict-resolution false
    positive while still catching novel obfuscated injection (G3).

    Returns {path: reason}. Pure deletions are NOT flagged (a removed path injects nothing).
    For octopus merges (>2 parents) or when git is too old for `merge-tree --write-tree`,
    the candidate set is "added/modified vs the FIRST parent" (mainline tip) — NOT the
    intersection across every parent. The intersection silently dropped any path
    byte-identical to one parent, so an octopus payload identical to a non-first parent (G2)
    produced no finding; the first-parent diff is byte-identity-agnostic and reaches it. The
    SAME corroboration gate is then applied, so a benign octopus stays clean.
    """
    ps = parents(repo, merge_sha)
    if len(ps) < 2:
        return {}

    deviating: set[str]
    base_tree: str | None = None
    if len(ps) == 2:
        base_tree = auto_merge_tree(repo, ps[0], ps[1])
    if base_tree is not None:
        deviating = changed_paths(repo, base_tree, merge_sha, diff_filter="AM")
    else:
        # Fallback (octopus / pre-2.38 git): we have no synthesized auto-merge tree, so the
        # FIRST parent (mainline tip) is the baseline a reviewer would compare against. The
        # candidate set is every path the merge ADDS/MODIFIES relative to that first parent
        # — i.e. everything the merge brings onto mainline.
        #
        # G2: we deliberately do NOT intersect "changed vs EVERY parent" here. That
        # intersection drops any path whose merge blob is byte-identical to even one parent
        # (an octopus that pulls a payload-carrying head, or a `-X theirs` resolution to one
        # side), so such a payload never reached the corroboration gate and produced NO
        # finding. The first-parent diff is byte-identity-agnostic: a payload identical to a
        # non-first parent still differs from the first parent and is examined. Topology
        # cannot separate evil from benign here; the corroboration gate (worm signature /
        # new-vs-all-parents / context-aware obfuscation of the introduced hunk) does — so a
        # benign octopus that merely combines clean branches still yields no finding.
        base_tree = ps[0]
        deviating = changed_paths(repo, base_tree, merge_sha, diff_filter="AM")

    flagged: dict[str, str] = {}
    for path in deviating:
        ok, reason = corroborated(repo, base_tree, merge_sha, path, ps, content_sig,
                                  obfuscation_reason)
        if ok:
            flagged[path] = reason
    return flagged

#!/usr/bin/env python3
"""Decide whether a path the merge deviates on is a REAL evil-merge signal.

The evidence available depends on what git could have done at that path, so the two cases are judged
apart rather than by one heuristic:
"""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.query import path_exists_at, introduced_added_text, file_at

CLEAN_DEVIATION = ("recorded content differs from the clean auto-merge at a path that did NOT "
                   "conflict — git cannot produce this, so it was edited during the merge")


def corroborated(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                 parent_shas: list[str], *, conflicted: bool = True,
                 content_sig=None, obfuscation_reason=None) -> tuple[bool, str]:
    """(corroborated, reason) for one deviating path. `conflicted` says whether the auto-merge
    conflicted here; it defaults to True so an unknown conflict state demands content evidence
    rather than being handed the decisive verdict.

    Content and obfuscation checks are INJECTED as callables so this module (in `lib.git`) stays
    free of any `bots.security` import — a lower layer must never depend up on the security domain. `content_sig` is `callable(text) -> reason|None`; `obfuscation_reason` is
    `callable(path, delta, baseline_text) -> reason|None`. Absent → not evaluated."""
    # A file no parent carries is review-evading whatever its content: no parent's diff shows it.
    if all(not path_exists_at(repo, p, path) for p in parent_shas):
        return True, "introduced file absent from every parent (review-evading)"

    first_parent = parent_shas[0]
    baselines = [base_tree] if first_parent == base_tree else [base_tree, first_parent]
    pairs = [(b, introduced_added_text(repo, b, merge_sha, path)) for b in baselines
             if path_exists_at(repo, b, path)]
    pairs = [(b, d) for b, d in pairs if d.strip()]
    deltas = [d for _b, d in pairs]
    if not deltas:
        # A deviation that ADDS nothing injects nothing — it removed or reordered. Real, but a
        # different question from "what did this merge smuggle in", which is this detector's
        # contract; flagging it here reported an ordinary edit as a payload.
        return False, ""

    if content_sig is not None:
        for d in deltas:
            hit = content_sig(d)
            if hit:
                return True, f"merge-introduced hunk matches signature: {hit}"

    if not conflicted:
        return True, CLEAN_DEVIATION

    # Conflicted: the resolution legitimately rewrites this path, so only EXECUTABLE obfuscation
    # counts. Density/entropy is not consulted — a resolution that pulls a file in wholesale reads as
    # one long high-entropy hunk, which is how ordinary framework source read as a packed payload.
    if obfuscation_reason is not None:
        for b, d in pairs:
            reason = obfuscation_reason(path, d, file_at(repo, b, path))
            if reason:
                return True, f"obfuscated merge-introduced hunk: {reason}"
    return False, ""

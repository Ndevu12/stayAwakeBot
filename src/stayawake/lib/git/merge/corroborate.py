#!/usr/bin/env python3
"""Decide whether a path the merge deviates on is a REAL evil-merge signal.

The evidence available depends on what git could have done at that path, so the two cases are judged
apart rather than by one heuristic:

  * the auto-merge did NOT conflict — git's algorithm is deterministic, so it could not have produced
    the recorded content. Somebody edited the file while merging. Decisive with no content analysis.
  * the auto-merge DID conflict — a human resolution is expected to deviate, so structure says
    nothing and only CONTENT can: a worm signature, or an executable-obfuscation construct in the
    introduced hunk.
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
    free of any `bots.security` import — a lower layer must never depend up on the security domain
    (#1236). `content_sig` is `callable(text) -> reason|None`; `obfuscation_reason` is
    `callable(path, delta, baseline_text) -> reason|None`. Absent → not evaluated."""
    # A file no parent carries is review-evading whatever its content: no parent's diff shows it.
    if all(not path_exists_at(repo, p, path) for p in parent_shas):
        return True, "introduced file absent from every parent (review-evading)"

    # WHICH baseline the introduced hunk is measured against decides everything.
    #
    # The auto-merge tree is the honest one, except at a CONFLICTED path: there the auto-merge blob
    # already carries both sides' text, so a resolution that takes a payload verbatim from one side
    # (`-X theirs`) introduces nothing against it and goes unseen (G2). The first parent — the
    # mainline a reviewer compares against — does see it.
    #
    # But the first parent is only a baseline for a path that EXISTS there. For a path the other side
    # contributed wholesale, the "introduced hunk" becomes the entire file measured against nothing,
    # and every whole-file property reads as an injected one: that is how 18 ordinary components of a
    # sync merge were reported as packed payloads.
    first_parent = parent_shas[0]
    baselines = [base_tree] if first_parent == base_tree else [base_tree, first_parent]
    # A baseline that does not CONTAIN the path gives no "before", so the whole file becomes the
    # "introduced hunk" and every whole-file property reads as an injected one. Such a baseline is
    # dropped: a signature still matches on content, but no shape claim is made from it.
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

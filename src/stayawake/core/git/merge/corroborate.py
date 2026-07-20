#!/usr/bin/env python3
"""Corroborate an introduced path as a REAL evil-merge signal — a raw "deviates from the
auto-merge" is not enough (benign conflict resolutions deviate too)."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.query import path_exists_at, introduced_added_text, file_at


def corroborated(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                 parent_shas: list[str], content_sig=None, obfuscation_reason=None) -> tuple[bool, str]:
    """Decide whether an introduced path is a CORROBORATED evil-merge signal, returning
    (corroborated, reason). A raw "this path deviates from the auto-merge" is NOT enough —
    benign conflict resolutions deviate too. We require one of:

      (a) NEW-vs-ALL-PARENTS — the path exists in the merge but in NONE of its parents.
          Such a file is structurally review-evading: no parent's PR diff shows it,
          regardless of its content. (Catches the classic injected-file evil merge.)
      (b) The merge-INTRODUCED hunk matches a worm content signature (loader fingerprint).
      (c) The merge-INTRODUCED hunk is OBFUSCATED relative to the file's pre-merge baseline
          (G3) — context-aware: suppressed in vendored/generated paths where obfuscation
          is expected; applied only to the introduced delta in hand-authored source.

    Both content and obfuscation checks are INJECTED as callables so this module (in `core.git`)
    stays free of any `bots.security` import — a lower layer must never depend up on the security
    domain (#1236). `content_sig` is `callable(text) -> reason|None` for (b); `obfuscation_reason`
    is `callable(path, delta, baseline_text) -> reason|None` for (c) (it owns the generated-context
    suppression). Absent (None) → that signal is simply not evaluated.
    """
    # (a) new vs ALL parents — content-agnostic, formatting-agnostic (presence test, so a
    #     binary file present in a parent is never misread as absent).
    if all(not path_exists_at(repo, p, path) for p in parent_shas):
        return True, "introduced file absent from every parent (review-evading)"

    # The review-evading hunk, measured against the auto-merge tree (what merging the
    # parents WOULD have produced). G2: when that auto-merge CONFLICTED at this path, the
    # conflicted tree already carries both sides' text — including a payload taken verbatim
    # from one side via `-X theirs`/manual resolution — so the auto-merge delta is empty and
    # misses it. We therefore ALSO measure the hunk against the FIRST parent (the mainline a
    # reviewer compares against): a payload resolved byte-identical to a non-first parent
    # still differs from the first parent. Corroborating on EITHER delta closes G2 without
    # re-flagging benign conflict resolutions (their first-parent hunk is ordinary code, as
    # the novel-conflict-resolution regression test asserts).
    first_parent = parent_shas[0]
    baselines = [base_tree] if base_tree == first_parent else [base_tree, first_parent]
    # (baseline, introduced-hunk) pairs with a non-empty hunk.
    pairs = [(b, introduced_added_text(repo, b, merge_sha, path)) for b in baselines]
    pairs = [(b, d) for b, d in pairs if d.strip()]
    if not pairs:
        return False, ""

    # (b) an introduced hunk matches a known worm content signature.
    if content_sig is not None:
        for _b, d in pairs:
            hit = content_sig(d)
            if hit:
                return True, f"merge-introduced hunk matches signature: {hit}"

    # (c) context-aware obfuscation of an introduced hunk (G3). The injected callable owns the
    # generated-context suppression AND the delta analysis, so no security-package import lands here.
    if obfuscation_reason is not None:
        for b, d in pairs:
            reason = obfuscation_reason(path, d, file_at(repo, b, path))
            if reason:
                return True, f"obfuscated merge-introduced hunk: {reason}"
    return False, ""

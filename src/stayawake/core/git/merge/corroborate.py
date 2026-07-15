#!/usr/bin/env python3
"""Corroborate an introduced path as a REAL evil-merge signal — a raw "deviates from the
auto-merge" is not enough (benign conflict resolutions deviate too)."""
from __future__ import annotations

from pathlib import Path

from stayawake.core.git.query import path_exists_at, introduced_added_text, file_at


def _is_generated_context(path: str) -> bool:
    """True when `path` is a vendored/minified/generated location where obfuscation is
    EXPECTED (the context-aware-confidence lever): suppress the obfuscation corroborator
    there so legitimate dense bundles never become evil-merge findings.

    Delegates to the single shared predicate in the security package so the merge
    corroborator and the whole-file obfuscation matcher use ONE source of truth and
    never drift. Imported lazily to keep core.git free of a hard security dependency."""
    from stayawake.bots.security.obfuscation import is_generated_context
    return is_generated_context(path)


def corroborated(repo: str | Path, base_tree: str, merge_sha: str, path: str,
                 parent_shas: list[str], content_sig=None) -> tuple[bool, str]:
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

    `content_sig` is an optional callable(text)->reason|None used for (b); kept injectable
    so this module stays free of the signature-DB import.
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

    # (c) context-aware obfuscation of an introduced hunk (G3).
    if not _is_generated_context(path):
        # Import here to keep core.git free of a hard security-package dependency.
        from stayawake.bots.security.obfuscation import analyze_delta
        for b, d in pairs:
            verdict = analyze_delta(d, file_at(repo, b, path))
            if verdict:
                return True, f"obfuscated merge-introduced hunk: {verdict.reason}"
    return False, ""

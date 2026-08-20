#!/usr/bin/env python3
"""Git-history matcher — the evil-merge detector."""
from __future__ import annotations

import sys

from stayawake.lib import git as gitutil
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_confirmed_loader_check
from stayawake.lib.git.merge.liveness import (introduced_liveness, describe,
                                              PRESENT, CHANGED, GONE, UNKNOWN)
from stayawake.bots.security.obfuscation import is_generated_context, analyze_delta


def _obfuscation_reason(path: str, delta: str, baseline: str) -> str | None:
    """Context-aware obfuscation signal (G3) for the evil-merge corroborator, INJECTED into
    `core.git`'s `evil_merge_paths` so that lower layer never imports the security domain.
    Owns the generated-context suppression (obfuscation is expected in vendored/minified paths, so
    a dense bundle there is never an evil-merge finding) and delegates the delta analysis to the
    single shared `analyze_delta` — one source of truth with the whole-file obfuscation matcher."""
    if is_generated_context(path):
        return None
    try:
        verdict = analyze_delta(delta, baseline)
    except Exception as exc:  # fail-SAFE: a detector fault on one hunk must not abort the sweep
        print(f"saw: obfuscation delta-analysis skipped for {path}: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return None
    return verdict.reason if verdict else None


_MAX_CANDIDATES = 2000

_LOADER_REASON_PREFIX = "merge-introduced hunk matches signature:"


def _liveness_note(repo, merge_sha: str, paths) -> str:
    """Whether the introduced content is STILL in the working tree. A merge that smuggled a payload
    and a merge whose payload was deleted three commits later need different responses, and the
    finding alone cannot tell them apart. Reported per state and never collapsed to "removed": a
    changed file may still carry the introduced lines."""
    states = [introduced_liveness(repo, merge_sha, p) for p in paths]
    if any(s == PRESENT for s in states):
        return f"{sum(s == PRESENT for s in states)} of {len(paths)} {describe(PRESENT)}"
    for state in (CHANGED, GONE):
        if any(s == state for s in states):
            return describe(state)
    return describe(UNKNOWN)


class GitHistoryMatcher(Matcher):
    handles = "git-history"

    def scan(self, target, signatures, all_signatures=None):
        by_conf = {s["id"]: s for s in signatures if s.get("kind") == "evil-merge"}
        if not by_conf or not gitutil.is_git_repo(target.repo_root):
            return []
        loader_sig = next((s for s in by_conf.values() if s.get("confidence") != "heuristic"), None)
        heuristic_sig = next((s for s in by_conf.values() if s.get("confidence") == "heuristic"), None)
        content_sig = build_confirmed_loader_check(all_signatures or signatures)
        findings: list[Finding] = []
        for sha in gitutil.merge_commits(target.repo_root)[:_MAX_CANDIDATES]:
            evil = gitutil.evil_merge_paths(target.repo_root, sha, content_sig=content_sig,
                                            obfuscation_reason=_obfuscation_reason)
            if not evil:
                continue
            meta = gitutil.commit_meta(target.repo_root, sha)
            paths = sorted(evil)
            loader_paths = [p for p in paths if evil[p].startswith(_LOADER_REASON_PREFIX)]
            sig = (loader_sig if loader_paths else heuristic_sig) or heuristic_sig or loader_sig
            why = evil[(loader_paths or paths)[0]]
            findings.append(Finding(
                signature_id=sig["id"], category=sig["category"],
                severity=Severity.parse(sig["severity"]), path=sha[:10],
                description=sig["description"], remediation=sig.get("remediation", "manual"),
                evidence=f"{len(evil)} corroborated path(s) introduced beyond a clean "
                         f"3-way merge; e.g. {paths[:3]} ({why}); "
                         f"{_liveness_note(target.repo_root, sha, paths)}; "
                         f"by {meta.get('author_email','?')}",
                vector="evil-merge", related_paths=tuple(paths), commit_sha=sha))
        return findings

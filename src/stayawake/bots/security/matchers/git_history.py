#!/usr/bin/env python3
"""Git-history matcher — the evil-merge detector."""
from __future__ import annotations

import sys

from stayawake.lib import git as gitutil
from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_confirmed_loader_check
from stayawake.bots.security.obfuscation import is_generated_context, analyze_delta


def _obfuscation_reason(path: str, delta: str, baseline: str) -> str | None:
    """Context-aware obfuscation signal (G3) for the evil-merge corroborator, INJECTED into
    `core.git`'s `evil_merge_paths` so that lower layer never imports the security domain (#1236).
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


# Bound on the EXPENSIVE per-candidate merge-tree confirmation phase (defense in depth
# for pathological repos with tens of thousands of genuine conflict-resolution merges).
# This caps post-prefilter *candidates*, NOT raw merges. `merge_commits` drops only true
# no-op merges (empty first-parent diff), so a buried evil merge — newest-first ordered —
# stays well within the cap and the G1 "buried behind many merges" case is always reached.
# Set high enough that no real repository ever hits it.
_MAX_CANDIDATES = 2000

# `corroborated()` (lib.git.merge.corroborate) tags a loader-signature match with this reason
# prefix. A merge carrying ANY such path is smuggling a KNOWN-malware payload past review — decisive
# on its own — so it routes to the CONFIRMED `evil-merge-loader` id; structural/obfuscation-only
# corroboration stays HEURISTIC `evil-merge`. Keep this in lockstep with corroborate.py's (b) reason.
_LOADER_REASON_PREFIX = "merge-introduced hunk matches signature:"


class GitHistoryMatcher(Matcher):
    handles = "git-history"

    def scan(self, target, signatures, all_signatures=None):
        # Two evil-merge signatures, graded by corroboration strength: the HEURISTIC baseline and the
        # CONFIRMED loader arm. The matcher owns the routing; the scanner stamps each finding's
        # confidence from its signature id (one source of truth). Fall back to whichever is present so
        # a caller passing a single evil-merge signature (older tests / a trimmed config) still works.
        by_conf = {s["id"]: s for s in signatures if s.get("kind") == "evil-merge"}
        if not by_conf or not gitutil.is_git_repo(target.repo_root):
            return []
        loader_sig = next((s for s in by_conf.values() if s.get("confidence") != "heuristic"), None)
        heuristic_sig = next((s for s in by_conf.values() if s.get("confidence") == "heuristic"), None)
        # Corroborate the merge-introduced hunk against worm loader fingerprints. The
        # content signatures live in their own matcher group; the scanner passes the full
        # signature set as `all_signatures` so we can reach them. Fall back to the
        # git-history group (loaders absent) when not provided.
        content_sig = build_confirmed_loader_check(all_signatures or signatures)
        findings: list[Finding] = []
        for sha in gitutil.merge_commits(target.repo_root)[:_MAX_CANDIDATES]:
            evil = gitutil.evil_merge_paths(target.repo_root, sha, content_sig=content_sig,
                                            obfuscation_reason=_obfuscation_reason)
            if not evil:
                continue
            meta = gitutil.commit_meta(target.repo_root, sha)
            paths = sorted(evil)
            # Route by the STRONGEST corroboration present in this merge: any loader-signature match
            # → the confirmed arm; else the heuristic arm. Degrade to whichever signature exists.
            loader_paths = [p for p in paths if evil[p].startswith(_LOADER_REASON_PREFIX)]
            sig = (loader_sig if loader_paths else heuristic_sig) or heuristic_sig or loader_sig
            why = evil[(loader_paths or paths)[0]]      # explain via the arm we routed on
            findings.append(Finding(
                signature_id=sig["id"], category=sig["category"],
                severity=Severity.parse(sig["severity"]), path=sha[:10],
                description=sig["description"], remediation=sig.get("remediation", "manual"),
                evidence=f"{len(evil)} corroborated path(s) introduced beyond a clean "
                         f"3-way merge; e.g. {paths[:3]} ({why}); "
                         f"by {meta.get('author_email','?')}",
                vector="evil-merge", related_paths=tuple(paths), commit_sha=sha))
        return findings

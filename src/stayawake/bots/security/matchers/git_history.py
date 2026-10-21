#!/usr/bin/env python3
"""Git-history matcher — the evil-merge detector."""
from __future__ import annotations

import re
import sys

from stayawake.lib import git as gitutil
from stayawake.bots.security.models import Finding, Severity, CONFIRMED, HEURISTIC, REPORT_ONLY
from stayawake.bots.security.matchers.base import Matcher, build_confirmed_loader_check, globs_ok
from stayawake.bots.security.matchers.content import matching_signatures
from stayawake.bots.security.matchers.npm_manifest import lifecycle_scripts
from stayawake.bots.security.dependencies.installed import stated_at
from stayawake.lib.git.merge import ReadBudget
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


MOST_MERGES_CHECKED = 2000

_LOADER_REASON_PREFIX = "merge-introduced hunk matches signature:"


def _merge_payload_check(signatures, left_out=frozenset()):
    """Build the check a merge's version of a file is held to: a known payload it carries that no
    earlier version of that file carries and that no file its parents wrote holds. Content signatures
    are matched as the content scan matches a file, each within the files it names; an install-script
    signature counts on a lifecycle script of package.json. Takes the signatures and the folders a
    scan leaves out. Returns `check(path, merged, earlier, held_by_a_parent) -> signature | None`,
    which raises `Unread` naming the path when the path could not be checked."""
    content = [(s, re.compile(s["pattern"], re.IGNORECASE)) for s in signatures
               if s.get("matcher") == "content" and s.get("pattern") and s.get("confidence") == CONFIRMED]
    scripts = [(s, re.compile(s["pattern"], re.IGNORECASE)) for s in signatures
               if s.get("matcher") == "npm-manifest" and s.get("pattern")
               and CONFIRMED in (s.get("confidence"), s.get("confidence_when_installed"))]

    def check(path, merged, earlier, held_by_a_parent):
        try:
            return judge(path, merged, earlier, held_by_a_parent)
        except gitutil.Unread:
            raise
        except Exception as exc:
            raise gitutil.Unread(path) from exc

    def judge(path, merged, earlier, held_by_a_parent):
        if any(part in left_out for part in path.split("/")[:-1]):
            return None
        scoped = [(s, rx) for s, rx in content if globs_ok(path, s)]
        carried = matching_signatures(merged, scoped)
        run = []
        if scripts and path.rsplit("/", 1)[-1] == "package.json":
            graded = [(sig, rx) for sig, rx in scripts
                      if stated_at(sig, "confidence", path) == CONFIRMED]
            for _key, cmd in lifecycle_scripts(merged):
                run += [(cmd, sig, m) for sig, rx in graded for m in [rx.search(cmd)] if m]
        if not carried and not run:
            return None
        before = earlier()
        held_before = {s["id"] for text in before for s, _m in matching_signatures(text, scoped)}
        for sig, m in carried:
            scope = (lambda rel, sig=sig: globs_ok(rel, sig)) if sig.get("file_globs") else None
            if sig["id"] not in held_before and not _written_by_a_parent(m.group(0), held_by_a_parent,
                                                                         scope, sig["id"]):
                return sig
        ran_before = {cmd for text in before for _key, cmd in lifecycle_scripts(text)} if run else set()
        for cmd, sig, m in run:
            if cmd not in ran_before and not _written_by_a_parent(m.group(0), held_by_a_parent,
                                                                  _a_manifest, "package.json"):
                return sig
        return None

    return check


def _note_unchecked(target, sha: str, paths) -> None:
    """Say that files a merge brought in could not all be read for a known payload. Takes the
    target, the merge and the paths. The merge keeps the grade the rest of its evidence gives it."""
    notes = getattr(target, "coverage_notes", None)
    if notes is None:
        return
    shown = ", ".join(sorted(paths)[:3]) + (" …" if len(paths) > 3 else "")
    notes.append(f"Merge commit {sha[:10]} brought in {len(paths)} file(s) that could not be read in full, "
                 f"so it is not known to be clean: {shown}.")


def _written_by_a_parent(matched: str, held_by_a_parent, scope, key: str) -> bool:
    """Tell whether a parent wrote the text a signature matched, in a file of the kind the signature
    reads. Takes the matched text, the question to ask of the parents' files, the files to ask about
    (None for all) and a name for that choice. Returns the answer."""
    return bool(matched.strip()) and held_by_a_parent(matched, scope, key)


def _a_manifest(path: str) -> bool:
    """Tell whether a path is a package.json. Takes the path. Returns the answer."""
    return path.rsplit("/", 1)[-1] == "package.json"


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
        named = getattr(target, "merge_scope", None)
        if not by_conf or named == [] or (named is None and not gitutil.is_git_repo(target.repo_root)):
            return []
        loader_sig = next((s for s in by_conf.values() if s.get("confidence") != "heuristic"
                           and s.get("remediation") != REPORT_ONLY), None)
        heuristic_sig = next((s for s in by_conf.values() if s.get("confidence") == "heuristic"), None)
        payload_merge_sig = next((s for s in by_conf.values() if s.get("confidence") == CONFIRMED
                                  and s.get("remediation") == REPORT_ONLY), None)
        content_sig = build_confirmed_loader_check(all_signatures or signatures)
        left_out = frozenset(getattr(getattr(target, "opts", None), "exclude_dirs", ()) or ())
        payload_sig = (_merge_payload_check(all_signatures or signatures, left_out)
                       if payload_merge_sig is not None else None)
        findings: list[Finding] = []
        budget = ReadBudget()
        with gitutil.borrowed_or_none(target.repo_root) as borrowed:
            merges = gitutil.merge_commits(target.repo_root) if named is None else named
            if merges is None:
                target.read_errors.append("the merge commits could not be listed")
                return findings
            for sha in merges[:MOST_MERGES_CHECKED]:
                try:
                    read = gitutil.merge_evidence(target.repo_root, sha, content_sig,
                                                  _obfuscation_reason, payload_sig,
                                                  borrowed=borrowed, budget=budget)
                except gitutil.Unread as missed:
                    target.read_errors.append(f"merge {sha[:12]}: {missed.subject} could not be read")
                    continue
                if read.unread:
                    _note_unchecked(target, sha, read.unread)
                if read.flagged and any(r.startswith(_LOADER_REASON_PREFIX) for r in read.flagged.values()):
                    findings.append(self._finding(target, sha, read.flagged, loader_sig, heuristic_sig))
                elif read.payloads:
                    findings.append(self._payload_finding(target, sha, read, payload_merge_sig))
                elif read.flagged:
                    findings.append(self._finding(target, sha, read.flagged, loader_sig, heuristic_sig))
                elif read.unread and heuristic_sig is not None:
                    findings.append(self._unchecked_finding(target, sha, read.unread, heuristic_sig))
        return findings

    @staticmethod
    def _unchecked_finding(target, sha: str, paths, sig) -> Finding:
        """Build the finding for a merge whose only files beyond a clean merge could not be read in
        full. Takes the target, the merge, the paths and the signature. Returns the finding, to check
        by hand; it names no path for a removal to act on."""
        meta = gitutil.commit_meta(target.repo_root, sha)
        paths = sorted(paths)
        return Finding(
            signature_id=sig["id"], category=sig["category"],
            severity=Severity.parse(sig["severity"]), path=sha[:10],
            description=sig["description"], remediation=sig.get("remediation", "manual"),
            evidence=f"{len(paths)} file(s) this merge brought in could not be read in full, so it is "
                     f"not known to be clean; e.g. {paths[:3]}; by {meta.get('author_email','?')}",
            vector="evil-merge", commit_sha=sha, confidence=HEURISTIC, composed_evidence=True)

    @staticmethod
    def _payload_finding(target, sha: str, read, sig) -> Finding:
        """Build the finding for a merge that carries a known payload other than a loader. Takes the
        target, the merge, its `MergeEvidence` and the signature. Returns the finding; it names the
        paths the merge flagged as related and the paths that carry the payload as its payload."""
        meta = gitutil.commit_meta(target.repo_root, sha)
        paths = sorted(read.payloads)
        first = read.payloads[paths[0]]
        what = first.get("shown_as") or first.get("description", first["id"])
        return Finding(
            signature_id=sig["id"], category=sig["category"],
            severity=Severity.parse(sig["severity"]), path=sha[:10],
            description=sig["description"], remediation=sig.get("remediation", REPORT_ONLY),
            evidence=f"{len(paths)} file(s) where this merge holds a known payload that neither "
                     f"parent held; e.g. {paths[:3]} ({what}); "
                     f"{_liveness_note(target.repo_root, sha, paths)}; "
                     f"by {meta.get('author_email','?')}",
            vector="evil-merge", related_paths=tuple(sorted(read.flagged)),
            payload_paths=tuple(paths), commit_sha=sha, confidence=CONFIRMED,
            composed_evidence=True)

    @staticmethod
    def _finding(target, sha: str, evil: dict[str, str], loader_sig, heuristic_sig) -> Finding:
        meta = gitutil.commit_meta(target.repo_root, sha)
        paths = sorted(evil)
        loader_paths = [p for p in paths if evil[p].startswith(_LOADER_REASON_PREFIX)]
        sig = (loader_sig if loader_paths else heuristic_sig) or heuristic_sig or loader_sig
        why = evil[(loader_paths or paths)[0]]
        return Finding(
            signature_id=sig["id"], category=sig["category"],
            severity=Severity.parse(sig["severity"]), path=sha[:10],
            description=sig["description"], remediation=sig.get("remediation", "manual"),
            evidence=f"{len(evil)} file(s) this merge added that neither side had; "
                     f"e.g. {paths[:3]} ({why}); "
                     f"{_liveness_note(target.repo_root, sha, paths)}; "
                     f"by {meta.get('author_email','?')}",
            vector="evil-merge", related_paths=tuple(paths),
            payload_paths=tuple(loader_paths), commit_sha=sha,
            confidence=(HEURISTIC if sig.get("confidence") == "heuristic" else CONFIRMED),
            composed_evidence=True)

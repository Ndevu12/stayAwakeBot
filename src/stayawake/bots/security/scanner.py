#!/usr/bin/env python3
"""Scan engine: run every matcher over one target and collect findings.

Pure and side-effect-free (no network beyond a target's own clone, never
executes scanned code). One responsibility: target in → ScanResult out.
"""
from __future__ import annotations

import inspect
from pathlib import Path
from fnmatch import fnmatch
from typing import Any

from stayawake.bots.security.models import (CONFIRMED, HEURISTIC, RESIDUE, QUARANTINE_DIR,
                                            Finding, ScanResult, Severity)
from stayawake.bots.security.matchers import REGISTRY
from stayawake.lib import git as gitutil


def _accepts_all_signatures(matcher) -> bool:
    """True if a matcher's `scan` opts into the cross-signature view (an
    `all_signatures` keyword param). Keeps the call site backward-compatible with
    matchers that take only (target, signatures)."""
    try:
        return "all_signatures" in inspect.signature(matcher.scan).parameters
    except (ValueError, TypeError):
        return False


def _allowed(finding: Finding, allowlist: list[dict[str, Any]]) -> bool:
    """True if a finding is suppressed by the allowlist.

    A rule must name a `signature` to suppress. A bare `path_glob` (no signature)
    is intentionally NOT honored — it would blanket-suppress *every* signature on
    that path, so a fresh payload dropped under e.g. a test-fixtures glob would slip
    through silently. Fixture allowlisting therefore requires `signature` (+ optional
    `path_glob` to scope it)."""
    for rule in allowlist or []:
        if not isinstance(rule, dict):
            continue                       # defensive: skip a non-mapping rule (config is validated upstream)
        sig = rule.get("signature")
        glob = rule.get("path_glob")
        if not sig or sig != finding.signature_id:
            continue                       # path-only rules are too broad — ignored
        if glob and not fnmatch(finding.path, glob):
            continue
        return True
    return False


def run_matchers(target, matcher_names: list[str],
                 signatures_by_matcher: dict[str, list[dict[str, Any]]],
                 all_sigs: list[dict[str, Any]]) -> dict[str, list[Finding]]:
    """Run the named matchers over `target`, returning {matcher_name: [raw Finding, …]} in each
    matcher's own emission order. RAW: no allowlist/confidence/advisory decisions and no sort — those
    are `finalize`'s job, applied ONCE so the sequential and (merged) parallel paths are identical.
    Side effect: `target.read_errors` / `coverage_notes` accumulate as files are read."""
    out: dict[str, list[Finding]] = {}
    for name in matcher_names:
        matcher = REGISTRY.get(name)
        if not matcher:
            continue
        sigs = signatures_by_matcher.get(name, [])
        findings = (matcher.scan(target, sigs, all_signatures=all_sigs)
                    if _accepts_all_signatures(matcher) else matcher.scan(target, sigs))
        out[name] = list(findings)
    return out


def finalize(display: str, source: str, by_matcher: dict[str, list[Finding]],
             matcher_order: list[str], read_errors: list[str], coverage_notes: list[str],
             opts, root, allowlist: list[dict[str, Any]] | None,
             all_sigs: list[dict[str, Any]]) -> ScanResult:
    """Turn raw per-matcher findings into a finished ScanResult. This is the SINGLE post-processing
    path shared by a sequential scan and a merged parallel scan — so a `-j` run is byte-identical to
    `-j 1`. Findings are consumed in `matcher_order` (the signatures' matcher order), preserving the
    matcher-major insertion order that the final `(-severity, path)` stable sort relies on for ties."""
    result = ScanResult(target=display, source=source)
    confidence_of = {s["id"]: (s["confidence"] if s.get("confidence") in (HEURISTIC, RESIDUE)
                               else CONFIRMED)
                     for s in all_sigs}
    for name in matcher_order:
        for finding in by_matcher.get(name, []):
            if _allowed(finding, allowlist or []):
                continue
            if finding.advisory_only:
                # Advisory-tier (e.g. a dependency CVE): route OUT of `findings` so the verdict never
                # sees it — reported separately, never gates the scan.
                result.advisories.append(finding)
            else:
                finding.confidence = confidence_of.get(finding.signature_id, CONFIRMED)
                result.findings.append(finding)
    # Stable, useful ordering: severity desc, then path.
    result.findings.sort(key=lambda f: (-int(f.severity), f.path))
    result.advisories.sort(key=lambda f: (-int(f.severity), f.path))
    # A file that EXISTED but could not be read is a scan GAP, not a clean result — surface it so the
    # run fails CLOSED (service.scan turns any errored target into a non-zero exit). Findings from the
    # readable files are kept; the target is still marked errored.
    if read_errors and not result.error:
        unique = sorted(set(read_errors))
        shown = ", ".join(unique[:5]) + (" …" if len(unique) > 5 else "")
        result.error = f"{len(unique)} file(s) unreadable: {shown}"
    result.notes.extend(coverage_notes or [])
    # points — so a payload in a non-entry node_modules file reads clean. Say so, so `clean` isn't
    # silently hollow, and point at the opt-in that does look. Coverage note, never gating.
    if opts is not None and root is not None and not getattr(opts, "deep", False):
        try:
            nm = Path(root) / "node_modules"
            if nm.is_dir() and any(nm.iterdir()):        # present AND non-empty (nothing to note if bare)
                result.notes.append(
                    "node_modules was not content-scanned (only dependency entry points + identity). "
                    "Run `saw scan --deep` to scan vendored code for loader payloads.")
        except OSError:
            pass
    if root is not None:
        finding = _cleanup_residue(Path(root))
        if finding is not None:
            result.findings.append(finding)
        note = _history_scope_note(root)
        if note:
            result.notes.append(note)
    return result


def _cleanup_residue(root: Path) -> Finding | None:
    """Files a cleanup backed up and then did not change.

    The quarantine holds the original of every file a fix rewrote, so a quarantined copy that is
    byte-identical to the live file means the backup happened and the rewrite did not. Nothing new
    executes, and the tree is not what the project would carry — the state neither CLEAN nor
    INFECTED could express. Comparing bytes to bytes, so there is no shape to be wrong about."""
    quarantine = root / QUARANTINE_DIR
    unchanged: list[str] = []
    try:
        if not quarantine.is_dir():
            return None
        for original in sorted(quarantine.rglob("*")):
            if not original.is_file() or original.is_symlink():
                continue
            relative = original.relative_to(quarantine)
            live = root / relative
            try:
                if live.is_file() and live.read_bytes() == original.read_bytes():
                    unchanged.append(str(relative))
            except OSError:
                continue
    except OSError:
        return None
    if not unchanged:
        return None
    shown = ", ".join(unchanged[:5]) + (" …" if len(unchanged) > 5 else "")
    return Finding(
        signature_id="cleanup-residue",
        category="remediation-residue",
        severity=Severity.LOW,
        path=unchanged[0],
        description=f"A cleanup backed up {len(unchanged)} file(s) here and then left them "
                    f"unchanged: {shown}. Nothing new executes, and this is not what the project "
                    "would carry.",
        remediation="Re-run the cleanup, or restore these from the quarantined originals and "
                    "clean them by hand.",
        confidence=RESIDUE,
        composed_evidence=True,
    )


def _history_scope_note(root) -> str | None:
    """What a scan of the working tree did NOT look at.

    A removal-commit remediation leaves the payload reachable from an earlier commit, and one
    command puts it back on disk: `git checkout <rev>`, a bisect, or a clone of a tag that predates
    the fix. Stating the axis costs a commit count; scanning it is a separate job.
    """
    try:
        n = gitutil.commit_count(root)
        branches, tags = gitutil.ref_counts(root)
    except OSError:
        return None
    if n is None:
        return None
    earlier, others = n - 1, max(branches - 1, 0)
    parts = []
    if earlier:
        parts.append(f"{earlier} earlier {'commit' if earlier == 1 else 'commits'}")
    if others:
        parts.append(f"{others} other {'branch' if others == 1 else 'branches'}")
    if tags:
        parts.append(f"{tags} {'tag' if tags == 1 else 'tags'}")
    if not parts:
        return None
    return (f"Only the working tree was scanned; {', '.join(parts)} not examined. Any of them can "
            "be put on disk by one command (`git checkout <rev>`, `git clone --branch <tag>`), so a "
            "file cleaned here may still be served from there.")


def scan_target(target, signatures_by_matcher: dict[str, list[dict[str, Any]]],
                allowlist: list[dict[str, Any]] | None = None) -> ScanResult:
    """Scan ONE target with EVERY matcher, sequentially — the single-worker path and the reference
    for the parallel path, which splits the same matchers across file-chunks and merges into
    the same `finalize`."""
    all_sigs = [s for group in signatures_by_matcher.values() for s in group]
    order = list(signatures_by_matcher.keys())
    try:
        by_matcher = run_matchers(target, order, signatures_by_matcher, all_sigs)
        return finalize(target.display, target.source, by_matcher, order,
                        getattr(target, "read_errors", None) or [],
                        getattr(target, "coverage_notes", None) or [],
                        getattr(target, "opts", None), getattr(target, "root", None),
                        allowlist, all_sigs)
    except Exception as exc:  # never let one bad repo abort the whole sweep
        return ScanResult(target=target.display, source=target.source,
                          error=f"{type(exc).__name__}: {exc}")

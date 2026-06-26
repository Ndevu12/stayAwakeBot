#!/usr/bin/env python3
"""Scan engine: run every matcher over one target and collect findings.

Pure and side-effect-free (no network beyond a target's own clone, never
executes scanned code). One responsibility: target in → ScanResult out.
"""
from __future__ import annotations

import inspect
from fnmatch import fnmatch
from typing import Any

from stayawake.bots.security.models import CONFIRMED, HEURISTIC, Finding, ScanResult
from stayawake.bots.security.matchers import REGISTRY


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
        sig = rule.get("signature")
        glob = rule.get("path_glob")
        if not sig or sig != finding.signature_id:
            continue                       # path-only rules are too broad — ignored
        if glob and not fnmatch(finding.path, glob):
            continue
        return True
    return False


def scan_target(target, signatures_by_matcher: dict[str, list[dict[str, Any]]],
                allowlist: list[dict[str, Any]] | None = None) -> ScanResult:
    result = ScanResult(target=target.display, source=target.source)
    # Flat view of every signature, so a matcher that corroborates against OTHER
    # matchers' signatures (the evil-merge detector cross-checks the content-loader
    # fingerprints) can reach them without re-loading the DB.
    all_sigs = [s for group in signatures_by_matcher.values() for s in group]
    # Confidence is a property of the signature, not the matcher, so stamp it centrally
    # here (one source of truth) rather than threading it through every matcher. Anything
    # not explicitly marked `heuristic` is treated as `confirmed` — the conservative
    # default, so a new signature can never silently downgrade itself out of INFECTED.
    confidence_of = {s["id"]: (HEURISTIC if s.get("confidence") == HEURISTIC else CONFIRMED)
                     for s in all_sigs}
    try:
        for matcher_name, sigs in signatures_by_matcher.items():
            matcher = REGISTRY.get(matcher_name)
            if not matcher:
                continue
            findings = (matcher.scan(target, sigs, all_signatures=all_sigs)
                        if _accepts_all_signatures(matcher)
                        else matcher.scan(target, sigs))
            for finding in findings:
                if not _allowed(finding, allowlist or []):
                    finding.confidence = confidence_of.get(finding.signature_id, CONFIRMED)
                    result.findings.append(finding)
        # Stable, useful ordering: severity desc, then path.
        result.findings.sort(key=lambda f: (-int(f.severity), f.path))
    except Exception as exc:  # never let one bad repo abort the whole sweep
        result.error = f"{type(exc).__name__}: {exc}"
    return result

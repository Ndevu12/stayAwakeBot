#!/usr/bin/env python3
"""Scan engine: run every matcher over one target and collect findings.

Pure and side-effect-free (no network beyond a target's own clone, never
executes scanned code). One responsibility: target in → ScanResult out.
"""
from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from stayawakebot.security.models import Finding, ScanResult
from stayawakebot.security.matchers import REGISTRY


def _allowed(finding: Finding, allowlist: list[dict[str, Any]]) -> bool:
    """True if a finding is suppressed by the allowlist (id and/or path glob)."""
    for rule in allowlist or []:
        sig = rule.get("signature")
        glob = rule.get("path_glob")
        if sig and sig != finding.signature_id:
            continue
        if glob and not fnmatch(finding.path, glob):
            continue
        if sig or glob:
            return True
    return False


def scan_target(target, signatures_by_matcher: dict[str, list[dict[str, Any]]],
                allowlist: list[dict[str, Any]] | None = None) -> ScanResult:
    result = ScanResult(target=target.display, source=target.source)
    try:
        for matcher_name, sigs in signatures_by_matcher.items():
            matcher = REGISTRY.get(matcher_name)
            if not matcher:
                continue
            for finding in matcher.scan(target, sigs):
                if not _allowed(finding, allowlist or []):
                    result.findings.append(finding)
        # Stable, useful ordering: severity desc, then path.
        result.findings.sort(key=lambda f: (-int(f.severity), f.path))
    except Exception as exc:  # never let one bad repo abort the whole sweep
        result.error = f"{type(exc).__name__}: {exc}"
    return result

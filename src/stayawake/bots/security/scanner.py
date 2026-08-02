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
    # Confidence is a property of the signature, not the matcher, so stamp it centrally (one source of
    # truth). Anything not explicitly `heuristic` is treated as `confirmed` — the conservative default,
    # so a new signature can never silently downgrade itself out of INFECTED.
    confidence_of = {s["id"]: (HEURISTIC if s.get("confidence") == HEURISTIC else CONFIRMED)
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
        # Dedup + sort: a file is read-attempted by several matchers, so it appears multiple times;
        # count DISTINCT files, and make the sample order-independent of how the scan was partitioned
        # (parallel chunks accumulate errors file-major, sequential accumulates matcher-major) — so
        # the message is deterministic and reports files, not read-attempts.
        unique = sorted(set(read_errors))
        shown = ", ".join(unique[:5]) + (" …" if len(unique) > 5 else "")
        result.error = f"{len(unique)} file(s) unreadable: {shown}"
    # Coverage notes a matcher accumulated (e.g. a truncated --deep sweep, #1222) — non-gating.
    result.notes.extend(coverage_notes or [])
    # Honesty note (#1222): a normal scan does NOT content-scan vendored dependency CODE — only entry
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
    return result


def scan_target(target, signatures_by_matcher: dict[str, list[dict[str, Any]]],
                allowlist: list[dict[str, Any]] | None = None) -> ScanResult:
    """Scan ONE target with EVERY matcher, sequentially — the single-worker path and the reference
    for the parallel path (#1325), which splits the same matchers across file-chunks and merges into
    the same `finalize`."""
    # Flat view of every signature, so a matcher that corroborates against OTHER matchers' signatures
    # (the evil-merge detector cross-checks the content-loader fingerprints) can reach them.
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

#!/usr/bin/env python3
"""Malicious-upstream-dependency audit — the coordinator (#1101, T1195.001; #1119 refactor).

This matcher is now a thin orchestrator: it asks each ecosystem **resolver** for the packages
a repo declares/locks (as `Purl`s), asks the **advisory store** whether any is known-bad, and
emits a `Finding` anchored to the source file. All parsing lives in `dependencies/resolvers/`
and all "is this bad, and why" lives in `dependencies/store.py` — this file owns only the
workflow, so `handles = "dependency-audit"` keeps the scanner/REGISTRY/verdict/allowlist
contract unchanged.

Exactness is the point (preserved from the original): an exact-locked (or exact-pinned)
`name@version` match is decisive (`confirmed` → INFECTED). Offline, deterministic, cheap; the
behavioral engine stays the backbone. The store is injectable (`store_factory`) so tests can
supply an in-memory corpus; the default (`AdvisoryStore.default`) is the inline seed **plus** the
offline OSV corpus (#1120) when `saw db update` has populated a cache — absent a cache it is the
seed alone, so scans stay offline and zero-setup.
"""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.dependencies import RESOLVERS, Advisory, AdvisoryStore
from stayawake.bots.security.dependencies.purl import ResolvedDependency


class DependencyAuditMatcher(Matcher):
    handles = "dependency-audit"

    def __init__(self, resolvers=RESOLVERS, store_factory=AdvisoryStore.default):
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures):
        store = self._store_factory(signatures)
        if store.is_empty():
            return []
        # The vulnerability (CVE) tier is opt-in and never affects the verdict; the malware tier is
        # always on. `advisory_only` findings are routed out of the verdict by the scanner.
        advisories_on = bool(getattr(target.opts, "dependency_advisories", False))
        findings: list[Finding] = []
        seen_malware: set[tuple[str, str]] = set()          # (source_path, coordinate)
        seen_vuln: set[tuple[str, str, str]] = set()        # + advisory id
        for resolver in self._resolvers:
            for dep in resolver.resolve(target):
                advisory = store.advisory_for(dep.purl)
                if advisory is not None:
                    key = (dep.source_path, dep.purl.coordinate)
                    if key not in seen_malware:
                        seen_malware.add(key)
                        findings.append(_emit(advisory, dep))
                    continue          # a malware hit dominates — don't also list the package's CVEs
                if advisories_on:
                    for vuln in store.vulnerabilities_for(dep.purl):
                        vkey = (dep.source_path, dep.purl.coordinate, vuln.osv_id or "")
                        if vkey not in seen_vuln:
                            seen_vuln.add(vkey)
                            findings.append(_emit_advisory(vuln, dep))
        return findings


def _emit(advisory: Advisory, dep: ResolvedDependency) -> Finding:
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""      # corpus hits carry an OSV id
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=dep.source_path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{dep.purl.coordinate} — known-malicious upstream package{cite} ({dep.source_name})",
        vector=sig["category"])


def _emit_advisory(advisory: Advisory, dep: ResolvedDependency) -> Finding:
    """A CVE/GHSA advisory on a declared dependency — informational, routed OUT of the verdict."""
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=dep.source_path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{dep.purl.coordinate} — known security advisory{cite} ({dep.source_name})",
        vector=sig["category"], advisory_only=True)

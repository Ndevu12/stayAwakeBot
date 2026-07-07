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
supply an in-memory corpus and phase 1b (#1120) can swap the inline seed for the offline OSV
DB without touching this coordinator.
"""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.dependencies import RESOLVERS, AdvisoryStore
from stayawake.bots.security.dependencies.purl import ResolvedDependency


class DependencyAuditMatcher(Matcher):
    handles = "dependency-audit"

    def __init__(self, resolvers=RESOLVERS, store_factory=AdvisoryStore.from_signatures):
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures):
        store = self._store_factory(signatures)
        if store.is_empty():
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()          # (source_path, coordinate) — dedup within a file
        for resolver in self._resolvers:
            for dep in resolver.resolve(target):
                advisory = store.advisory_for(dep.purl)
                if advisory is None:
                    continue
                key = (dep.source_path, dep.purl.coordinate)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_emit(advisory.signature, dep))
        return findings


def _emit(sig: dict, dep: ResolvedDependency) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=dep.source_path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{dep.purl.coordinate} — known-malicious upstream package ({dep.source_name})",
        vector=sig["category"])

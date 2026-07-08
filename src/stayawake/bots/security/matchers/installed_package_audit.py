#!/usr/bin/env python3
"""Audit the INSTALLED dependency tree against the lockfile + corpus (#1144, epic #1141).

The lockfile dependency audit (dependency_audit.py) sees only what a repo DECLARES. This matcher reads
what's actually ON DISK (dependencies/installed.py) and reconciles it — closing the real gap that a
postinstall can drop a package into node_modules WITHOUT touching the lockfile, invisible to a lockfile-only
audit. Two checks, both cheap and offline:
  * IDENTITY-ON-DISK — an installed name@version is known-malicious (corpus) → `confirmed` (INFECTED),
    caught even though the lockfile was never edited.
  * GHOST — a package present on disk but absent from the lockfile → `heuristic` (SUSPICIOUS): npm writes
    every install into the lockfile, so an off-lockfile package is anomalous (benign cases — locally-linked
    packages — are symlinks, which the provider skips).

Thin orchestrator (SRP): the `InstalledTree` providers read disk, the `RESOLVERS` give the locked set, the
`AdvisoryStore` says "is it bad"; this file only reconciles + emits. Runs only when a project-local
installed tree exists (a remote clone with no install falls back to the lockfile audit). Reuses the same
memoized corpus as dependency_audit — no new parsing, no new deps.
"""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.dependencies import RESOLVERS, AdvisoryStore
from stayawake.bots.security.dependencies.installed import INSTALLED_TREES
from stayawake.bots.security.dependencies.purl import Purl


class InstalledPackageAuditMatcher(Matcher):
    handles = "installed-package-audit"

    def __init__(self, trees=INSTALLED_TREES, resolvers=RESOLVERS,
                 store_factory=AdvisoryStore.default):
        self._trees = trees
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures):
        by_id = {s["id"]: s for s in signatures}
        store = self._store_factory(signatures)
        findings: list[Finding] = []
        for tree in self._trees:
            installed = list(tree.read(target))
            if not installed:
                continue                              # no installed tree present → lockfile audit only
            locked = self._locked_names(tree.ecosystem, target)
            for pkg in installed:
                advisory = (store.advisory_for(Purl(tree.ecosystem, pkg.name, pkg.version))
                            if (pkg.version and not store.is_empty()) else None)
                if advisory is not None:
                    findings.append(_malicious(advisory, pkg))
                elif pkg.name not in locked:
                    findings.append(_ghost(by_id.get("ghost-package"), pkg))
        return [f for f in findings if f is not None]

    def _locked_names(self, ecosystem: str, target) -> set[str]:
        names: set[str] = set()
        for r in self._resolvers:
            if getattr(r, "ecosystem", None) == ecosystem:
                for dep in r.resolve(target):
                    names.add(dep.purl.name)
        return names


def _malicious(advisory, pkg) -> Finding:
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=pkg.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{pkg.name}@{pkg.version} INSTALLED on disk is known-malicious{cite} "
                 f"(caught even if the lockfile was not edited)",
        vector=sig["category"])


def _ghost(sig, pkg) -> Finding | None:
    if sig is None:
        return None
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=pkg.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{pkg.name}@{pkg.version or '?'} is installed but absent from the lockfile — "
                 f"a postinstall may have dropped it off-lockfile",
        vector=sig["category"])

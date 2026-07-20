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

import re

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_content_sig
from stayawake.bots.security.dependencies import RESOLVERS, AdvisoryStore
from stayawake.bots.security.dependencies.installed import INSTALLED_TREES
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.dependencies.remediation import advisory_reference, malware_fix


class InstalledPackageAuditMatcher(Matcher):
    handles = "installed-package-audit"

    def __init__(self, trees=INSTALLED_TREES, resolvers=RESOLVERS,
                 store_factory=AdvisoryStore.default):
        self._trees = trees
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures, all_signatures=None):
        by_id = {s["id"]: s for s in signatures}
        store = self._store_factory(signatures)
        tamper_sig = by_id.get("tampered-installed-package")
        hook_sig = by_id.get("installed-lifecycle-hook")
        entry_sig = by_id.get("installed-entry-loader")
        # Reuse the CONFIRMED npm-lifecycle patterns from the signature DB (setup_bun dropper,
        # curl|wget→interpreter) — one source, applied to INSTALLED package.json hooks that the
        # npm-manifest matcher can't reach (node_modules is pruned). The heuristic exec pattern is
        # excluded: it FPs on legit curl/bun/deno across hundreds of third-party packages.
        hook_patterns = _confirmed_lifecycle_patterns(all_signatures) if hook_sig is not None else []
        # The confirmed code-loader fingerprints (build_content_sig, one callable) run on each installed
        # package's ENTRY file(s) — the FP-safe tier, targeted to main/bin so it isn't the brute-force
        # node_modules scan PR3 rejected. A novel malicious package's runtime loader is otherwise pruned.
        entry_check = build_content_sig(all_signatures) if (entry_sig is not None and all_signatures) else None
        findings: list[Finding] = []
        for tree in self._trees:
            installed = list(tree.read(target))
            locked = (self._locked_names(tree.ecosystem, target)
                      if (installed and tree.ghost_reconcilable) else set())
            for pkg in installed:
                advisory = (store.advisory_for(Purl(tree.ecosystem, pkg.name, pkg.version))
                            if (pkg.version and not store.is_empty()) else None)
                if advisory is not None:
                    findings.append(_malicious(advisory, pkg))
                elif tree.ghost_reconcilable and pkg.name not in locked:
                    findings.append(_ghost(by_id.get("ghost-package"), pkg))
                if hook_patterns and pkg.hooks:
                    findings.append(_lifecycle_hook(hook_sig, hook_patterns, pkg))
                if entry_check is not None and pkg.entries:
                    findings.append(_entry_loader(entry_sig, entry_check, target, pkg))
            if tamper_sig is not None:                # RECORD sha256 integrity (Python provides it)
                for t in tree.tampered(target):
                    findings.append(_tampered(tamper_sig, t))
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
        vector=sig["category"],
        fix_advice=malware_fix(pkg.name),                         # remove from disk + lockfile, don't upgrade
        reference=advisory_reference(advisory.osv_id, advisory.aliases))


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


def _tampered(sig, t) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=t.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{t.package}: {t.detail} — installed file modified after install", vector=sig["category"])


def _confirmed_lifecycle_patterns(all_signatures):
    """Compiled patterns of the CONFIRMED npm-lifecycle signatures (matcher `npm-manifest`, not
    `heuristic`) — the FP-safe install-time IoCs, reused from the signature DB (one source, no copy)."""
    return [(s["id"], re.compile(s["pattern"], re.IGNORECASE))
            for s in (all_signatures or [])
            if s.get("matcher") == "npm-manifest" and s.get("confidence") != "heuristic"
            and s.get("pattern")]


def _entry_loader(sig, check, target, pkg) -> Finding | None:
    for rel in pkg.entries:
        text = target.read_text(rel)
        if text is None:
            continue
        hit = check(text)
        if hit:
            return Finding(
                signature_id=sig["id"], category=sig["category"],
                severity=Severity.parse(sig["severity"]), path=rel,
                description=sig["description"], remediation=sig.get("remediation", "manual"),
                evidence=f"{pkg.name}@{pkg.version or '?'} entry {rel} carries loader fingerprint {hit}",
                vector=sig["category"])
    return None


def _lifecycle_hook(sig, patterns, pkg) -> Finding | None:
    for key, cmd in (pkg.hooks or {}).items():
        for pid, rx in patterns:
            if rx.search(cmd):
                return Finding(
                    signature_id=sig["id"], category=sig["category"],
                    severity=Severity.parse(sig["severity"]), path=pkg.path,
                    description=sig["description"], remediation=sig.get("remediation", "manual"),
                    evidence=f"{pkg.name}@{pkg.version or '?'} {key}: {cmd[:80]} (matches {pid})",
                    vector=sig["category"])
    return None

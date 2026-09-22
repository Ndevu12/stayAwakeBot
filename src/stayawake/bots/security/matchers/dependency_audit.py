#!/usr/bin/env python3
"""Malicious-upstream-dependency audit — the coordinator."""
from __future__ import annotations

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher
from stayawake.bots.security.dependencies import RESOLVERS, Advisory, AdvisoryStore
from stayawake.bots.security.dependencies.purl import ResolvedDependency
from stayawake.bots.security.dependencies.remediation import (
    advisory_reference, external_advisory_fix, malware_fix, vulnerability_fix)


class DependencyAuditMatcher(Matcher):
    handles = "dependency-audit"

    def __init__(self, resolvers=RESOLVERS, store_factory=AdvisoryStore.default):
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures):
        external_on = bool(getattr(target.opts, "external_audit", False))
        store = self._store_factory(signatures)
        if store.is_empty() and not external_on:
            return []
        advisories_on = bool(getattr(target.opts, "dependency_advisories", False))
        findings: list[Finding] = []
        seen_malware: set[tuple[str, str]] = set()
        seen_vuln: set[tuple[str, str, str]] = set()
        emitted: set[tuple[str, str]] = set()
        if not store.is_empty():
            for resolver in self._resolvers:
                for dep in resolver.resolve(target):
                    advisory = store.advisory_for(dep.purl)
                    if advisory is not None:
                        key = (dep.source_path, dep.purl.coordinate)
                        if key not in seen_malware:
                            seen_malware.add(key)
                            findings.append(_emit(advisory, dep))
                        continue      # a malware hit dominates — don't also list the package's CVEs
                    if advisories_on:
                        for vuln in store.vulnerabilities_for(dep.purl):
                            vkey = (dep.source_path, dep.purl.coordinate, vuln.osv_id or "")
                            if vkey not in seen_vuln:
                                seen_vuln.add(vkey)
                                findings.append(_emit_advisory(vuln, dep))
                                emitted.add((vuln.osv_id or "", dep.purl.coordinate))
        if external_on and not getattr(target, "names_one_file", False):
            findings.extend(_external_findings(target, signatures, emitted))
        return findings


def _emit(advisory: Advisory, dep: ResolvedDependency) -> Finding:
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""
    fix = malware_fix(dep.purl.name, dep.purl.version, dep.purl.type)
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=dep.source_path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{dep.purl.coordinate} — known-malicious upstream package{cite} ({dep.source_name})",
        vector=sig["category"],
        fix_advice=fix.advice, dependency_state=fix.state, fix_command=fix.command,
        package=fix.package, package_name=fix.name,
        reference=advisory_reference(advisory.osv_id, advisory.aliases), composed_evidence=True)


def _emit_advisory(advisory: Advisory, dep: ResolvedDependency) -> Finding:
    """A CVE/GHSA advisory on a declared dependency — informational, routed OUT of the verdict."""
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""
    fix = vulnerability_fix(dep.purl.type, dep.purl.name, dep.purl.version,
                            advisory.fixed_version)
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=dep.source_path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{dep.purl.coordinate} — known security advisory{cite} ({dep.source_name})",
        vector=sig["category"], advisory_only=True,
        fix_advice=fix.advice, dependency_state=fix.state, fix_command=fix.command,
        package=fix.package, package_name=fix.name,
        fixed_version=advisory.fixed_version,
        reference=advisory_reference(advisory.osv_id, advisory.aliases), composed_evidence=True)


def _external_findings(target, signatures, seen: set[tuple[str, str]]) -> list[Finding]:
    """Run the opt-in external auditors over the target and normalize into advisory-tier findings,
    stamped with the `vulnerable-dependency` signature. Lazily imported so the subprocess machinery
    loads only when the user opted in."""
    vuln_sig = next((s for s in signatures if s.get("advisory_corpus")), None)
    if vuln_sig is None:
        return []
    from stayawake.bots.security.dependencies.external import run_external_audit
    return [_emit_external(vuln_sig, ef)
            for ef in run_external_audit(target.repo_root, seen=seen)]


def _emit_external(sig: dict, finding) -> Finding:
    """An external auditor's vulnerability → an advisory-tier finding, attributing the tool."""
    fix = external_advisory_fix(finding.package, finding.version, finding.advisory_id,
                                finding.source_tool)
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(finding.severity), path=finding.source_path or ".",
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=(f"{finding.package}@{finding.version} — {finding.advisory_id} "
                  f"(via {finding.source_tool})"),
        vector=sig["category"], advisory_only=True,
        fix_advice=fix.advice, dependency_state=fix.state, fix_command=fix.command,
        package=fix.package, package_name=fix.name,
        reference=advisory_reference(finding.advisory_id), composed_evidence=True)

#!/usr/bin/env python3
"""Opt-in external-auditor adapters (#1125): osv-scanner normalization, orchestrator dedup, the
off-by-default gate, and a REAL subprocess run via a fake `osv-scanner` on PATH."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from stayawake.bots.security.dependencies.external import run_external_audit
from stayawake.bots.security.dependencies.external.base import ExternalAuditor, ExternalFinding
from stayawake.bots.security.dependencies.external.osv_scanner import OsvScannerAdapter
from stayawake.bots.security.matchers.dependency_audit import DependencyAuditMatcher
from stayawake.bots.security.models import CLEAN
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIG_VULN = {"id": "vulnerable-dependency", "category": "supply-chain-vuln", "severity": "medium",
            "matcher": "dependency-audit", "description": "advisory", "remediation": "manual",
            "advisory_corpus": True}


def _osv_json(name="lodash", version="4.17.15", eco="npm", vid="GHSA-jf85-cpcp-j695", sev="high"):
    return json.dumps({"results": [{"source": {"path": f"/repo/package-lock.json"},
        "packages": [{"package": {"name": name, "version": version, "ecosystem": eco},
                      "vulnerabilities": [{"id": vid, "database_specific": {"severity": sev}}]}]}]})


@contextmanager
def fake_tool(name, stdout, exit_code=1):
    """Put an executable `name` on PATH that prints `stdout` (auditors exit non-zero when they find
    vulns, hence the default exit 1)."""
    d = Path(tempfile.mkdtemp())
    (d / name).write_text(f"#!/bin/sh\ncat <<'JSON_EOF'\n{stdout}\nJSON_EOF\nexit {exit_code}\n")
    (d / name).chmod(0o755)
    old = os.environ.get("PATH", "")
    os.environ["PATH"] = f"{d}{os.pathsep}{old}"
    try:
        yield
    finally:
        os.environ["PATH"] = old


class TestOsvScannerNormalization(unittest.TestCase):
    def _audit(self, output):
        return OsvScannerAdapter().audit("/repo", run=lambda argv, cwd, **k: output)

    def test_normalizes_to_findings(self):
        f = self._audit(_osv_json())[0]
        self.assertEqual((f.ecosystem, f.package, f.version, f.advisory_id, f.severity, f.source_tool),
                         ("npm", "lodash", "4.17.15", "GHSA-jf85-cpcp-j695", "high", "osv-scanner"))
        self.assertEqual(f.source_path, "package-lock.json")

    def test_ecosystem_canonicalized(self):
        f = self._audit(_osv_json(eco="crates.io"))[0]
        self.assertEqual(f.ecosystem, "cargo")            # OSV "crates.io" → PURL "cargo"

    def test_unknown_severity_defaults_medium(self):
        self.assertEqual(self._audit(_osv_json(sev="???"))[0].severity, "medium")

    def test_empty_and_malformed_output(self):
        self.assertEqual(self._audit(None), [])
        self.assertEqual(self._audit("{ not json"), [])
        self.assertEqual(self._audit(json.dumps({"results": []})), [])


class TestOrchestrator(unittest.TestCase):
    def test_absent_tool_is_skipped(self):
        # Real osv-scanner is not installed in CI → available() False → nothing runs, no error.
        self.assertEqual(run_external_audit("/repo"), [])

    def test_dedup_within_and_against_seen(self):
        class FakeAdapter(ExternalAuditor):
            name = "fake"
            def available(self):
                return True
            def audit(self, root, run=None):
                return [ExternalFinding("npm", "a", "1.0.0", "GHSA-1", "high", "fake"),
                        ExternalFinding("npm", "a", "1.0.0", "GHSA-1", "high", "fake"),  # dup
                        ExternalFinding("npm", "b", "2.0.0", "GHSA-2", "low", "fake")]
        out = run_external_audit("/repo", seen={("GHSA-2", "b@2.0.0")}, adapters=(FakeAdapter(),))
        # GHSA-1 deduped to one; GHSA-2 already in `seen` (corpus) → dropped
        self.assertEqual([f.advisory_id for f in out], ["GHSA-1"])


class TestRealSubprocess(unittest.TestCase):
    def test_real_osv_scanner_via_fake_on_path(self):
        # Exercises the REAL chain: shutil.which → subprocess.run → parse, without installing the tool.
        with fake_tool("osv-scanner", _osv_json(vid="GHSA-real-chain")):
            out = run_external_audit(tempfile.mkdtemp())
        self.assertEqual([f.advisory_id for f in out], ["GHSA-real-chain"])


class TestMatcherIntegration(unittest.TestCase):
    def _scan(self, external):
        d = Path(tempfile.mkdtemp())
        (d / "package-lock.json").write_text("{}")
        return scan_target(LocalRepoTarget(d, "t", ScanOptions(external_audit=external)),
                           {"dependency-audit": [SIG_VULN]}, [])

    def test_off_by_default(self):
        with fake_tool("osv-scanner", _osv_json()):
            r = self._scan(external=False)
        self.assertEqual(r.advisories, [])                # opt-in — nothing ran

    def test_external_findings_are_advisories_not_verdict(self):
        with fake_tool("osv-scanner", _osv_json(vid="GHSA-xyz")):
            r = self._scan(external=True)
        self.assertEqual(r.verdict, CLEAN)                # advisories never gate
        self.assertEqual(r.findings, [])
        self.assertEqual([a.signature_id for a in r.advisories], ["vulnerable-dependency"])
        self.assertTrue(r.advisories[0].advisory_only)
        self.assertIn("GHSA-xyz", r.advisories[0].evidence)
        self.assertIn("via osv-scanner", r.advisories[0].evidence)


if __name__ == "__main__":
    unittest.main()

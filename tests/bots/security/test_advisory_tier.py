#!/usr/bin/env python3
"""Two-tier verdict split (#1121): malware → INFECTED; ordinary CVEs → a separate, opt-in advisory
tier that never moves the verdict. Offline throughout (synthetic OSV zip; cache via env override)."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore, db
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.models import CLEAN, INFECTED, Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.sinks.render import render_markdown, render_terminal
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.core.timeutil import now_iso
from tests.bots.security._osv_fixtures import mal_record, osv_zip, vuln_record

MAL_SIG = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
           "matcher": "dependency-audit", "description": "malware", "remediation": "manual",
           "corpus": True}
VULN_SIG = {"id": "vulnerable-dependency", "category": "supply-chain-vuln", "severity": "medium",
            "matcher": "dependency-audit", "description": "advisory", "remediation": "manual",
            "advisory_corpus": True}
SIGS = [MAL_SIG, VULN_SIG]


def _lock(pkg, ver):
    d = Path(tempfile.mkdtemp())
    (d / "package-lock.json").write_text(json.dumps(
        {"packages": {f"node_modules/{pkg}": {"version": ver}}}), encoding="utf-8")
    return d


class TestAdvisoryTier(unittest.TestCase):
    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        self._old_env = os.environ.get("SAW_ADVISORY_CACHE_DIR")
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(self.cache)   # REGISTRY default matcher reads it
        z = osv_zip({"MAL.json": mal_record("evil", ["1.0.0"], rid="MAL-2024-1"),
                     "CVE.json": vuln_record("shaky", ["2.0.0"], rid="CVE-2024-9")})
        db.write_manifest(self.cache, [db.update_ecosystem("npm", self.cache, fetch=lambda b: z)])

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
        else:
            os.environ["SAW_ADVISORY_CACHE_DIR"] = self._old_env
        db._CORPUS_MEMO.clear()

    # ── store serves both tiers, from the right signatures ──
    def test_store_serves_two_tiers(self):
        s = AdvisoryStore.default(SIGS, cache_dir=self.cache)
        self.assertIsNotNone(s.advisory_for(Purl("npm", "evil", "1.0.0")))     # malware
        self.assertIsNone(s.advisory_for(Purl("npm", "shaky", "2.0.0")))       # CVE is not malware
        vulns = s.vulnerabilities_for(Purl("npm", "shaky", "2.0.0"))
        self.assertEqual([v.osv_id for v in vulns], ["CVE-2024-9"])
        self.assertEqual(vulns[0].signature["id"], "vulnerable-dependency")

    def _scan(self, pkg, ver, *, advisories):
        opts = ScanOptions(dependency_advisories=advisories)
        return scan_target(LocalRepoTarget(_lock(pkg, ver), "t", opts),
                           {"dependency-audit": SIGS}, [])

    # ── the crux: a CVE is reported but never gates ──
    def test_cve_is_advisory_only_and_verdict_stays_clean(self):
        r = self._scan("shaky", "2.0.0", advisories=True)
        self.assertEqual(r.verdict, CLEAN)                 # NOT infected/suspicious
        self.assertEqual(r.findings, [])                   # not in the verdict-bearing list
        self.assertEqual([a.signature_id for a in r.advisories], ["vulnerable-dependency"])
        self.assertTrue(r.advisories[0].advisory_only)
        self.assertIn("CVE-2024-9", r.advisories[0].evidence)

    def test_advisories_on_by_default(self):
        # ScanOptions() default → the offline CVE tier is part of a plain scan.
        r = scan_target(LocalRepoTarget(_lock("shaky", "2.0.0"), "t", ScanOptions()),
                        {"dependency-audit": SIGS}, [])
        self.assertEqual([a.signature_id for a in r.advisories], ["vulnerable-dependency"])

    def test_no_advisories_suppresses_the_section(self):
        r = self._scan("shaky", "2.0.0", advisories=False)     # ← --no-advisories path
        self.assertEqual(r.verdict, CLEAN)
        self.assertEqual(r.advisories, [])

    def test_malware_still_infects_regardless_of_flag(self):
        for advisories in (False, True):
            r = self._scan("evil", "1.0.0", advisories=advisories)
            self.assertEqual(r.verdict, INFECTED)
            self.assertEqual([f.signature_id for f in r.findings], ["malicious-dependency"])
            self.assertEqual(r.advisories, [])             # malware hit dominates; no CVE listing

    # ── model: advisories are excluded from the verdict by construction ──
    def test_scanresult_verdict_ignores_advisories(self):
        adv = Finding(signature_id="vulnerable-dependency", category="supply-chain-vuln",
                      severity=Severity.CRITICAL, path="package-lock.json", description="x",
                      advisory_only=True)
        r = ScanResult(target="t", source="local", advisories=[adv])
        self.assertEqual(r.verdict, CLEAN)                 # even a CRITICAL advisory doesn't gate
        self.assertEqual(r.to_dict()["advisories"][0]["signature_id"], "vulnerable-dependency")

    # ── rendering: a separate, clearly non-gating section ──
    def test_render_shows_advisories_section_without_changing_status(self):
        adv = Finding(signature_id="vulnerable-dependency", category="supply-chain-vuln",
                      severity=Severity.MEDIUM, path="package-lock.json",
                      description="known advisory", evidence="shaky@2.0.0 — known security advisory "
                      "[CVE-2024-9] (package-lock.json)", advisory_only=True)
        payload = ScanReport(now_iso(), [ScanResult("t", "local", advisories=[adv])]).to_payload()
        term = render_terminal(payload, detail=True)
        self.assertIn("Dependency advisories", term)
        self.assertIn("do not affect the verdict", term)
        self.assertNotIn("INFECTED", term)
        self.assertIn("Dependency advisories", render_markdown(payload))


class TestAdvisoryWiring(unittest.TestCase):
    def test_advisories_default_on_and_opt_out(self):
        from stayawake.bots.security import service
        self.assertTrue(service._options({}).dependency_advisories)                         # default ON
        self.assertFalse(service._options({}, no_advisories=True).dependency_advisories)    # --no-advisories
        self.assertFalse(service._options({"dependency_advisories": False}).dependency_advisories)  # config off
        self.assertFalse(service._options({}).external_audit)                               # external opt-in

    def test_scan_cli_flags(self):
        from stayawake.cli.dispatch import build_parser
        p = build_parser()
        self.assertFalse(p.parse_args(["scan"]).no_advisories)                 # advisories on by default
        self.assertTrue(p.parse_args(["scan", "--no-advisories"]).no_advisories)
        self.assertTrue(p.parse_args(["scan", "-x"]).external_audit)
        self.assertTrue(p.parse_args(["scan", "--external"]).external_audit)

    def test_config_string_cannot_flip_the_sandbox(self):
        # A quoted YAML string must NOT be truthy — a config typo can't silently leave the offline
        # sandbox (`bool("false")` is True; the strict coercion prevents that).
        from stayawake.bots.security import service
        for falsy in ("false", "no", "off", "0", ""):
            self.assertFalse(service._options({"external_audit": falsy}).external_audit, falsy)
        self.assertFalse(service._options({"dependency_advisories": "false"}).dependency_advisories)
        self.assertTrue(service._options({"external_audit": True}).external_audit)      # real bool works
        self.assertTrue(service._options({"external_audit": "yes"}).external_audit)     # explicit truthy


if __name__ == "__main__":
    unittest.main()

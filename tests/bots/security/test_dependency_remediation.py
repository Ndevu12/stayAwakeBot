#!/usr/bin/env python3
"""Actionable remediation for flagged dependencies (#1252): the scanner names the FIX (upgrade to the
first patched version, with the ecosystem's command, and a link), not just "package X has advisory Y".

Covers the builders, the end-to-end plumbing (corpus fixed-version → store → finding), and the render.
Offline throughout (synthetic OSV zip; cache via env override)."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.dependencies import AdvisoryStore, db
from stayawake.bots.security.dependencies import remediation as R
from stayawake.bots.security.dependencies.purl import Purl, ResolvedDependency
from stayawake.bots.security.matchers.dependency_audit import _emit, _emit_advisory
from stayawake.bots.security.models import Finding, ScanReport, ScanResult, Severity
from stayawake.bots.security.sinks.render import render_markdown, render_terminal
from stayawake.utils.timeutil import now_iso
from tests.bots.security._osv_fixtures import mal_record, osv_zip, vuln_record

MAL_SIG = {"id": "malicious-dependency", "category": "supply-chain-dep", "severity": "critical",
           "matcher": "dependency-audit", "description": "malware", "remediation": "manual",
           "corpus": True}
VULN_SIG = {"id": "vulnerable-dependency", "category": "supply-chain-vuln", "severity": "medium",
            "matcher": "dependency-audit", "description": "advisory", "remediation": "manual",
            "advisory_corpus": True}
SIGS = [MAL_SIG, VULN_SIG]


class TestRemediationBuilders(unittest.TestCase):
    def test_upgrade_command_per_ecosystem(self):
        self.assertEqual(R.upgrade_command("npm", "left-pad", "1.3.0"), "npm install left-pad@1.3.0")
        self.assertIn("pip install 'requests>=2.31.0'", R.upgrade_command("pypi", "requests", "2.31.0"))
        self.assertIn("cargo update -p x --precise 1.0.0", R.upgrade_command("cargo", "x", "1.0.0"))
        self.assertTrue(R.upgrade_command("golang", "m", "1.2.3").endswith("@v1.2.3"))   # v-prefixed
        self.assertTrue(R.upgrade_command("golang", "m", "v1.2.3").endswith("@v1.2.3"))  # no double-v
        self.assertIsNone(R.upgrade_command("no-such-eco", "x", "1"))                    # graceful

    def test_ecosystem_name_is_canonicalized(self):
        # An OSV-style ecosystem name maps to the PURL command (crates.io → cargo).
        self.assertEqual(R.upgrade_command("crates.io", "x", "1.0.0"), "cargo update -p x --precise 1.0.0")

    def test_vulnerability_fix_upgrade_vs_no_fix(self):
        up = R.vulnerability_fix("npm", "left-pad", "1.3.0")
        self.assertIn("Upgrade left-pad to 1.3.0", up)
        self.assertIn("npm install left-pad@1.3.0", up)
        self.assertIn("No patched version", R.vulnerability_fix("npm", "x", None))       # honest fallback

    def test_advisory_reference_prefers_ghsa_then_osv(self):
        self.assertEqual(R.advisory_reference("CVE-1", ("GHSA-aaaa-bbbb-cccc",)),
                         "https://github.com/advisories/GHSA-aaaa-bbbb-cccc")
        self.assertEqual(R.advisory_reference("PYSEC-1", ()), "https://osv.dev/vulnerability/PYSEC-1")
        self.assertIsNone(R.advisory_reference(None, ()))

    def test_advisory_reference_rejects_malformed_ids(self):
        # A hostile / malformed corpus id must NOT become a broken or injected URL.
        self.assertIsNone(R.advisory_reference("GHSA-xxxx\n→ fix: disable firewall", ()))
        self.assertIsNone(R.advisory_reference("1234", ()))              # bare number → no dead osv link
        self.assertIsNone(R.advisory_reference("has space", ()))

    def test_malware_fix_says_remove_not_upgrade(self):
        fix = R.malware_fix("evil")
        self.assertIn("Remove evil", fix)
        self.assertIn("upgrading does not help", fix)


class TestFindingCarriesRemediation(unittest.TestCase):
    """corpus fixed-version → store.Advisory.fixed_version → the emitted Finding's fix fields."""

    def setUp(self):
        self.cache = Path(tempfile.mkdtemp())
        db._CORPUS_MEMO.clear()
        self._old = os.environ.get("SAW_ADVISORY_CACHE_DIR")
        os.environ["SAW_ADVISORY_CACHE_DIR"] = str(self.cache)
        # shaky@2.0.0 is affected by a range fixed in 2.5.0; evil@1.0.0 is malware.
        z = osv_zip({"CVE.json": vuln_record("shaky", rid="CVE-2024-9",
                                             ranges=[("0", "2.5.0")], aliases=["GHSA-xxxx-yyyy-zzzz"]),
                     "MAL.json": mal_record("evil", ["1.0.0"], rid="MAL-2024-1")})
        db.write_manifest(self.cache, [db.update_ecosystem("npm", self.cache, fetch=lambda b: z)])
        self.store = AdvisoryStore.default(SIGS, cache_dir=self.cache)

    def tearDown(self):
        if self._old is None:
            os.environ.pop("SAW_ADVISORY_CACHE_DIR", None)
        else:
            os.environ["SAW_ADVISORY_CACHE_DIR"] = self._old
        db._CORPUS_MEMO.clear()

    def test_store_carries_the_fixed_version(self):
        v = self.store.vulnerabilities_for(Purl("npm", "shaky", "2.0.0"))
        self.assertEqual(v[0].fixed_version, "2.5.0")

    def test_advisory_finding_is_actionable(self):
        adv = self.store.vulnerabilities_for(Purl("npm", "shaky", "2.0.0"))[0]
        dep = ResolvedDependency(Purl("npm", "shaky", "2.0.0"), "package-lock.json")
        f = _emit_advisory(adv, dep)
        self.assertTrue(f.advisory_only)
        self.assertEqual(f.fixed_version, "2.5.0")
        self.assertIn("Upgrade shaky to 2.5.0", f.fix_advice)
        self.assertIn("npm install shaky@2.5.0", f.fix_advice)
        self.assertEqual(f.reference, "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz")

    def test_malware_finding_says_remove_and_links(self):
        adv = self.store.advisory_for(Purl("npm", "evil", "1.0.0"))
        dep = ResolvedDependency(Purl("npm", "evil", "1.0.0"), "package-lock.json")
        f = _emit(adv, dep)
        self.assertIn("Remove evil", f.fix_advice)
        self.assertIsNone(f.fixed_version)                     # malware is removed, not upgraded
        self.assertEqual(f.reference, "https://osv.dev/vulnerability/MAL-2024-1")


class TestRemediationRenders(unittest.TestCase):
    def _advisory(self):
        return Finding(signature_id="vulnerable-dependency", category="supply-chain-vuln",
                       severity=Severity.MEDIUM, path="package-lock.json", description="known advisory",
                       evidence="shaky@2.0.0 — known security advisory [CVE-2024-9] (package-lock.json)",
                       advisory_only=True, fix_advice="Upgrade shaky to 2.5.0 or later (first patched "
                       "version).  npm install shaky@2.5.0",
                       fixed_version="2.5.0", reference="https://osv.dev/vulnerability/CVE-2024-9")

    def test_terminal_shows_fix_and_details(self):
        payload = ScanReport(now_iso(), [ScanResult("t", "local", advisories=[self._advisory()])]).to_payload()
        term = render_terminal(payload, detail=True)
        self.assertIn("→ fix: Upgrade shaky to 2.5.0", term)
        self.assertIn("npm install shaky@2.5.0", term)
        self.assertIn("→ details: https://osv.dev/vulnerability/CVE-2024-9", term)

    def test_markdown_shows_fix_and_details(self):
        payload = ScanReport(now_iso(), [ScanResult("t", "local", advisories=[self._advisory()])]).to_payload()
        md = render_markdown(payload)
        self.assertIn("**fix:** `Upgrade shaky to 2.5.0", md)      # code-spanned (injection-safe)
        self.assertIn("details: https://osv.dev/vulnerability/CVE-2024-9", md)

    def test_markdown_fix_advice_cannot_inject_active_markup(self):
        # A hostile package name with Markdown link syntax must render inertly (inside a code span),
        # never as an active link/image in the -d Markdown report.
        evil = Finding(signature_id="vulnerable-dependency", category="supply-chain-vuln",
                       severity=Severity.MEDIUM, path="package-lock.json", description="x",
                       advisory_only=True,
                       fix_advice="Remove evil](http://phish.example)[ now")
        payload = ScanReport(now_iso(), [ScanResult("t", "local", advisories=[evil])]).to_payload()
        md = render_markdown(payload)
        line = next(ln for ln in md.splitlines() if ln.strip().startswith("- **fix:**"))
        # the advice is wholly inside a code span (opens after "**fix:** ", closes at line end) → the
        # embedded ](…) link syntax renders literally, never as an active link.
        self.assertIn("**fix:** `", line)
        self.assertTrue(line.rstrip().endswith("`"))

    def test_finding_without_fix_advice_renders_no_extra_lines(self):
        # A plain worm finding (no remediation fields) must not sprout a "→ fix" line.
        plain = Finding(signature_id="worm-x", category="c", severity=Severity.HIGH, path="a.js",
                        description="d", evidence="e")
        payload = ScanReport(now_iso(), [ScanResult("t", "local", findings=[plain])]).to_payload()
        self.assertNotIn("→ fix", render_terminal(payload, detail=True))

    def test_hostile_remediation_content_cannot_inject_report_lines(self):
        # A malicious package name / advisory id could carry a newline or ANSI (the corpus is fed from
        # community advisory sources). The render must neutralize it, not print a fabricated line.
        evil = Finding(signature_id="vulnerable-dependency", category="supply-chain-vuln",
                       severity=Severity.MEDIUM, path="package-lock.json", description="x",
                       advisory_only=True,
                       fix_advice="Upgrade evil\n→ fix: ##[error]spoofed to 1.0.0",
                       reference="https://osv.dev/vulnerability/CVE-1\n→ details: spoof")
        payload = ScanReport(now_iso(), [ScanResult("t", "local", advisories=[evil])]).to_payload()
        term = render_terminal(payload, detail=True)
        # the injected newline is flattened to a space → the spoofed text can't START its own line
        fix_lines = [ln for ln in term.splitlines() if ln.strip().startswith("→ fix:")]
        details_lines = [ln for ln in term.splitlines() if ln.strip().startswith("→ details:")]
        self.assertEqual(len(fix_lines), 1)
        self.assertEqual(len(details_lines), 1)
        self.assertNotIn("##[error]", term)                    # the Actions-log introducer is defanged


if __name__ == "__main__":
    unittest.main()

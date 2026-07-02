#!/usr/bin/env python3
"""Confidence-graded verdict: INFECTED only for a `confirmed` finding; heuristic-only
matches surface as SUSPICIOUS (informed, never asserted as malware). This is what keeps
the scanner from labelling a base64 asset / crypto test vector "infected"."""
from __future__ import annotations

import random
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import (
    Finding, ScanResult, Severity, CONFIRMED, HEURISTIC, CLEAN, SUSPICIOUS, INFECTED,
)
from stayawake.bots.security import remediation
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _finding(sig_id, sev=Severity.MEDIUM, confidence=CONFIRMED, remediation="manual"):
    return Finding(signature_id=sig_id, category="code-loader", severity=sev,
                   path="x.ts", description="d", remediation=remediation, confidence=confidence)


def _scan(files):
    d = Path(tempfile.mkdtemp())
    for rel, c in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(c, encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, [])


class TestVerdict(unittest.TestCase):
    # ── The core rule: only confirmed → infected ────────────────────────────────
    def test_no_findings_is_clean(self):
        r = ScanResult(target="t", source="local")
        self.assertEqual(r.verdict, CLEAN)
        self.assertFalse(r.infected)
        self.assertFalse(r.suspicious)

    def test_heuristic_only_is_suspicious_not_infected(self):
        r = ScanResult(target="t", source="local",
                       findings=[_finding("obfuscated-source-file", confidence=HEURISTIC)])
        self.assertEqual(r.verdict, SUSPICIOUS)
        self.assertFalse(r.infected)
        self.assertTrue(r.suspicious)

    def test_any_confirmed_is_infected(self):
        r = ScanResult(target="t", source="local",
                       findings=[_finding("loader-seed-var", Severity.CRITICAL, CONFIRMED)])
        self.assertEqual(r.verdict, INFECTED)
        self.assertTrue(r.infected)

    def test_confidence_is_independent_of_severity(self):
        # A CONFIRMED *medium* IOC (the worm's exact tooling markers) is INFECTED, while a
        # HEURISTIC *high* finding (evil-merge) is only SUSPICIOUS. Severity != confidence.
        ioc = ScanResult(target="t", source="local",
                         findings=[_finding("gitignore-autopush-markers", Severity.MEDIUM, CONFIRMED)])
        heur_high = ScanResult(target="t", source="local",
                               findings=[_finding("evil-merge", Severity.HIGH, HEURISTIC)])
        self.assertEqual(ioc.verdict, INFECTED)
        self.assertEqual(heur_high.verdict, SUSPICIOUS)

    def test_mixed_confirmed_and_heuristic_is_infected(self):
        r = ScanResult(target="t", source="local", findings=[
            _finding("obfuscated-source-file", confidence=HEURISTIC),
            _finding("loader-global-bang", Severity.HIGH, CONFIRMED),
        ])
        self.assertEqual(r.verdict, INFECTED)

    def test_many_heuristics_never_escalate_to_infected(self):
        # No count-based escalation: three independent heuristic hits stay SUSPICIOUS.
        r = ScanResult(target="t", source="local",
                       findings=[_finding("obfuscated-source-file", confidence=HEURISTIC) for _ in range(3)])
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_to_dict_exposes_verdict(self):
        r = ScanResult(target="t", source="local",
                       findings=[_finding("obfuscated-source-file", confidence=HEURISTIC)])
        d = r.to_dict()
        self.assertEqual(d["verdict"], SUSPICIOUS)
        self.assertFalse(d["infected"])
        self.assertTrue(d["suspicious"])
        self.assertEqual(d["findings"][0]["confidence"], HEURISTIC)

    # ── End-to-end through the scanner (confidence stamped from the signature) ──
    def test_scanner_stamps_confidence_and_grades_assets_suspicious(self):
        # A base64 asset embedded in source trips only the heuristic obfuscated-source-file.
        random.seed(2)
        al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(al) for _ in range(400))
        r = _scan({"avatar.ts": f'export const A = "{blob}";\n'})
        self.assertEqual(r.verdict, SUSPICIOUS)
        obf = [f for f in r.findings if f.signature_id == "obfuscated-source-file"]
        self.assertTrue(obf and all(f.confidence == HEURISTIC for f in obf))

    def test_scanner_grades_real_loader_infected(self):
        r = _scan({"x.mjs": "var _$_1e42 = sfL(0); String.fromCharCode(127);\n"})
        self.assertEqual(r.verdict, INFECTED)
        self.assertTrue(any(f.confidence == CONFIRMED for f in r.findings))

    def test_exfil_branding_and_runner_are_infected_token_is_suspicious(self):
        # #1089: the worm's exact vanity labels are CONFIRMED (INFECTED); a bare mention is
        # HEURISTIC (SUSPICIOUS), so a security write-up isn't falsely labelled malware.
        self.assertEqual(_scan({"r.md": "A Mini Shai-Hulud has Appeared\n"}).verdict, INFECTED)
        self.assertEqual(
            _scan({"gh-token-monitor.service": "--name SHA1HULUD\n"}).verdict, INFECTED)
        self.assertEqual(_scan({"w.md": "about the Shai-Hulud worm\n"}).verdict, SUSPICIOUS)

    # ── Remediation safety: heuristic findings never auto-strip ─────────────────
    def test_codeloader_is_never_plan_auto_fixed(self):
        # Code-loader findings are NEVER surgically edited via plan/apply (that corrupted
        # valid files) — they route to git recovery instead. So at EITHER confidence they
        # are not "auto-fixable" and produce no plan() change.
        for conf in (HEURISTIC, CONFIRMED):
            f = _finding("obfuscated-source-file", remediation="recover", confidence=conf)
            self.assertFalse(remediation.is_auto_fixable(f), conf)
            self.assertEqual(remediation.plan([f]), [], conf)


class TestConfidenceSignatureValidation(unittest.TestCase):
    def test_invalid_confidence_value_fails_loudly(self):
        bad = ("version: 1\nsignatures:\n"
               "  - id: x\n    category: code-loader\n    severity: medium\n"
               "    matcher: content\n    pattern: 'x'\n    description: d\n"
               "    confidence: definitely-malware\n")
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(bad)
            path = fh.name
        with self.assertRaises(ValueError):
            load_signatures(path)


if __name__ == "__main__":
    unittest.main()

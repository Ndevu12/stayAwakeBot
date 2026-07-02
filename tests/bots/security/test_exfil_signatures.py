#!/usr/bin/env python3
"""Shai-Hulud exfiltration / persistence-branding signatures (#1089).

Detection + confidence + file_globs scoping + allowlist suppression for the worm's own
vanity labels: attacker-repo/commit branding, and the self-hosted runner name SHA1HULUD.
All inputs are inert vanity strings — no payload.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, SUSPICIOUS
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _scan(files, allow=None):
    d = Path(tempfile.mkdtemp())
    for rel, c in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(c, encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


class TestExfilBranding(unittest.TestCase):
    def test_branding_phrases_are_confirmed_infected(self):
        for phrase in ("Sha1-Hulud: The Second Coming", "A Mini Shai-Hulud has Appeared"):
            r = _scan({"README.md": f"secrets exfiltrated by {phrase}\n"})
            self.assertIn("exfil-shai-hulud-branding",
                          {f.signature_id for f in r.findings}, phrase)
            self.assertEqual(r.verdict, INFECTED, phrase)


class TestExfilRunner(unittest.TestCase):
    def test_runner_name_in_service_file_is_confirmed_infected(self):
        r = _scan({"gh-token-monitor.service":
                   "ExecStart=/opt/actions-runner/run.sh --name SHA1HULUD --labels self-hosted\n"})
        self.assertIn("exfil-sha1hulud-runner", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_runner_name_in_dotfile_config_is_detected(self):
        r = _scan({".runner": '{"agentName": "SHA1HULUD"}\n'})
        self.assertIn("exfil-sha1hulud-runner", {f.signature_id for f in r.findings})

    def test_runner_name_in_prose_is_NOT_flagged(self):
        # A plain mention outside runner/workflow/service files (e.g. this repo's own docs and
        # hygiene runbook) is out of the signature's file_globs scope — no false runner finding.
        r = _scan({"notes.py": "# incident response: watch for a runner named SHA1HULUD\n"})
        self.assertNotIn("exfil-sha1hulud-runner", {f.signature_id for f in r.findings})


class TestExfilToken(unittest.TestCase):
    def test_bare_token_is_heuristic_suspicious_not_infected(self):
        r = _scan({"writeup.md": "This dependency looks like the Shai-Hulud worm.\n"})
        self.assertIn("exfil-shai-hulud-token", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)  # heuristic only → not asserted as malware

    def test_token_matches_both_spellings(self):
        for spelling in ("Shai-Hulud", "Sha1-Hulud"):
            r = _scan({"note.md": f"mentions {spelling} here\n"})
            self.assertIn("exfil-shai-hulud-token", {f.signature_id for f in r.findings}, spelling)

    def test_token_suppressed_by_signature_scoped_allowlist(self):
        # Mirrors this repo's own suppression: a legitimate mention under an allowlisted path
        # (e.g. src/ — obfuscation.py names "the canonical Shai-Hulud string shuffler") is not reported.
        allow = [{"signature": "exfil-shai-hulud-token", "path_glob": "src/**"}]
        r = _scan({"src/x.py": "# canonical Shai-Hulud string shuffler\n"}, allow=allow)
        self.assertNotIn("exfil-shai-hulud-token", {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

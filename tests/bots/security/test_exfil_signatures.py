#!/usr/bin/env python3
"""A known worm's exfiltration / persistence-branding signatures (#1089).

Detection + confidence + file_globs scoping + allowlist suppression for the worm's own
vanity labels: attacker-repo/commit branding, and the name it gives its self-hosted runner.
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
from tests.support import samples

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
        for phrase in (samples.joined(samples.WORM_NAME_WITH_DIGIT, ': The Second Coming'), samples.joined('A Mini ', samples.WORM_NAME, ' has Appeared')):
            r = _scan({"README.md": f"secrets exfiltrated by {phrase}\n"})
            self.assertIn("known-worm-branding",
                          {f.signature_id for f in r.findings}, phrase)
            self.assertEqual(r.verdict, INFECTED, phrase)


class TestExfilRunner(unittest.TestCase):
    def test_runner_name_in_service_file_is_confirmed_infected(self):
        r = _scan({"gh-token-monitor.service":
                   samples.joined('ExecStart=/opt/actions-runner/run.sh --name ', samples.RUNNER_NAME, ' --labels self-hosted\n')})
        self.assertIn("known-worm-runner", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_runner_name_in_dotfile_config_is_detected(self):
        r = _scan({".runner": samples.joined('{"agentName": "', samples.RUNNER_NAME, '"}\n')})
        self.assertIn("known-worm-runner", {f.signature_id for f in r.findings})

    def test_runner_name_in_prose_is_NOT_flagged(self):
        # A plain mention outside runner/workflow/service files (e.g. this repo's own docs and
        # hygiene runbook) is out of the signature's file_globs scope — no false runner finding.
        r = _scan({"notes.py": samples.joined('# incident response: watch for a runner named ', samples.RUNNER_NAME, '\n')})
        self.assertNotIn("known-worm-runner", {f.signature_id for f in r.findings})


class TestExfilToken(unittest.TestCase):
    def test_bare_token_is_heuristic_suspicious_not_infected(self):
        r = _scan({"writeup.md": samples.joined('This dependency looks like the ', samples.WORM_NAME, ' worm.\n')})
        self.assertIn("known-worm-name", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)  # heuristic only → not asserted as malware

    def test_token_matches_both_spellings(self):
        for spelling in (samples.WORM_NAME, samples.WORM_NAME_WITH_DIGIT):
            r = _scan({"note.md": f"mentions {spelling} here\n"})
            self.assertIn("known-worm-name", {f.signature_id for f in r.findings}, spelling)

    def test_token_suppressed_by_signature_scoped_allowlist(self):
        # Mirrors this repo's own suppression: a legitimate mention under an allowlisted path
        # (e.g. a mention of the worm's string shuffler in src/) is not reported.
        allow = [{"signature": "known-worm-name", "path_glob": "src/**"}]
        r = _scan({"src/x.py": samples.joined('# canonical ', samples.WORM_NAME, ' string shuffler\n')}, allow=allow)
        self.assertNotIn("known-worm-name", {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

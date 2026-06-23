#!/usr/bin/env python3
"""Remediation engine: planning + applying makes an infected tree clean, idempotently."""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from security.signatures import load_signatures      # noqa: E402
from security.scanner import scan_target             # noqa: E402
from security.targets import LocalRepoTarget, ScanOptions  # noqa: E402
from security import remediation                     # noqa: E402

FIX = ROOT / "tests" / "security" / "fixtures" / "infected"
SIGS = load_signatures(ROOT / "config" / "security_signatures.yml")


class TestRemediation(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp()) / "repo"
        shutil.copytree(FIX, self.repo)
        self.q = self.repo / ".malware-quarantine"

    def _findings(self):
        return scan_target(LocalRepoTarget(self.repo, "t", ScanOptions()), SIGS, []).findings

    def test_apply_makes_tree_clean(self):
        before = self._findings()
        self.assertTrue(before, "fixture should start infected")
        applied = remediation.apply(self.repo, remediation.plan(before), self.q)
        self.assertTrue(applied, "should apply changes")
        remaining = {f.signature_id for f in self._findings()}
        self.assertEqual(remaining, set(), f"still infected after remediation: {remaining}")
        # originals preserved in quarantine
        self.assertTrue(self.q.exists())

    def test_idempotent(self):
        remediation.apply(self.repo, remediation.plan(self._findings()), self.q)
        self.assertEqual(remediation.plan(self._findings()), [], "second pass should be a no-op")

    def test_strip_payload_keeps_legit_config(self):
        text = 'const config = { plugins: [] };\nexport default config;PAYLOAD_JUNK_HERE\n'
        out = remediation.strip_payload_text(text)
        self.assertIn("export default config;", out)
        self.assertNotIn("PAYLOAD_JUNK_HERE", out)


if __name__ == "__main__":
    unittest.main()

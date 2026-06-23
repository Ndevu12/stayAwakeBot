#!/usr/bin/env python3
"""Evil-merge detector test: a merge commit that introduces a file present in
neither parent must be flagged."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


from stayawake.bots.security.matchers.git_history import GitHistoryMatcher          # noqa: E402
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions  # noqa: E402

EVIL_SIG = [{
    "id": "evil-merge", "category": "evil-merge", "severity": "high",
    "matcher": "git-history", "kind": "evil-merge",
    "description": "evil merge", "remediation": "manual",
}]


def _git(d, *args):
    subprocess.run(["git", "-C", str(d), *args], check=True,
                   capture_output=True, text=True)


class TestEvilMerge(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="evilmerge-"))
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t.test")
        _git(self.d, "config", "user.name", "Tester")
        (self.d / "a.txt").write_text("base\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "init")
        self.base = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        _git(self.d, "checkout", "-qb", "feature")
        (self.d / "b.txt").write_text("feature\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "feature work")
        _git(self.d, "checkout", "-q", self.base)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _findings(self):
        t = LocalRepoTarget(self.d, "tmp", ScanOptions())
        return GitHistoryMatcher().scan(t, EVIL_SIG)

    def test_clean_merge_not_flagged(self):
        _git(self.d, "merge", "--no-ff", "-q", "-m", "honest merge", "feature")
        self.assertEqual(self._findings(), [], "honest merge must not be flagged")

    def test_evil_merge_flagged(self):
        # Merge but inject a file that exists in neither parent.
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected in the merge only\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "merge with injection")
        findings = self._findings()
        self.assertTrue(findings, "evil merge should be detected")
        self.assertIn("evil.txt", findings[0].evidence)


if __name__ == "__main__":
    unittest.main()

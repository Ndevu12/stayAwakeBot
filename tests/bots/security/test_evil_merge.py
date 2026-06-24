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

    def test_overlapping_clean_merge_not_flagged(self):
        # Regression for #1004: both sides edit the SAME file in different hunks; the clean
        # 3-way auto-merge combines them, so the merged file differs from BOTH parents. That
        # is normal git, not an evil merge — it must NOT be flagged. (The old "changed vs
        # every parent" intersection flagged exactly this.)
        (self.d / "shared.txt").write_text("l1\nl2\nl3\nl4\nl5\n")
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "add shared")
        _git(self.d, "checkout", "-qb", "side")
        (self.d / "shared.txt").write_text("l1-side\nl2\nl3\nl4\nl5\n")    # edit top hunk
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "side edits l1")
        _git(self.d, "checkout", "-q", self.base)
        (self.d / "shared.txt").write_text("l1\nl2\nl3\nl4\nl5-base\n")    # edit bottom hunk
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "base edits l5")
        _git(self.d, "merge", "--no-ff", "-q", "-m", "clean combine", "side")
        # The merged shared.txt == "l1-side … l5-base": differs from both parents, equals the
        # clean auto-merge → no deviation → no finding.
        self.assertEqual(self._findings(), [],
                         "a clean 3-way merge of independent edits must not be flagged")

    def test_merge_deleting_one_sided_add_not_flagged(self):
        # Regression for the worm-guard false positive: `feature` ADDS b.txt (absent on base
        # and at the merge-base). A clean 3-way merge KEEPS that addition, so the auto-merge
        # tree contains b.txt — but the recorded merge DELETES it (a routine "accept the other
        # branch's removal" resolution). That deviates from the auto-merge only by a deletion,
        # which injects nothing, so it must NOT be flagged as an evil merge.
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        _git(self.d, "rm", "-qf", "b.txt")   # -f: b.txt is staged by the merge but not in HEAD
        _git(self.d, "commit", "-qm", "merge but drop b.txt")
        self.assertEqual(self._findings(), [],
                         "a merge that only deletes a path must not be flagged")


if __name__ == "__main__":
    unittest.main()

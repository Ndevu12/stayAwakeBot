#!/usr/bin/env python3
"""PR submission: slug parsing + duplicate-PR avoidance (no real git/network)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


from stayawake.bots.security import pr                              # noqa: E402
from stayawake.bots.security.models import Finding, Severity, ScanResult  # noqa: E402
from stayawake.bots.security.remediation import Change             # noqa: E402


class TestSlug(unittest.TestCase):
    def test_parses_ssh_and_https(self):
        self.assertEqual(pr.slug_from_url("git@github.com:Ndevu12/stayAwakeBot.git"), "Ndevu12/stayAwakeBot")
        self.assertEqual(pr.slug_from_url("https://github.com/Ndevu12/stayAwakeBot"), "Ndevu12/stayAwakeBot")
        self.assertIsNone(pr.slug_from_url("git@gitlab.com:x/y.git"))


def _fake_git(cwd, *args, **kwargs):   # **kwargs tolerates _git(..., env=…) on push
    cp = SimpleNamespace(returncode=0, stdout="", stderr="")
    if args[:2] == ("remote", "get-url"):
        cp.stdout = "git@github.com:owner/repo.git"
    elif args[:1] == ("symbolic-ref",):
        cp.stdout = "refs/remotes/origin/main"
    return cp


class TestNoDuplicatePr(unittest.TestCase):
    def _run(self, existing_pulls):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        clean = ScanResult("owner/repo", "local", [])
        # First scan finds the payload; the post-apply re-scan(s) come back clean.
        scans = [infected, clean, clean]
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=existing_pulls), \
             mock.patch.object(pr.github_api, "create_pull",
                               return_value={"number": 99, "html_url": "u"}) as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        return outcome, create

    def test_opens_pr_when_none_exists(self):
        outcome, create = self._run(existing_pulls=[])
        create.assert_called_once()
        self.assertIn("opened PR #99", outcome)

    def test_updates_not_duplicates_when_pr_open(self):
        outcome, create = self._run(existing_pulls=[{"number": 7, "html_url": "u7"}])
        create.assert_not_called()                       # <-- no duplicate PR
        self.assertIn("updated existing PR #7", outcome)

    def test_aborts_when_payload_survives_remediation(self):
        # A2: if the tree is still infected after apply+quarantine, NO PR is opened.
        finding = Finding("x", "code-loader", Severity.CRITICAL, "evil.cjs",
                          "loader", remediation="strip-appended-payload")
        infected = ScanResult("owner/repo", "local", [finding])
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target", return_value=infected), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "evil.cjs")]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "quarantine_residual", return_value=[]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "create_pull") as create:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")
        create.assert_not_called()
        self.assertIn("ABORTED", outcome)


class TestReadOnlyFallback(unittest.TestCase):
    """When the fix branch can't be pushed (no write access), the remediation ladder
    must still produce something: a patch artifact AND a de-duplicated notify issue."""

    def _run(self, existing_issues, out):
        finding = Finding("x", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", remediation="strip-appended-payload")
        scans = [ScanResult("owner/repo", "local", [finding]),   # worktree scan: infected
                 ScanResult("owner/repo", "local", []),          # post-apply re-scan: clean
                 ScanResult("owner/repo", "local", [])]

        def fake_git(cwd, *args, **kwargs):   # **kwargs tolerates _git(..., env=…) on push
            cp = SimpleNamespace(returncode=0, stdout="", stderr="")
            if args[:2] == ("remote", "get-url"):
                cp.stdout = "git@github.com:owner/repo.git"
            elif args[:1] == ("symbolic-ref",):
                cp.stdout = "refs/remotes/origin/main"
            elif args[:1] == ("push",):
                cp.returncode = 1                       # <-- read-only: push rejected
            elif args[:1] == ("format-patch",):
                cp.stdout = "From abc\nSubject: fix\n\npatch-body\n"
            return cp

        with mock.patch.object(pr, "_git", side_effect=fake_git), \
             mock.patch.object(pr, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else scans), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.github_api, "list_open_pulls", return_value=[]), \
             mock.patch.object(pr.github_api, "create_pull") as create_pull, \
             mock.patch.object(pr.github_api, "list_open_issues", return_value=existing_issues), \
             mock.patch.object(pr.github_api, "create_issue",
                               return_value={"number": 5, "html_url": "iu"}) as create_issue:
            outcome = pr.submit_fix_pr(Path("/repo"), object(), {}, [], token="t",
                                       patches_dir=out)
        return outcome, create_pull, create_issue

    def test_saves_patch_and_opens_issue(self):
        out = Path(tempfile.mkdtemp())
        outcome, create_pull, create_issue = self._run([], out)
        create_pull.assert_not_called()                  # no PR opened
        create_issue.assert_called_once()                # notify issue opened
        self.assertIn("patch", outcome.lower())
        self.assertIn("issue #5", outcome)
        patch_file = out / "owner-repo.patch"
        self.assertTrue(patch_file.is_file(), "fix must be saved as a patch on push failure")
        self.assertIn("patch-body", patch_file.read_text(encoding="utf-8"))

    def test_issue_is_deduplicated(self):
        out = Path(tempfile.mkdtemp())
        outcome, _, create_issue = self._run([{"number": 9}], out)
        create_issue.assert_not_called()                 # an open issue exists ⇒ no duplicate
        self.assertIn("#9", outcome)


if __name__ == "__main__":
    unittest.main()

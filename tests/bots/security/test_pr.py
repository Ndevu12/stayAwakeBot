#!/usr/bin/env python3
"""PR submission: slug parsing + duplicate-PR avoidance (no real git/network)."""
from __future__ import annotations

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


def _fake_git(cwd, *args):
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


if __name__ == "__main__":
    unittest.main()

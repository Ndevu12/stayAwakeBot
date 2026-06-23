#!/usr/bin/env python3
"""PR submission: slug parsing + duplicate-PR avoidance (no real git/network)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from security import pr                              # noqa: E402
from security.models import Finding, Severity, ScanResult  # noqa: E402
from security.remediation import Change             # noqa: E402


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
        with mock.patch.object(pr, "_git", side_effect=_fake_git), \
             mock.patch.object(pr, "scan_target",
                               return_value=ScanResult("owner/repo", "local", [finding])), \
             mock.patch.object(pr.remediation, "plan",
                               return_value=[Change("strip-payload", "postcss.config.mjs")]), \
             mock.patch.object(pr.remediation, "apply", return_value=None), \
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


if __name__ == "__main__":
    unittest.main()

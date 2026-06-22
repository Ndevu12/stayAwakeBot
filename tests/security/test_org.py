#!/usr/bin/env python3
"""Org-wide auto-PR sweep orchestration (no real clone/network)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from stayawakebot.security import remediator                    # noqa: E402

SIGS = ROOT / "config" / "security_signatures.yml"


def _cfg(users):
    f = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    f.write(f"settings: {{ signatures_path: '{SIGS}' }}\n"
            f"targets: {{ github: {{ users: {users} }} }}\n")
    f.close()
    return f.name


class TestOrgSweep(unittest.TestCase):
    def test_no_token_is_noop(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(remediator.submit_org_prs(_cfg(["o"]), token=None), 0)

    def test_no_targets_is_noop(self):
        self.assertEqual(remediator.submit_org_prs(_cfg([]), token="t"), 0)

    def test_opens_one_pr_per_infected_repo(self):
        with mock.patch.object(remediator.github_api, "list_repos", return_value=["o/a", "o/b"]), \
             mock.patch.object(remediator.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="opened PR #1 (url)"), \
             mock.patch.object(remediator.shutil, "rmtree"):
            self.assertEqual(remediator.submit_org_prs(_cfg(["o"]), token="t"), 2)


if __name__ == "__main__":
    unittest.main()

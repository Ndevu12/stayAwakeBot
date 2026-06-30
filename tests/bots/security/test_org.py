#!/usr/bin/env python3
"""Remote fix sweep orchestration — `saw fix --remote` (no real clone/network)."""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security import service


def _cfg(users):
    # No signatures_path → the scanner uses its packaged default DB.
    f = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    f.write(f"targets: {{ github: {{ users: {users} }} }}\n")
    f.close()
    return f.name


@contextlib.contextmanager
def _fake_https_auth(_token):
    yield ("https://x@github.com/", {})


class TestRemoteFix(unittest.TestCase):
    def test_no_token_is_noop(self):
        # No credential at all (hermetic: don't let a logged-in gh supply a real token).
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(service.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(service.github_api, "list_repos", return_value=[]):
            self.assertEqual(remediator.fix(_cfg(["o"]), remote=True, no_stream=True), 0)

    def test_no_targets_is_noop(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_repos", return_value=[]):
            self.assertEqual(remediator.fix(_cfg([]), remote=True, no_stream=True), 0)

    def test_opens_one_pr_per_repo(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_repos", return_value=["o/a", "o/b"]), \
             mock.patch.object(remediator.gitutil, "github_https_auth", _fake_https_auth), \
             mock.patch.object(remediator.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="o/x: opened PR #1 (url)") as m_pr, \
             mock.patch.object(remediator.shutil, "rmtree"):
            # Two repos, both cloned + PR'd cleanly → no repo needs review → exit 0.
            self.assertEqual(remediator.fix(_cfg(["o"]), remote=True, no_stream=True), 0)
            self.assertEqual(m_pr.call_count, 2)   # one PR attempt per repo

    def test_aborted_repo_makes_exit_one(self):
        with mock.patch.object(service.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(service.github_api, "list_repos", return_value=["o/a"]), \
             mock.patch.object(remediator.gitutil, "github_https_auth", _fake_https_auth), \
             mock.patch.object(remediator.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0, stdout="", stderr="")), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="o/a: ABORTED — 1 finding still present"), \
             mock.patch.object(remediator.shutil, "rmtree"):
            # A repo that couldn't be auto-cleaned (ABORTED) → exit 1 (needs manual review).
            self.assertEqual(remediator.fix(_cfg(["o"]), remote=True, no_stream=True), 1)


if __name__ == "__main__":
    unittest.main()

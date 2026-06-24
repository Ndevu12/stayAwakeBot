#!/usr/bin/env python3
"""GitHub credential resolution: env precedence + gh fallback, with every gh edge
case (not installed, not logged in, empty, timeout, OS error) degrading to no token
rather than raising."""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

from stayawake.core import auth


def _cp(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["gh"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class TestResolveToken(unittest.TestCase):
    def test_env_security_token_preferred_and_gh_not_called(self):
        with mock.patch.dict(os.environ, {"GH_SECURITY_TOKEN": "envtok"}, clear=True), \
             mock.patch.object(auth, "gh_token", return_value="ghtok") as gh:
            self.assertEqual(auth.resolve_token(), ("envtok", "GH_SECURITY_TOKEN"))
            gh.assert_not_called()  # never shell out when an env token is present

    def test_github_token_used_when_security_absent(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "ght"}, clear=True), \
             mock.patch.object(auth, "gh_token", return_value=None):
            self.assertEqual(auth.resolve_token(), ("ght", "GITHUB_TOKEN"))

    def test_gh_fallback_when_no_env(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(auth, "gh_token", return_value="ghtok"):
            self.assertEqual(auth.resolve_token(), ("ghtok", "gh"))

    def test_none_when_nothing_available(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(auth, "gh_token", return_value=None):
            self.assertEqual(auth.resolve_token(), (None, None))

    def test_blank_env_var_is_ignored(self):
        with mock.patch.dict(os.environ, {"GH_SECURITY_TOKEN": "   "}, clear=True), \
             mock.patch.object(auth, "gh_token", return_value="ghtok"):
            self.assertEqual(auth.resolve_token(), ("ghtok", "gh"))


class TestGhToken(unittest.TestCase):
    def test_not_installed(self):
        with mock.patch.object(auth.shutil, "which", return_value=None):
            self.assertIsNone(auth.gh_token())

    def test_logged_in_returns_stripped_token(self):
        with mock.patch.object(auth.shutil, "which", return_value="/usr/bin/gh"), \
             mock.patch.object(auth.subprocess, "run", return_value=_cp(0, "tok123\n")):
            self.assertEqual(auth.gh_token(), "tok123")

    def test_not_logged_in_returns_none(self):
        with mock.patch.object(auth.shutil, "which", return_value="/usr/bin/gh"), \
             mock.patch.object(auth.subprocess, "run", return_value=_cp(1, "", "no oauth token")):
            self.assertIsNone(auth.gh_token())

    def test_empty_output_returns_none(self):
        with mock.patch.object(auth.shutil, "which", return_value="/usr/bin/gh"), \
             mock.patch.object(auth.subprocess, "run", return_value=_cp(0, "  \n")):
            self.assertIsNone(auth.gh_token())

    def test_timeout_returns_none(self):
        with mock.patch.object(auth.shutil, "which", return_value="/usr/bin/gh"), \
             mock.patch.object(auth.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("gh", 10)):
            self.assertIsNone(auth.gh_token())

    def test_os_error_returns_none(self):
        with mock.patch.object(auth.shutil, "which", return_value="/usr/bin/gh"), \
             mock.patch.object(auth.subprocess, "run", side_effect=OSError("spawn failed")):
            self.assertIsNone(auth.gh_token())


class TestHint(unittest.TestCase):
    def test_hint_when_gh_missing_says_install(self):
        with mock.patch.object(auth, "gh_installed", return_value=False):
            h = auth.no_credential_hint("cloning private repos")
            self.assertIn("install the github cli", h.lower())
            self.assertIn("cloning private repos", h)

    def test_hint_when_gh_present_says_login(self):
        with mock.patch.object(auth, "gh_installed", return_value=True):
            h = auth.no_credential_hint("cloning private repos")
            self.assertIn("gh auth login", h)
            self.assertNotIn("install the GitHub CLI", h)


if __name__ == "__main__":
    unittest.main()

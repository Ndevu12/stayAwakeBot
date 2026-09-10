#!/usr/bin/env python3
"""GitHub HTTPS auth helper: the token must never appear in the URL, process args, or
the askpass file — only in the child environment, where git reads it via GIT_ASKPASS."""
from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib import git as gitutil


@unittest.skipIf(os.name == "nt", "askpass path is POSIX-only; Windows keeps credential-in-URL")
class TestGithubHttpsAuth(unittest.TestCase):
    def test_token_kept_out_of_url_and_askpass_file(self):
        secret = "ghp_SUPERSECRET_0123456789"
        with gitutil.github_https_auth(secret) as (prefix, env):
            # URL prefix carries only the username, never the secret.
            self.assertEqual(prefix, "https://x-access-token@github.com/")
            self.assertNotIn(secret, prefix)
            # The secret lives only in the child env, read via the askpass helper.
            self.assertEqual(env["SAB_GH_TOKEN"], secret)
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            askpass = Path(env["GIT_ASKPASS"])
            self.assertTrue(askpass.is_file())
            self.assertTrue(os.access(askpass, os.X_OK), "askpass must be executable")
            self.assertNotIn(secret, askpass.read_text(encoding="utf-8"),
                             "token must NOT be baked into the askpass script")
            saved = askpass
        self.assertFalse(saved.exists(), "askpass script must be cleaned up on exit")

    def test_no_token_is_anonymous(self):
        with gitutil.github_https_auth(None) as (prefix, env):
            self.assertEqual(prefix, "https://github.com/")
            self.assertNotIn("GIT_ASKPASS", env)
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_empty_token_is_anonymous(self):
        with gitutil.github_https_auth("") as (prefix, env):
            self.assertEqual(prefix, "https://github.com/")
            self.assertNotIn("GIT_ASKPASS", env)




class TestSshAwareTransport(unittest.TestCase):
    """HTTPS (scoped token, secret out of argv) is tried first; SSH is the added reach when HTTPS
    cannot get to the repo. The transport that works is cached and tried first next time."""

    def setUp(self):
        from stayawake.lib.git import auth as gauth
        gauth._transport.clear()
        self.addCleanup(gauth._transport.clear)

    def _attempt(self, https_ok, ssh_ok):
        calls = []

        def attempt(url, env):
            is_ssh = url.startswith("git@")
            calls.append("ssh" if is_ssh else "https")
            return mock.Mock(returncode=0 if (ssh_ok if is_ssh else https_ok) else 128)
        return attempt, calls

    def test_https_used_when_it_works_and_ssh_not_tried(self):
        from stayawake.lib.git import auth as gauth
        attempt, calls = self._attempt(https_ok=True, ssh_ok=True)
        res = gauth.run_remote_git("acme/app", "tok", attempt)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(calls, ["https"])
        self.assertEqual(gauth._transport["acme/app"], "https")

    def test_falls_to_ssh_when_https_fails(self):
        from stayawake.lib.git import auth as gauth
        attempt, calls = self._attempt(https_ok=False, ssh_ok=True)
        res = gauth.run_remote_git("acme/app", "tok", attempt)
        self.assertEqual(res.returncode, 0)
        self.assertEqual(calls, ["https", "ssh"])
        self.assertEqual(gauth._transport["acme/app"], "ssh")

    def test_cached_transport_is_tried_first(self):
        from stayawake.lib.git import auth as gauth
        gauth._transport["acme/app"] = "ssh"
        attempt, calls = self._attempt(https_ok=True, ssh_ok=True)
        gauth.run_remote_git("acme/app", "tok", attempt)
        self.assertEqual(calls, ["ssh"])

    def test_both_fail_returns_failure_and_caches_nothing(self):
        from stayawake.lib.git import auth as gauth
        attempt, calls = self._attempt(https_ok=False, ssh_ok=False)
        res = gauth.run_remote_git("acme/app", "tok", attempt)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(calls, ["https", "ssh"])
        self.assertNotIn("acme/app", gauth._transport)

    def test_attempt_gets_each_transport_url_with_no_token_in_ssh(self):
        from stayawake.lib.git import auth as gauth
        seen = []

        def attempt(url, env):
            seen.append(url)
            return mock.Mock(returncode=0 if url.startswith("git@") else 128)
        gauth.run_remote_git("acme/app", "tok", attempt)
        self.assertEqual(seen[0], "https://x-access-token@github.com/acme/app.git")
        self.assertEqual(seen[1], "git@github.com:acme/app.git")
        self.assertNotIn("tok", seen[1])

    def test_ssh_env_never_prompts_and_carries_no_token(self):
        from stayawake.lib.git import auth as gauth
        env = gauth._ssh_env()
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertIn("BatchMode=yes", env["GIT_SSH_COMMAND"])
        self.assertNotIn("SAB_GH_TOKEN", env)

    def test_github_remote_yields_ssh_url_when_that_is_cached(self):
        from stayawake.lib.git import auth as gauth
        gauth._transport["acme/app"] = "ssh"
        with gauth.github_remote("acme/app", "tok") as (url, env):
            self.assertEqual(url, "git@github.com:acme/app.git")
            self.assertNotIn("tok", url)


if __name__ == "__main__":
    unittest.main()

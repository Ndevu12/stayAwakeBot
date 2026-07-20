#!/usr/bin/env python3
"""GitHub HTTPS auth helper: the token must never appear in the URL, process args, or
the askpass file — only in the child environment, where git reads it via GIT_ASKPASS."""
from __future__ import annotations

import os
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

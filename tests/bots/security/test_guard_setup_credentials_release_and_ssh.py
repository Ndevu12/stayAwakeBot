#!/usr/bin/env python3
"""saw's own HTTPS git leaves the user's credential helpers out; the latest SAW Guard release is
read without the token when the token cannot read it; a guard PR from a clone that pushes over SSH
does not need the `workflow` scope."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.guard import provision
from stayawake.lib.adapters import github_api
from stayawake.lib.git import auth


class TestSawsGitLeavesCredentialHelpersOut(unittest.TestCase):
    def test_the_helper_list_is_emptied_with_and_without_a_token(self):
        for token in (None, "t0k"):
            with auth.github_https_auth(token) as (_prefix, env):
                n = int(env["GIT_CONFIG_COUNT"]) - 1
                self.assertEqual("credential.helper", env[f"GIT_CONFIG_KEY_{n}"])
                self.assertEqual("", env[f"GIT_CONFIG_VALUE_{n}"])

    def test_config_the_user_set_this_way_is_kept(self):
        with mock.patch.dict("os.environ", {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.x",
                                            "GIT_CONFIG_VALUE_0": "y"}):
            with auth.github_https_auth(None) as (_prefix, env):
                self.assertEqual("2", env["GIT_CONFIG_COUNT"])
                self.assertEqual("core.x", env["GIT_CONFIG_KEY_0"])
                self.assertEqual("credential.helper", env["GIT_CONFIG_KEY_1"])


class TestTheLatestReleaseIsReadWithoutATokenThatCannotReadIt(unittest.TestCase):
    def test_a_refused_token_falls_back_to_reading_without_one(self):
        def answer(path, token=None, quiet=False):
            return {"tag_name": "v0.2.0"} if token is None else None
        with mock.patch.object(github_api, "request", side_effect=answer):
            self.assertEqual("v0.2.0", github_api.latest_release("o", "r", "t0k")["tag_name"])

    def test_a_refused_token_falls_back_for_the_release_commit_too(self):
        def answer(path, token=None, quiet=False):
            return {"sha": "a" * 40} if token is None else None
        with mock.patch.object(github_api, "request", side_effect=answer):
            self.assertEqual("a" * 40, github_api.ref_commit_sha("o", "r", "tags/v0.2.0", "t0k"))


class TestAGuardPrOverSsh(unittest.TestCase):
    def _clone(self, url: str) -> Path:
        repo = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", url], check=True)
        return repo

    def test_an_ssh_origin_pushes_over_ssh(self):
        self.assertTrue(provision._pushes_over_ssh(self._clone("git@github.com:o/r.git")))
        self.assertTrue(provision._pushes_over_ssh(self._clone("ssh://git@github.com/o/r.git")))

    def test_an_https_origin_does_not(self):
        self.assertFalse(provision._pushes_over_ssh(self._clone("https://github.com/o/r.git")))

    def test_an_ssh_origin_asks_only_for_what_a_fix_pr_needs(self):
        from stayawake.core.identity import Intent
        repo = self._clone("git@github.com:o/r.git")
        refused = mock.Mock(allowed=False, message="stop")
        with mock.patch("stayawake.core.identity.require", return_value=refused) as require:
            provision._setup_pr(repo, mock.Mock(), "main", None, False)
        self.assertEqual(Intent.OPEN_FIX_PR, require.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

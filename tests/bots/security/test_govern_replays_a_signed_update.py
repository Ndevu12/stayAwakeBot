#!/usr/bin/env python3
"""A signed pull, merge or rebase is checked, and the commit that reaches the folder is signed."""
from __future__ import annotations

import subprocess

from stayawake.bots.security import govern
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout


class ASignedUpdate(_TrackingCheckout):

    def setUp(self):
        super().setUp()
        key = self.root / "signing-key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        for setting, value in (("gpg.format", "ssh"), ("user.signingkey", str(key)), ("commit.gpgsign", "true")):
            self.git(self.open, "config", setting, value)
        self.write(self.open, "local.txt", "local\n")
        self.commit(self.open, "local work")

    def _checked_and_applied(self, *args: str) -> None:
        answer, _code = govern.prepare(str(self.open), str(self.into), "git", list(args))
        self.assertIn("scan", answer, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertTrue((self.open / "new.txt").exists())

    def _signed(self, commit: str = "HEAD") -> bool:
        return "gpgsig" in self.git(self.open, "cat-file", "-p", commit)

    def test_a_signed_pull_that_merges_is_checked_and_signed(self):
        self._checked_and_applied("pull", "--no-rebase")
        self.assertEqual(len(self.git(self.open, "rev-list", "--parents", "-n", "1", "HEAD").split()), 3)
        self.assertTrue(self._signed())

    def test_a_merge_asked_to_sign_is_checked_and_signed(self):
        self.git(self.open, "config", "commit.gpgsign", "false")
        self.git(self.open, "fetch", "-q")
        self._checked_and_applied("merge", "--no-ff", "-S", "origin/main")
        self.assertTrue(self._signed())

    def test_a_signed_rebase_is_checked_and_signs_the_rebased_commit(self):
        self._checked_and_applied("pull", "--rebase")
        self.assertIn("local work", self.git(self.open, "log", "-1", "--format=%s"))
        self.assertTrue(self._signed())

    def test_a_signing_program_the_repository_names_never_runs(self):
        ran = self.root / "ran"
        program = self.root / "repository-signer"
        program.write_text(f"#!/bin/sh\ntouch {ran}\nexit 1\n")
        program.chmod(0o755)
        self.git(self.open, "config", "gpg.ssh.program", str(program))
        answer, _code = govern.prepare(str(self.open), str(self.into), "git", ["pull", "--no-rebase"])
        self.assertFalse(ran.exists(), "saw ran a signing program the repository named")
        self.assertIn("scan", answer, answer)
        govern.apply(str(self.open), str(self.into))
        self.assertTrue(self._signed())


if __name__ == "__main__":
    import unittest
    unittest.main()

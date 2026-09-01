#!/usr/bin/env python3
"""The sandbox itself. A fixture nothing tests is how a test came to sweep the system temp
directory and how another answered a question from the developer's own git config."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from tests.support.gitrepo import GitSandbox, OutsideTheSandbox


class TestTheBoundaryHolds(GitSandbox):
    def test_a_path_outside_the_sandbox_is_refused(self):
        with self.assertRaises(OutsideTheSandbox):
            self.owned(Path(self.root).parent)
        with self.assertRaises(OutsideTheSandbox):
            self.owned("/tmp")

    def test_a_symlink_out_of_the_sandbox_is_refused(self):
        escape = self.root / "escape"
        escape.symlink_to(Path(self.root).parent)
        with self.assertRaises(OutsideTheSandbox):
            self.owned(escape / "somewhere")

    def test_every_helper_goes_through_the_boundary(self):
        outside = Path(self.root).parent
        with self.assertRaises(OutsideTheSandbox):
            self.git(outside, "status")
        with self.assertRaises(OutsideTheSandbox):
            self.git_may_fail(outside, "status")
        with self.assertRaises(OutsideTheSandbox):
            self.write(outside, "x.txt", "no")


class TestTheHostDoesNotDecideTheAnswer(GitSandbox):
    def test_the_developers_global_config_is_not_consulted(self):
        repo = self.new_repo()
        self.assertEqual(os.environ["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(
            subprocess.run(["git", "-C", str(repo), "config", "--global", "--list"],
                           capture_output=True, text=True).stdout.strip(), "")

    def test_state_is_written_inside_the_sandbox(self):
        self.assertTrue(Path(os.environ["XDG_STATE_HOME"]).is_relative_to(self.root))

    def test_a_remote_operation_fails_instead_of_dialling_out(self):
        """The failure that matters is the SPEED of it: unstubbed, these waited out a 180-second
        network timeout each and looked like a slow suite."""
        repo = self.new_repo()
        res = self.git_may_fail(repo, "ls-remote", "https://github.com/acme/does-not-exist.git")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not allowed", (res.stderr or "").lower())


class TestTheShapesAreWhatTheyClaim(GitSandbox):
    def test_the_evil_merge_carries_the_payload_and_a_hand_edit(self):
        repo, merge = self.evil_merge_repo()
        self.assertEqual(len(self.git(repo, "rev-list", "--parents", "-n1", merge).split()) - 1, 2)
        self.assertEqual(self.git(repo, "show", f"{merge}:payload.js"), "PAYLOAD\n")
        self.assertEqual(self.git(repo, "show", f"{merge}:README.md"),
                         "readme\nnote added while merging\n")

    def test_a_repository_starts_clean_and_unsigned(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "a\n")
        head = self.commit(repo, "init")
        self.assertNotIn(b"gpgsig", self.raw_commit(repo, head))
        self.assertEqual(self.git(repo, "status", "--porcelain"), "")

    def test_the_raw_body_is_bytes_not_decoded_text(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "a\n")
        self.git(repo, "add", "-A")
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "-F", "-"],
                       input=b"subject\n\nno final newline", check=True, capture_output=True)
        self.assertEqual(self.raw_body(repo, self.rev(repo)), b"subject\n\nno final newline\n")
        self.assertTrue(self.header(repo, self.rev(repo), "author").startswith(b"author T <"))


if __name__ == "__main__":
    unittest.main()

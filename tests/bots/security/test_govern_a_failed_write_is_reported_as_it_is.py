#!/usr/bin/env python3
"""An update that cannot be written into the open folder leaves it unchanged, or says it may have
changed."""
from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.lib.git import incoming
from stayawake.lib.git.write import working_tree
from tests.support.gitrepo import GitSandbox


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0, "needs a folder its owner cannot write")
class AFailedWriteIsReportedAsItIs(GitSandbox):

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("open")
        self.write(self.repo, "a.txt", "goes away\n")
        self.write(self.repo, "ro/b.txt", "before\n")
        self.base = self.commit(self.repo, "start")
        self.git(self.repo, "checkout", "-q", "-b", "next")
        self.git(self.repo, "rm", "-q", "a.txt")
        self.write(self.repo, "ro/b.txt", "after\n")
        self.commit(self.repo, "delete a, change b")
        self.git(self.repo, "checkout", "-q", "main")
        self.into = self.root / "holding"
        self._run("govern", "prepare", "--json", "--repo", str(self.repo), "--into", str(self.into),
                  "--tool", "git", "--", "checkout", "next")
        (self.repo / "ro").chmod(0o555)
        self.addCleanup((self.repo / "ro").chmod, 0o755)

    def _run(self, *args: str) -> dict:
        out = io.StringIO()
        with redirect_stdout(out):
            cli.main(list(args))
        return json.loads(out.getvalue())

    def _apply(self) -> dict:
        return self._run("govern", "apply", "--json", "--repo", str(self.repo), "--into", str(self.into))

    def test_a_write_that_fails_puts_back_what_it_removed(self):
        applied = self._apply()
        self.assertFalse(applied["applied"])
        self.assertEqual(applied["reason"], "the update could not be written into the open folder")
        self.assertEqual((self.repo / "a.txt").read_text(), "goes away\n")
        self.assertEqual((self.repo / "ro" / "b.txt").read_text(), "before\n")
        self.assertEqual(self.git(self.repo, "status", "--porcelain").strip(), "")
        self.assertEqual(self.rev(self.repo), self.base)

    def test_a_folder_that_cannot_be_put_back_is_said_to_have_changed(self):
        real = working_tree._write_paths
        calls = []

        def write_then_refuse_the_way_back(*args, **kwargs):
            calls.append(args[2])
            return real(*args, **kwargs) if len(calls) == 1 else False
        with mock.patch.object(working_tree, "_write_paths", side_effect=write_then_refuse_the_way_back):
            applied = self._apply()
        self.assertFalse(applied["applied"])
        self.assertEqual(applied["reason"], incoming.WRITE_LEFT_PART_WAY)
        self.assertFalse((self.repo / "a.txt").exists())

    def test_putting_the_folder_back_leaves_it_as_it_was_when_it_cannot_finish(self):
        self.assertEqual(incoming.restore(self.repo, self.git(self.repo, "rev-parse", "next").strip()),
                         "the folder could not be put back")
        self.assertEqual(self.git(self.repo, "status", "--porcelain").strip(), "")
        self.assertEqual(self.rev(self.repo), self.base)


if __name__ == "__main__":
    unittest.main()

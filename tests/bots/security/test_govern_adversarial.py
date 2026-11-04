#!/usr/bin/env python3
"""Adversarial gate for `saw govern`: refute the three fail-open properties with hostile input.

1. Nothing from the incoming repository runs — an incoming `.gitattributes` filter does not execute.
2. An infected tree never reaches the open folder, even over a dirty file.
3. The operator's uncommitted work is never lost, including on the exact path the update changes.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from stayawake import cli
from stayawake.utils import exitcodes
from tests.support import samples
from tests.support.gitrepo import GitSandbox


class GovernAdversarial(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "already\n")
        self.commit(self.repo, "start")
        self.base = self.rev(self.repo)
        self.git(self.repo, "checkout", "-q", "-b", "next")
        self.write(self.repo, "arrived.txt", "from next\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", "main")
        self.into = self.root / "holding"

    def _prepare(self, *cmd: str) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["govern", "prepare", "--json", "--repo", str(self.repo),
                             "--into", str(self.into), "--tool", "git", "--", *cmd])
        return code, json.loads(out.getvalue())

    def _apply(self) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["govern", "apply", "--json", "--repo", str(self.repo), "--into", str(self.into)])
        return code, json.loads(out.getvalue())

    def test_an_incoming_attributes_filter_never_runs(self):
        # The incoming branch applies a smudge filter to the arriving file; even with the command
        # configured, saw's checkout must not run it.
        self.git(self.repo, "checkout", "-q", "next")
        self.write(self.repo, ".gitattributes", "arrived.txt filter=pwn\n")
        self.commit(self.repo, "attributes")
        self.git(self.repo, "checkout", "-q", "main")
        self.git(self.repo, "config", "filter.pwn.smudge", "sh -c 'touch owned'")
        self._prepare("checkout", "next")
        self.assertFalse((self.repo / "owned").exists())
        self._apply()
        self.assertFalse((self.repo / "owned").exists())

    def test_uncommitted_change_on_the_arriving_path_is_kept(self):
        self.write(self.repo, "arrived.txt", "mine\n")       # operator's own, on the path next brings in
        self.assertEqual(self._prepare("checkout", "next")[0], exitcodes.CLEAN)
        code, applied = self._apply()
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertTrue(applied["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "mine\n")

    def test_an_infected_arrival_leaves_a_dirty_file_untouched(self):
        self.git(self.repo, "checkout", "-q", "next")
        self.write(self.repo, "loader.js",
                   "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE)
        self.commit(self.repo, "worm")
        self.git(self.repo, "checkout", "-q", "main")
        self.write(self.repo, "keep.txt", "WIP\n")           # uncommitted work present
        code, body = self._prepare("checkout", "next")
        self.assertEqual(code, exitcodes.FINDINGS, body)
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "loader.js").exists())
        code, applied = self._apply()
        self.assertFalse(applied["applied"])
        self.assertEqual((self.repo / "keep.txt").read_text(encoding="utf-8"), "WIP\n")
        self.assertFalse((self.repo / "loader.js").exists())


if __name__ == "__main__":
    import unittest
    unittest.main()

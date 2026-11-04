#!/usr/bin/env python3
"""The MCP worker's govern method: a cooperating agent delegates a bringing-files command to saw,
which checks it in a holding area it owns and applies it only when the check is clean or residue.
"""
from __future__ import annotations

from stayawake.bots.mcp.worker import Session
from tests.support import samples
from tests.support.gitrepo import GitSandbox


class McpGovern(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "already\n")
        self.commit(self.repo, "start")
        self.base = self.rev(self.repo)
        self.git(self.repo, "checkout", "-q", "-b", "next")

    def _govern(self, *cmd: str) -> dict:
        return Session().govern({"repo": str(self.repo), "tool": "git", "args": list(cmd)})

    def test_a_clean_update_is_checked_and_applied(self):
        self.write(self.repo, "arrived.txt", "from next\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", "main")
        r = self._govern("checkout", "next")
        self.assertEqual(r["verdict"], "clean", r)
        self.assertTrue(r["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "from next\n")

    def test_an_infected_update_is_held(self):
        self.write(self.repo, "loader.js",
                   "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE)
        self.commit(self.repo, "worm")
        self.git(self.repo, "checkout", "-q", "main")
        r = self._govern("checkout", "next")
        self.assertEqual(r["verdict"], "infected", r)
        self.assertFalse(r["applied"])
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "loader.js").exists())

    def test_a_command_saw_does_not_check_is_not_verified(self):
        self.git(self.repo, "checkout", "-q", "main")
        r = self._govern("status")
        self.assertEqual(r["verdict"], "not verified")

    def test_bad_arguments_are_not_verified(self):
        for bad in ({"tool": "git", "args": ["pull"]},               # no repo
                    {"repo": str(self.repo), "tool": "svn", "args": ["pull"]},  # not git/gh
                    {"repo": str(self.repo), "tool": "git", "args": "pull"}):   # args not a list
            with self.subTest(bad=bad):
                self.assertEqual(Session().govern(bad)["verdict"], "not verified")


if __name__ == "__main__":
    import unittest
    unittest.main()

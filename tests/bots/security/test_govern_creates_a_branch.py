#!/usr/bin/env python3
"""Creating a branch where the folder is passes through; creating one from another commit is checked."""
from __future__ import annotations

from stayawake.bots.security import govern
from stayawake.lib.git import incoming
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_PAYLOAD = "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE


class CreatingABranch(_TrackingCheckout):

    def _head(self) -> str:
        return self.git(self.open, "rev-parse", "HEAD").strip()

    def test_a_new_branch_where_the_folder_is_passes_through(self):
        before = self._head()
        for args in (["switch", "-c", "try"], ["switch", "--create", "try"], ["checkout", "-b", "try"]):
            with self.subTest(args=args):
                answer, code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
                self.assertNotIn("decision", answer)
                self.assertEqual(self._head(), before)

    def test_a_new_branch_from_another_commit_is_checked_and_applied(self):
        self.git(self.open, "fetch", "-q")
        upstream = self.git(self.open, "rev-parse", "origin/main").strip()
        start = self._head()
        for branch, args in (("try", ["switch", "-c", "try", "origin/main"]),
                             ("try-too", ["checkout", "-b", "try-too", "origin/main"])):
            with self.subTest(args=args):
                answer, _code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertIn("scan", answer, answer)
                self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
                self.assertEqual(self._head(), upstream)
                self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), branch)
                self.assertTrue((self.open / "new.txt").exists())
                self.git(self.open, "switch", "-q", "--detach", start)


class WhatACommandBrings(_TrackingCheckout):

    def test_going_back_to_the_previous_branch_is_checked(self):
        for args in (["checkout", "-"], ["switch", "-"]):
            with self.subTest(args=args):
                self.assertFalse(incoming.brings_nothing("git", args))
                self.assertEqual(incoming.classify("git", args), args[0])

    def test_a_command_saw_declines_to_check_is_still_asked_about(self):
        for args in (["rebase", "--abort"], ["fetch", "--dry-run"], ["submodule", "foreach", "git", "pull"]):
            with self.subTest(args=args):
                self.assertFalse(incoming.brings_nothing("git", args))
                answer, _code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertNotIn("passthrough", answer)
                self.assertIn("decision", answer)

    def test_every_spelling_that_names_a_commit_is_checked(self):
        self.write(self.upstream, "loader.js", _PAYLOAD)
        self.commit(self.upstream, "payload")
        self.git(self.open, "fetch", "-q")
        before = self.git(self.open, "rev-parse", "HEAD").strip()
        for args in (["checkout", "-m", "origin/main"], ["checkout", "origin/main", "-m"],
                     ["checkout", "--merge", "origin/main"], ["checkout", "--recurse-submodules", "origin/main"],
                     ["checkout", "--recurse-submodules=yes", "origin/main"], ["switch", "-m", "--detach", "origin/main"],
                     ["switch", "--detach", "origin/main", "-m"], ["checkout", "--made-up-option"]):
            with self.subTest(args=args):
                self.assertFalse(incoming.brings_nothing("git", args))
                answer, _code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertNotIn("passthrough", answer)
                self.assertEqual(self.git(self.open, "rev-parse", "HEAD").strip(), before)
                self.assertFalse((self.open / "loader.js").exists())
                if "--made-up-option" not in args:
                    self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)

    def test_an_end_or_try_word_inside_a_value_or_a_path_is_still_checked(self):
        for args in (["merge", "-m", "--abort", "origin/main"], ["merge", "-m", "--quit", "origin/main"],
                     ["merge", "--mess", "--abort", "origin/main"], ["merge", "--message", "--abort", "origin/main"],
                     ["pull", "-o", "--dry-run"], ["checkout", "origin/main", "--", "--abort"]):
            with self.subTest(args=args):
                self.assertEqual(incoming.classify("git", args), args[0])
        for args in (["merge", "--abort"], ["rebase", "--quit"], ["fetch", "--dry-run"]):
            with self.subTest(args=args):
                self.assertIsNone(incoming.classify("git", args))

    def test_no_stat_and_no_tags_are_still_checked(self):
        for args in (["pull", "-n"], ["fetch", "-n"], ["merge", "-n", "origin/main"], ["rebase", "-n"]):
            with self.subTest(args=args):
                self.assertEqual(incoming.classify("git", args), args[0])


if __name__ == "__main__":
    import unittest
    unittest.main()

#!/usr/bin/env python3
"""Creating a branch where the folder is passes through; creating one from another commit is checked."""
from __future__ import annotations

from stayawake.bots.security import govern
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_PAYLOAD = "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE


class CreatingABranch(_TrackingCheckout):

    def _head(self) -> str:
        return self.git(self.open, "rev-parse", "HEAD").strip()

    def test_a_new_branch_where_the_folder_is_is_made_by_saw(self):
        before = self._head()
        for branch, args in (("try", ["switch", "-c", "try"]), ("try-too", ["switch", "--create", "try-too"]),
                             ("try-three", ["checkout", "-b", "try-three"])):
            with self.subTest(args=args):
                answer, code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertEqual(code, exitcodes.CLEAN, answer)
                self.assertNotIn("decision", answer)
                self.assertEqual(govern.apply(str(self.open), str(self.into))[0],
                                 {"applied": True, "outcome": "brought_in"})
                self.assertEqual(self._head(), before)
                self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), branch)

    def test_a_new_branch_from_another_commit_is_checked_and_applied(self):
        self.git(self.open, "fetch", "-q")
        upstream = self.git(self.open, "rev-parse", "origin/main").strip()
        start = self._head()
        for branch, args in (("try", ["switch", "-c", "try", "origin/main"]),
                             ("try-too", ["checkout", "-b", "try-too", "origin/main"])):
            with self.subTest(args=args):
                answer, _code = govern.prepare(str(self.open), str(self.into), "git", args)
                self.assertIn("scan", answer, answer)
                self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
                self.assertEqual(self._head(), upstream)
                self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), branch)
                self.assertTrue((self.open / "new.txt").exists())
                self.git(self.open, "switch", "-q", "--detach", start)


class EverySpellingIsJudgedByWhatItWrites(_TrackingCheckout):
    """The upstream's main brings a payload. The open folder has fetched it."""

    def setUp(self):
        super().setUp()
        self.write(self.upstream, "loader.js", _PAYLOAD)
        self.commit(self.upstream, "payload")
        self.git(self.open, "fetch", "-q")
        self.before = self.git(self.open, "rev-parse", "HEAD").strip()

    def _never_lands(self, *args: str) -> dict:
        answer, _code = govern.prepare(str(self.open), str(self.into), "git", list(args))
        self.assertNotIn("passthrough", answer)
        govern.apply(str(self.open), str(self.into))
        self.assertEqual(self.git(self.open, "rev-parse", "HEAD").strip(), self.before)
        self.assertFalse((self.open / "loader.js").exists())
        return answer

    def test_going_back_to_the_previous_branch_is_judged(self):
        self.git(self.open, "checkout", "-q", "--detach", "origin/main")
        self.git(self.open, "checkout", "-q", "main")
        for args in (["checkout", "-"], ["switch", "--detach", "-"]):
            with self.subTest(args=args):
                answer = self._never_lands(*args)
                self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)

    def test_a_command_git_refuses_or_saw_does_not_replay_is_asked_about(self):
        for args in (["rebase", "--abort"], ["merge", "--abort"], ["submodule", "foreach", "git", "pull"],
                     ["checkout", "--made-up-option"], ["checkout", "origin/main", "--", "--abort"]):
            with self.subTest(args=args):
                self.assertIn("run-as-typed", self._never_lands(*args)["decision"]["choices"])

    def test_every_spelling_that_writes_the_payload_is_held(self):
        for args in (["checkout", "-m", "origin/main"], ["checkout", "origin/main", "-m"],
                     ["checkout", "--merge", "origin/main"], ["checkout", "--recurse-submodules", "origin/main"],
                     ["checkout", "--recurse-submodules=yes", "origin/main"], ["switch", "-m", "--detach", "origin/main"],
                     ["switch", "--detach", "origin/main", "-m"], ["merge", "-m", "--abort", "origin/main"],
                     ["merge", "--mess", "--abort", "origin/main"], ["merge", "-n", "origin/main"],
                     ["pull", "-n"], ["rebase", "-n"]):
            with self.subTest(args=args):
                answer = self._never_lands(*args)
                self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)


if __name__ == "__main__":
    import unittest
    unittest.main()

#!/usr/bin/env python3
"""A history amend could not read is named, never reported cleaned."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend_survivors import _FILE, _Survivors, _foreign_finding

_OTHER = "lib/other.woff2"


class TestAmendNamesWhatItCouldNotRead(_Survivors):

    def _carrier(self) -> str:
        return self.git(self.d, "log", "--format=%H", "--diff-filter=A", "--", _FILE).strip()

    def _never_removed(self, outcome):
        self.assertNotIn(_FILE, outcome.removed)
        self.assertIn(_FILE, render_amend_line(outcome))

    def test_a_carrier_git_could_not_read_is_never_reported_removed(self):
        self._foreign_on_main()
        carrier, real = self._carrier(), amendmod.gitutil.entry_at

        def unread_carrier(repo, treeish, path):
            return (False, None) if treeish == carrier else real(repo, treeish, path)

        with mock.patch.object(amendmod.gitutil, "entry_at", unread_carrier):
            outcome = self._act_removing_foreign()
        self._never_removed(outcome)

    def _two_fonts(self, failing: str, unread):
        """Run amend over two foreign files while git does not answer `failing` for the other one.
        Returns the outcome."""
        self.write(self.d, _FILE, "wOF2\x00camouflage\n")
        self.write(self.d, _OTHER, "wOF2\x00camouflage too\n")
        self.commit(self.d, "add the foreign fonts")
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "unrelated work")
        scan = ScanResult(target=str(self.d), source="local",
                          findings=[_foreign_finding(_FILE), _foreign_finding(_OTHER)])
        with self._remote(), mock.patch.object(amendmod.gitutil, failing, unread), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=lambda *a: PushResult(True))

    def _cleans_one_and_names_the_other(self, outcome):
        self.assertTrue(outcome.completed)
        self.assertIn(_FILE, outcome.removed)
        self.assertNotIn(_OTHER, outcome.removed)
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._reasons(outcome))
        self.assertIn(f"every copy of {_OTHER}", render_amend_line(outcome))

    def test_what_it_could_read_is_cleaned_and_what_it_could_not_is_named(self):
        real = amendmod.gitutil.entry_at

        def unread_other(repo, treeish, path):
            return (False, None) if path == _OTHER else real(repo, treeish, path)

        self._cleans_one_and_names_the_other(self._two_fonts("entry_at", unread_other))

    def test_a_history_it_could_not_walk_is_named_while_the_rest_is_cleaned(self):
        real = amendmod.gitutil.file_commits

        def unwalked_other(repo, path, **walk):
            return None if path == _OTHER else real(repo, path, **walk)

        self._cleans_one_and_names_the_other(self._two_fonts("file_commits", unwalked_other))

    def test_a_history_git_could_not_walk_is_never_reported_removed(self):
        self._foreign_on_main()
        with mock.patch.object(amendmod.gitutil, "file_commits", return_value=None):
            outcome = self._act_removing_foreign()
        self._never_removed(outcome)

    def test_a_branch_naming_no_commit_is_named_before_any_rewrite(self):
        self._foreign_on_main()
        tip = self.rev(self.d)
        (self.d / ".git" / "refs" / "heads" / "ghost").write_text("1" * 40 + "\n")
        outcome = self._act_removing_foreign()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.BRANCH_NAMES_NO_COMMIT, self._reasons(outcome))
        self.assertIn("refs/heads/ghost", render_amend_line(outcome))
        self.assertEqual(self.rev(self.d), tip)

    def test_a_clone_without_its_whole_history_is_refused_before_any_rewrite(self):
        self._foreign_on_main()
        tip = self.rev(self.d)
        fetched_before = []

        def incomplete(repo):
            fetched_before.append(amendmod.gitutil.fetch_refs.called)
            return False

        with mock.patch.object(amendmod.gitutil, "holds_its_history", incomplete):
            outcome = self._act_removing_foreign()
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.HISTORY_INCOMPLETE, self._reasons(outcome))
        self.assertEqual(fetched_before, [False])
        self.assertEqual(self.rev(self.d), tip)


if __name__ == "__main__":
    unittest.main()

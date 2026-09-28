#!/usr/bin/env python3
"""`saw fix amend` names a removed file that still lives on a ref it does not rewrite.

amend rewrites the branches (local heads and origin). A confirmed foreign file it removed can still
be reached from a ref outside that scope — a tag, the stash, a non-origin remote, an arbitrary ref.
These pin that such a copy is named and makes the run need review, rather than being reported gone.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from stayawake.bots.security.models import CONFIRMED, Finding, ScanResult, Severity
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.bots.security.remediation.footprint import REMOVE_FILE
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend import _AmendFixture

_FILE = "src/fonts/BlockchainFont.woff2"


def _foreign_finding(path=_FILE):
    return Finding("fake-font-blockchain", "fake-font", Severity.HIGH, path,
                   "wholly foreign", remediation=REMOVE_FILE, confidence=CONFIRMED)


class TestAmendNamesSurvivorsOnOtherRefs(_AmendFixture):

    def _act_removing_foreign(self):
        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding()])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
                return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                     pusher=lambda *a: PushResult(True))

    def _foreign_on_main(self):
        """Introduce the foreign file early so it rides to the tip, then two unrelated commits."""
        self.write(self.d, _FILE, "wOF2\x00camouflage\n")
        self.commit(self.d, "add the foreign font")
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "unrelated work")
        self.write(self.d, "app.js", "ok2\n")
        self.commit(self.d, "more unrelated work")

    def _reachable(self, ref, path=_FILE):
        return subprocess.run(["git", "-C", str(self.d), "cat-file", "-e", f"{ref}:{path}"],
                              capture_output=True).returncode == 0

    def _reasons(self, outcome):
        return [r.cause for r in outcome.reasons]

    def test_a_tag_holding_the_removed_file_is_named(self):
        self._foreign_on_main()
        self.git(self.d, "tag", "v1.0")
        outcome = self._act_removing_foreign()
        self.assertIn(_FILE, outcome.removed)
        self.assertTrue(self._reachable("refs/tags/v1.0"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertIn("refs/tags/v1.0", render_amend_line(outcome))

    def test_a_stash_holding_the_removed_file_is_named(self):
        self._foreign_on_main()
        (self.d / "app.js").write_text("dirty\n")
        self.git(self.d, "stash", "push", "-u", "-m", "wip")
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/stash"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertIn("stash@{", render_amend_line(outcome))

    def test_a_non_origin_remote_ref_holding_it_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/remotes/upstream/main", tip)
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/remotes/upstream/main"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/remotes/upstream/main", render_amend_line(outcome))

    def test_an_arbitrary_ref_holding_it_is_named(self):
        self._foreign_on_main()
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/backup/main", tip)
        outcome = self._act_removing_foreign()
        self.assertTrue(self._reachable("refs/backup/main"))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/backup/main", render_amend_line(outcome))

    def test_a_clean_amend_names_no_other_ref(self):
        """No ref outside the branches holds the file, so the new reason does not fire."""
        self._foreign_on_main()
        outcome = self._act_removing_foreign()
        self.assertIn(_FILE, outcome.removed)
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))

    def test_a_tag_at_the_cleaned_tip_is_not_named(self):
        """A tag pointing at the rewritten, clean tip holds no payload and is not a survivor."""
        self._foreign_on_main()
        outcome = self._act_removing_foreign()
        head = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "tag", "release", head)
        self.assertFalse(self._reachable("refs/tags/release"))
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))

    def test_every_stash_reflog_entry_is_enumerated_not_just_the_top(self):
        """A payload can sit in an older stash entry, so the check must see every reflog entry, not
        only `refs/stash` (which is `stash@{0}`)."""
        from stayawake.bots.security.pr import amend as amendmod
        (self.d / "wip.txt").write_text("a\n")
        self.git(self.d, "stash", "push", "-u", "-m", "one")
        (self.d / "wip.txt").write_text("b\n")
        self.git(self.d, "stash", "push", "-u", "-m", "two")
        names = {r for r, _ in amendmod._candidate_refs(self.d)}
        self.assertIn("stash@{0}", names)
        self.assertIn("stash@{1}", names)

    def test_scope_lists_other_refs_but_never_a_branch_or_origin(self):
        """The enumeration covers tags, arbitrary refs and stash entries, and leaves out the branches
        an amend rewrites — a stale `origin` tracking ref is not reported once the push moved it."""
        from stayawake.bots.security.pr import amend as amendmod
        tip = self.git(self.d, "rev-parse", "HEAD").strip()
        self.git(self.d, "update-ref", "refs/remotes/origin/main", tip)
        self.git(self.d, "tag", "v9")
        self.git(self.d, "update-ref", "refs/backup/x", tip)
        names = {r for r, _ in amendmod._candidate_refs(self.d)}
        self.assertIn("refs/tags/v9", names)
        self.assertIn("refs/backup/x", names)
        self.assertNotIn("refs/heads/main", names)
        self.assertNotIn("refs/remotes/origin/main", names)


if __name__ == "__main__":
    unittest.main()

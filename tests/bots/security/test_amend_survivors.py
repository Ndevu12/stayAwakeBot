#!/usr/bin/env python3
"""`saw fix amend` accounts for a removed file beyond the branches it rewrites.

A ref outside the rewrite that still reaches a removed file is named for review, and a file amend
removes does not survive the history it rewrites.
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
        """The foreign file committed early and carried to the tip, with unrelated commits after it."""
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
        """With no ref outside the branches holding the file, no survivor is reported."""
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
        """Every stash reflog entry is checked, not only `refs/stash`."""
        from stayawake.bots.security.pr import amend as amendmod
        (self.d / "wip.txt").write_text("a\n")
        self.git(self.d, "stash", "push", "-u", "-m", "one")
        (self.d / "wip.txt").write_text("b\n")
        self.git(self.d, "stash", "push", "-u", "-m", "two")
        names = {r for r, _ in amendmod._candidate_refs(self.d)}
        self.assertIn("stash@{0}", names)
        self.assertIn("stash@{1}", names)

    def test_scope_lists_other_refs_but_never_a_branch_or_origin(self):
        """The enumeration lists tags, arbitrary refs and stash entries, and no branch an amend
        rewrites."""
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


class TestAmendRemovesEveryCopy(_AmendFixture):
    """A file amend removes does not survive the history it rewrites."""

    OLD, NEW = "src/fonts/loader.woff", "assets/fonts/renamed.woff"
    PAYLOAD = 'var _0x=String.fromCharCode(118,97,114);eval(_0x+" x=1");\n'

    def _act_removing(self, path):
        scan = ScanResult(target=str(self.d), source="local", findings=[_foreign_finding(path)])
        with self._remote():
            with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
                return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                     pusher=lambda *a: PushResult(True))

    def _renamed_payload(self):
        self.write(self.d, self.OLD, self.PAYLOAD)
        self.commit(self.d, "add the foreign font")
        oid = self.git(self.d, "rev-parse", f"HEAD:{self.OLD}").strip()
        self.write(self.d, self.NEW, self.PAYLOAD)
        (self.d / self.OLD).unlink()
        self.commit(self.d, "rename it")
        self.write(self.d, "app.js", "ok\n")
        self.commit(self.d, "unrelated work")
        return oid

    def _on_branch(self, oid):
        objs = subprocess.run(["git", "-C", str(self.d), "rev-list", "--objects", "HEAD"],
                              capture_output=True, text=True).stdout
        return oid in {ln.split()[0] for ln in objs.splitlines() if ln.split()}

    def _reasons(self, outcome):
        return [r.cause for r in outcome.reasons]

    def test_a_renamed_payload_is_removed_at_its_former_path_too(self):
        oid = self._renamed_payload()
        self.git(self.d, "tag", "v-pre", "HEAD~2")
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertIn(self.NEW, outcome.removed)
        self.assertIn(self.OLD, outcome.removed)
        self.assertFalse(self._on_branch(oid))
        self.assertIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._reasons(outcome))
        self.assertIn("refs/tags/v-pre", render_amend_line(outcome))

    def test_a_former_path_reused_by_a_legitimate_file_keeps_it(self):
        oid = self._renamed_payload()
        self.write(self.d, self.OLD, "legitimate font data\n")
        self.commit(self.d, "a new legitimate file at the old name")
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertFalse(self._on_branch(oid))
        kept = self.git(self.d, "show", f"HEAD:{self.OLD}")
        self.assertEqual("legitimate font data\n", kept)

    def test_a_walk_that_cannot_complete_refuses(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=None):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.HISTORY_TOO_LARGE_TO_ENUMERATE, self._reasons(outcome))

    def _anywhere(self, oid):
        objs = subprocess.run(["git", "-C", str(self.d), "rev-list", "--objects",
                               "--branches", "--glob=refs/remotes/origin/*"],
                              capture_output=True, text=True).stdout
        return oid in {ln.split()[0] for ln in objs.splitlines() if ln.split()}

    def test_a_copy_on_a_side_branch_under_a_non_ascii_name_is_removed(self):
        self.git(self.d, "checkout", "-qb", "side")
        self.write(self.d, "src/évil.woff", self.PAYLOAD)
        self.commit(self.d, "a copy on the side")
        self.git(self.d, "checkout", "-q", self.base)
        oid = self._renamed_payload()
        outcome = self._act_removing(self.NEW)
        self.assertTrue(outcome.completed)
        self.assertFalse(self._anywhere(oid))

    def test_a_copy_only_a_side_branch_reaches_is_refused_not_reported_removed(self):
        self.git(self.d, "checkout", "-qb", "side")
        self.write(self.d, "src/copy.woff", self.PAYLOAD)
        self.commit(self.d, "a copy on the side")
        self.git(self.d, "checkout", "-q", self.base)
        self.write(self.d, self.NEW, self.PAYLOAD)
        self.commit(self.d, "the scanned copy")
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=[]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))
        self.assertIn("side", render_amend_line(outcome))

    def test_an_unreadable_location_is_refused_by_name(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=["no/such.woff"]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))
        self.assertIn("no/such.woff", render_amend_line(outcome))

    def test_a_copy_the_run_cannot_take_out_makes_it_refuse(self):
        self._renamed_payload()
        from stayawake.bots.security.pr import amend as amendmod
        with mock.patch.object(amendmod.gitutil, "blob_paths", return_value=[]):
            outcome = self._act_removing(self.NEW)
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.PAYLOAD_STILL_REACHABLE, self._reasons(outcome))


if __name__ == "__main__":
    unittest.main()

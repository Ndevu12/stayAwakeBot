#!/usr/bin/env python3
"""Host-level denials: enforcing only after read-back; never remove what is already there."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import denial
from stayawake.bots.security.hygiene.models import HygieneIssue, PROCESSES_NOT_READABLE_ID
from stayawake.utils import hostdenial


def _issue(id_):
    return HygieneIssue(id=id_, severity="unknown", title=id_, detail=id_, remediation="x")


class TestRunContract(unittest.TestCase):
    def test_not_implemented_is_not_success(self):
        code, text = harden.run(supported=lambda: False, privileged=lambda: True, live=lambda: [])
        self.assertEqual(code, 2)
        self.assertIn("not implemented", text.lower())

    def test_not_root_is_not_success(self):
        code, text = harden.run(supported=lambda: True, privileged=lambda: False, live=lambda: [])
        self.assertEqual(code, 2)
        self.assertIn("root", text.lower())

    def test_live_loader_is_refused(self):
        code, text = harden.run(supported=lambda: True, privileged=lambda: True,
                                live=lambda: [_issue("live-obfuscated-process")],
                                folders=lambda: [], apply=lambda p: None)
        self.assertEqual(code, 1)
        self.assertIn("capture", text.lower())
        self.assertNotIn("enforcing", text)

    def test_unreadable_processes_are_refused(self):
        code, text = harden.run(supported=lambda: True, privileged=lambda: True,
                                live=lambda: [_issue(PROCESSES_NOT_READABLE_ID)],
                                folders=lambda: [], apply=lambda p: None)
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())

    def test_an_unexamined_table_is_refused(self):
        from stayawake.bots.security.hygiene import process
        from stayawake.utils.procsnap import Snapshot
        apply = mock.Mock()
        with mock.patch.object(process, "_snapshot", return_value=Snapshot()):
            code, text = harden.run(
                supported=lambda: True, privileged=lambda: True,
                live=process.check_live_processes,
                folders=lambda: [Path("/denial")], apply=apply)
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())
        apply.assert_not_called()

    def test_unread_arguments_on_an_examined_table_do_not_refuse(self):
        from stayawake.bots.security.hygiene import process
        from stayawake.utils.procsnap import Process, Snapshot
        p = Path("/denial")
        snap = Snapshot(processes=[Process(pid=1, argv_unreadable=True)], unreadable=1)
        with mock.patch.object(process, "_snapshot", return_value=snap):
            code, _ = harden.run(
                supported=lambda: True, privileged=lambda: True,
                live=process.check_live_processes,
                folders=lambda: [p],
                apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)

    def test_a_run_that_denied_nothing_does_not_claim_it_did(self):
        p = Path("/usr/local/lib/node")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.OCCUPIED,
                                                  "already had something in it, so it was not changed"))
        self.assertEqual(code, 3)
        self.assertNotIn("is denied", text)
        self.assertIn("NOT in place", text)
        self.assertIn("do not rotate", text.lower())
        self.assertIn("inspect", text.lower())

    def test_one_denied_among_untouched_does_not_claim_the_host(self):
        a, b = Path("/a"), Path("/b")
        def apply(path):
            if path == a:
                return denial.PathOutcome(path, denial.ENFORCING, "in place")
            return denial.PathOutcome(path, denial.OCCUPIED,
                                      "already had something in it, so it was not changed")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply)
        self.assertEqual(code, 3)
        self.assertNotIn("is denied", text)
        self.assertIn("NOT in place", text)

    def test_enforcing_only_when_every_target_reads_back(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)
        self.assertIn("enforcing", text)
        self.assertIn("built-in transport is unaffected", text)
        self.assertNotIn("prevent", text.lower())

    def test_a_write_that_is_not_read_back_is_unknown_never_success(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.UNKNOWN, "could not be verified"))
        self.assertEqual(code, 3)
        self.assertIn("unknown", text)
        self.assertNotIn("enforcing", text.split("\n")[0])

    def test_occupied_is_not_success_and_names_that_it_was_not_changed(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.OCCUPIED,
                                                  "already had something in it, so it was not changed"))
        self.assertEqual(code, 3)
        self.assertIn("not changed", text)

    def test_one_occupied_among_enforcing_is_not_success(self):
        a, b = Path("/a"), Path("/b")
        def apply(path):
            if path == a:
                return denial.PathOutcome(path, denial.ENFORCING, "in place")
            return denial.PathOutcome(path, denial.OCCUPIED,
                                      "already had something in it, so it was not changed")
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply)
        self.assertEqual(code, 3)

    def test_no_targets_is_not_success(self):
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: [], apply=lambda p: None)
        self.assertEqual(code, 3)

    def test_every_target_is_applied(self):
        seen = []
        paths = [Path("/a"), Path("/b"), Path("/c")]
        def apply(path):
            seen.append(path)
            return denial.PathOutcome(path, denial.ENFORCING, "in place")
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: True, live=lambda: [],
            folders=lambda: paths, apply=apply)
        self.assertEqual(code, 0)
        self.assertEqual(seen, paths)

    def test_the_targets_are_the_same_list_the_audit_uses(self):
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        self.assertIs(harden.run.__kwdefaults__["folders"], _global_folders)

    def test_other_live_findings_do_not_refuse(self):
        p = Path("/denial")
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: True,
            live=lambda: [_issue("some-other-hygiene")],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)

    def test_capture_refuses_before_any_write(self):
        apply = mock.Mock()
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: True,
            live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_not_root_does_not_write(self):
        apply = mock.Mock()
        harden.run(supported=lambda: True, privileged=lambda: False, live=lambda: [],
                   folders=lambda: [Path("/denial")], apply=apply)
        apply.assert_not_called()


class TestApplyOne(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_occupied_path_is_left_alone(self):
        target = self.d / "taken"
        target.mkdir()
        (target / "payload").write_text("x")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue((target / "payload").exists())

    def test_file_at_the_path_is_not_removed(self):
        target = self.d / "file"
        target.write_text("x")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue(target.is_file())

    def test_symlink_at_the_path_is_not_followed(self):
        target = self.d / "link"
        target.symlink_to(self.d / "elsewhere")
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue(target.is_symlink())

    def test_unverified_flag_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=True):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_already_holding_is_enforcing_without_rewriting(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=True), \
             mock.patch.object(hostdenial, "set_immutable") as setter:
            out = denial.apply_one(target)
        setter.assert_not_called()
        self.assertEqual(out.state, denial.ENFORCING)

    def test_a_flag_that_did_not_take_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", side_effect=[False, True]), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_a_write_error_is_unknown(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod",
                        side_effect=OSError):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_writes_do_not_follow_a_symlink(self):
        victim = self.d / "victim"
        victim.write_text("x")
        os.chmod(victim, 0o644)
        target = self.d / "staging"
        target.symlink_to(victim)
        dir_st = mock.Mock()
        dir_st.st_mode = __import__("stat").S_IFDIR | 0o755
        real_lstat = Path.lstat
        def lstat(self_path):
            if getattr(lstat, "once", True):
                lstat.once = False
                return dir_st
            return real_lstat(self_path)
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(Path, "lstat", lstat), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True):
            denial.apply_one(target)
        self.assertEqual(victim.stat().st_mode & 0o777, 0o644)

    def test_does_not_freeze_a_directory_that_gained_children(self):
        target = self.d / "empty"
        target.mkdir()
        (target / "payload").write_text("x")
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", side_effect=[True, False]), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod"), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable") as setter:
            out = denial.apply_one(target)
        setter.assert_not_called()
        self.assertEqual(out.state, denial.OCCUPIED)
        self.assertTrue((target / "payload").exists())

    def test_a_linked_parent_is_not_created_through(self):
        victim = self.d / "victim"
        victim.mkdir()
        (victim / "KEEPME").write_text("x")
        parent = self.d / "parent"
        parent.symlink_to(victim)
        target = parent / "denial"
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertFalse((victim / "denial").exists())
        self.assertEqual({p.name for p in victim.iterdir()}, {"KEEPME"})

    def test_a_linked_ancestor_is_not_created_through(self):
        victim = self.d / "victim"
        victim.mkdir()
        prefix = self.d / "prefix"
        prefix.symlink_to(victim)
        target = prefix / "lib" / "node"
        with mock.patch.object(hostdenial, "holds", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertEqual(list(victim.iterdir()), [])

    def test_a_root_owned_system_link_is_still_created_under(self):
        victim = self.d / "real"
        victim.mkdir()
        parent = self.d / "link"
        parent.symlink_to(victim)
        target = parent / "denial"
        link_st = parent.lstat()
        root_owned = mock.Mock()
        root_owned.st_mode = link_st.st_mode
        root_owned.st_uid = 0
        real_lstat = Path.lstat
        def lstat(self_path):
            if self_path == parent:
                return root_owned
            return real_lstat(self_path)
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(Path, "lstat", lstat), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue((victim / "denial").is_dir())

    def test_a_missing_path_under_real_parents_is_created(self):
        target = self.d / "lib" / "node_modules"
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue(target.is_dir())
        self.assertFalse(target.is_symlink())

    def test_mode_writes_pass_follow_symlinks_false(self):
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(hostdenial, "empty_dir", return_value=True), \
             mock.patch("stayawake.bots.security.harden.denial.os.chmod") as chmod, \
             mock.patch("stayawake.bots.security.harden.denial.os.chown") as chown, \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            denial.apply_one(target)
        self.assertTrue(chmod.called)
        self.assertFalse(chmod.call_args.kwargs.get("follow_symlinks", True))
        self.assertTrue(chown.called)
        self.assertFalse(chown.call_args.kwargs.get("follow_symlinks", True))


class TestAuditDoesNotTreatADenialAsADrop(unittest.TestCase):
    def test_a_holding_path_is_not_a_weak_indicator(self):
        from stayawake.bots.security.hygiene import host_artifacts
        fake = Path(tempfile.mkdtemp(prefix="holding-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(fake, ignore_errors=True))
        with mock.patch.object(host_artifacts, "_global_folders", return_value=[fake]), \
             mock.patch.object(hostdenial, "holds", return_value=True), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            strong, weak, unread, _controlled = host_artifacts._host_artifacts()
        self.assertEqual(strong, [])
        self.assertEqual(weak, [])
        self.assertEqual(unread, [])

    def test_a_tree_that_does_not_hold_is_still_reported(self):
        from stayawake.bots.security.hygiene import host_artifacts
        fake = Path(tempfile.mkdtemp(prefix="drop-"))
        (fake / "pkg").mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(fake, ignore_errors=True))
        with mock.patch.object(host_artifacts, "_global_folders", return_value=[fake]), \
             mock.patch.object(hostdenial, "holds", return_value=False), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            strong, weak, unread, _controlled = host_artifacts._host_artifacts()
        self.assertTrue(any(str(fake) in item[0] for item in weak), weak)
        self.assertEqual(strong, [])
        self.assertEqual(unread, [])


class TestAControlDoesNotMakeTheHostReadSafer(unittest.TestCase):
    """Applying the control removes the location it covers from the audit's evidence. A host whose
    remaining location still carries a tree must not come out of the rotation gate because of it."""

    def _grade(self, locations, holding):
        from stayawake.bots.security.hygiene import host_artifacts
        with mock.patch.object(host_artifacts, "_global_folders", return_value=locations), \
             mock.patch.object(hostdenial, "holds", lambda p: p in holding), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            return host_artifacts.check_host_artifacts()

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="control-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.covered = self.d / "covered"
        self.covered.mkdir()
        self.left = self.d / "left"
        (self.left / "pkg").mkdir(parents=True)

    def test_rotation_stays_unsafe_when_a_location_was_left_as_it_stood(self):
        from stayawake.bots.security.hygiene.models import ROTATION_UNSAFE_IDS, rotation_safety
        before = {i.id for i in self._grade([self.covered, self.left], holding=set())}
        self.assertTrue(before & ROTATION_UNSAFE_IDS, before)
        after = self._grade([self.covered, self.left], holding={self.covered})
        ids = {i.id for i in after}
        self.assertTrue(ids & ROTATION_UNSAFE_IDS, ids)
        self.assertNotEqual(rotation_safety(ids), "safe")
        self.assertEqual([i.severity for i in after], ["warning"])
        self.assertIn(str(self.left), after[0].detail)
        self.assertIn("do not rotate", after[0].remediation.lower())

    def test_a_fully_controlled_host_reports_nothing(self):
        self.assertEqual(self._grade([self.covered], holding={self.covered}), [])


if __name__ == "__main__":
    unittest.main()

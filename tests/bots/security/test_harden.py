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
from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import HygieneIssue, PROCESSES_NOT_READABLE_ID
from stayawake.utils import hostdenial, operator


def _issue(id_):
    return HygieneIssue(id=id_, severity="unknown", title=id_, detail=id_, remediation="x")


class TestRunContract(unittest.TestCase):
    def test_not_implemented_is_not_success(self):
        code, text = harden.run(supported=lambda: False, privileged=lambda: True, live=lambda: [])
        self.assertEqual(code, 2)
        self.assertIn("not implemented", text.lower())

    def test_without_root_it_still_takes_what_it_can(self):
        """Root is asked of the PATH, not of the command. Refusing the whole run because one
        location needs privilege withheld a control from everyone unwilling to give a security
        tool root — and the locations that need it are named rather than skipped in silence."""
        mine, theirs = Path("/mine"), Path("/theirs")
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: False, live=lambda: [],
            folders=lambda: [mine, theirs],
            apply=lambda p: denial.PathOutcome(p, denial.SELF_ENFORCING, "in place")
            if p == mine else denial.PathOutcome(p, denial.NEEDS_ROOT, "not yours to write to"))
        self.assertIn("enforcing-as-you: /mine", text)
        self.assertIn("needs-root: /theirs", text)
        self.assertIn("sudo", text)
        self.assertNotEqual(code, 0, "a location it could not take is not a complete result")

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

    def test_without_root_it_does_write(self):
        """The inverse of what this used to pin: the run no longer stops before trying."""
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/denial"),
                                                          denial.SELF_ENFORCING, "in place"))
        harden.run(supported=lambda: True, privileged=lambda: False, live=lambda: [],
                   folders=lambda: [Path("/denial")], apply=apply)
        apply.assert_called_once()

    def test_capture_still_comes_before_any_write_without_root(self):
        """The one gate privilege never relaxed: a live loader is the only copy of the second
        stage, and a denied write kills the process that holds it."""
        apply = mock.Mock()
        code, _ = harden.run(
            supported=lambda: True, privileged=lambda: False,
            live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_a_self_held_result_is_never_reported_as_root_held(self):
        code, text = harden.run(
            supported=lambda: True, privileged=lambda: False, live=lambda: [],
            folders=lambda: [Path("/mine")],
            apply=lambda p: denial.PathOutcome(p, denial.SELF_ENFORCING, "in place"))
        self.assertIn("enforcing-as-you", text)
        self.assertIn("code running as you can take the lock off first", text)
        self.assertNotIn("only root can remove it", text)
        self.assertEqual(code, 0, "it took every location it was given")


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
        with mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
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
        """With privilege, because taking ownership is the step that reaches `chown` — the write
        of the owner is exactly the one a planted link would redirect."""
        target = self.d / "empty"
        target.mkdir()
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(hostdenial, "privileged", return_value=True), \
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
             mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
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
             mock.patch.object(hostdenial, "held_by",
                               lambda p: hostdenial.ROOT_HELD if p in holding else None), \
             mock.patch.object(host_artifacts, "_host_user_tag", return_value=None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner", lambda *_a, **_k: None), \
             mock.patch.object(host_artifacts, "_distinct_dirs", lambda paths: []):
            return host_artifacts.check_host_artifacts()

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="control-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        # Both carry a real tree. An empty directory is not evidence of one, so a fixture built
        # from empty directories tests nothing about what covering a location does.
        self.covered = self.d / "covered"
        (self.covered / "pkg").mkdir(parents=True)
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


class TestTheTwoGradesAreNeverConflated(unittest.TestCase):
    """A lock the operator holds is a weaker control than one root holds — MEASURED, its owner
    clears the flag with one call and no privilege. Reporting them alike would hand someone an
    assurance that code running as them can undo."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-grade-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _locked(self, name: str) -> Path:
        target = self.d / name
        target.mkdir()
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        self.assertTrue(hostdenial.set_immutable(target), "the fixture must really be locked")
        return target

    def test_a_lock_this_account_owns_reads_back_as_self_held(self):
        self.assertEqual(hostdenial.held_by(self._locked("mine")), hostdenial.SELF_HELD)

    def test_the_strict_reading_still_answers_only_for_root(self):
        """`holds` is what the host-artifact probe asks. A location the operator can reopen is
        not one it may call controlled."""
        self.assertFalse(hostdenial.holds(self._locked("mine")))

    def test_an_unlocked_directory_is_held_by_nobody(self):
        target = self.d / "open"
        target.mkdir()
        self.assertIsNone(hostdenial.held_by(target))

    def test_a_directory_with_something_in_it_is_held_by_nobody(self):
        target = self.d / "full"
        target.mkdir()
        (target / "payload.js").write_text("x")
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        hostdenial.set_immutable(target)
        self.assertIsNone(hostdenial.held_by(target))

    def test_applying_without_privilege_reports_the_weaker_grade(self):
        target = self.d / "fresh"
        with mock.patch.object(hostdenial, "privileged", return_value=False):
            out = denial.apply_one(target)
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        self.assertEqual(out.state, denial.SELF_ENFORCING)
        self.assertIn("running as you can remove it", out.detail)


class TestWhereItCannotWriteWithoutRoot(unittest.TestCase):
    def test_a_location_this_account_cannot_write_to_is_named_not_guessed(self):
        with mock.patch.object(hostdenial, "privileged", return_value=False), \
             mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(hostdenial, "can_write_into", return_value=False):
            out = denial.apply_one(Path("/somewhere/not/mine"))
        self.assertEqual(out.state, denial.NEEDS_ROOT)
        self.assertIn("sudo", out.detail)

    def test_a_writable_location_is_not_reported_as_needing_root(self):
        self.assertTrue(hostdenial.can_write_into(Path.home() / ".node_modules_probe"))


class TestOnlyPrefixesThisMachineHas(unittest.TestCase):
    """Under privilege the creation walks up making missing ancestors, so naming a prefix the host
    does not have would have a control create the prefix of a package manager nobody installed —
    and there is nothing to deny there, because the runtime never resolves through it."""

    def test_a_prefix_that_is_not_here_is_dropped(self):
        self.assertFalse(host_artifacts._prefix_on_this_machine(Path("/opt/no-such-prefix")))

    def test_a_prefix_that_is_here_is_kept(self):
        self.assertTrue(host_artifacts._prefix_on_this_machine(Path("/usr")))

    def test_a_prefix_that_cannot_be_read_is_kept_so_it_can_be_reported(self):
        """`is_dir()` answers False for absent and unreadable alike. Dropping the second would
        take the location out of the list before anything could record that it could not be read."""
        with mock.patch("stayawake.bots.security.hygiene.host_artifacts.os.stat",
                        side_effect=PermissionError):
            self.assertTrue(host_artifacts._prefix_on_this_machine(Path("/anything")))

    def test_a_platform_default_the_host_lacks_is_not_targeted(self):
        """Through the target list, not the helper: a test that calls the helper directly still
        passes when the call site is removed.

        A GUESSED default only — this used to assert the same of a prefix the operator DECLARED,
        which silently removed a resolution path from the run while it still reported success.
        """
        absent = [r for r in ("/opt/homebrew", "/opt/local") if not Path(r).exists()]
        if not absent:
            self.skipTest("this host has every platform default installed")
        targets = [str(p) for p in host_artifacts._global_folders()]
        for root in absent:
            self.assertNotIn(f"{root}/lib/node", targets)

    def test_a_prefix_the_environment_names_and_the_host_has_is_targeted(self):
        """The positive control, so the test above cannot pass because nothing is targeted."""
        with mock.patch.dict(os.environ, {"PREFIX": "/usr"}):
            targets = [str(p) for p in host_artifacts._global_folders()]
        self.assertIn("/usr/lib/node", targets)

    def test_the_home_entries_are_named_whether_or_not_they_exist(self):
        """Absent is the state a payload creates them from, so they are targeted regardless."""
        names = {p.name for p in host_artifacts._global_folders()}
        self.assertIn(".node_modules", names)
        self.assertIn(".node_libraries", names)


class TestItDoesNotAccuseItsOwnWork(unittest.TestCase):
    """`saw audit` reported the directories `saw harden` had just created as a corroborated
    supply-chain staging warning, on a real machine. The claim was "a node module tree" while the
    test was only "does this path exist" — so an EMPTY directory was called a tree."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-probe-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _findings_for(self, target: Path):
        with mock.patch.object(host_artifacts, "_global_folders", lambda: [target]):
            return [i.id for i in host_artifacts.check_host_artifacts()]

    def test_a_denial_this_tool_placed_is_not_a_finding(self):
        target = self.d / "denied"
        target.mkdir()
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        self.assertTrue(hostdenial.set_immutable(target))
        self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)
        self.assertEqual(self._findings_for(target), [])

    def test_an_empty_location_nothing_holds_is_still_a_finding(self):
        """The signal is that the location EXISTS, not what is in it — nothing ordinary creates
        one. Suppressing an empty directory to stop the self-accusation lost that, and the hygiene
        suite caught it: the discriminator has to be the control, not the contents."""
        target = self.d / "empty"
        target.mkdir()
        self.assertTrue(self._findings_for(target))

    def test_a_denial_the_operator_holds_still_counts_as_a_control(self):
        """Not only "do not accuse it" — CREDIT it. A finding elsewhere must read as being outside
        a control that covers a sibling, which is a different grade from a lone indicator. The
        strict root-only reading left an operator-held denial out of that account entirely."""
        denied, staged = self.d / "denied", self.d / "staged"
        denied.mkdir()
        (staged / "pkg").mkdir(parents=True)
        self.addCleanup(lambda: hostdenial.clear_immutable(denied))
        self.assertTrue(hostdenial.set_immutable(denied))

        with mock.patch.object(host_artifacts, "_global_folders", lambda: [denied, staged]):
            ids = [i.id for i in host_artifacts.check_host_artifacts()]

        self.assertIn("host-drop-artifact-outside-a-control", ids)

    def test_a_directory_with_modules_in_it_is_still_a_finding(self):
        """The positive control: narrowing the claim must not lose what it was for."""
        target = self.d / "staged"
        (target / "evil").mkdir(parents=True)
        self.assertTrue(self._findings_for(target), "a real tree must still be reported")


class TestTheUpgradePathIsReachable(unittest.TestCase):
    """The report tells the operator to re-run with sudo to raise an operator-held lock. That path
    was unreachable: the grade compared the owner against the EFFECTIVE uid, which is root under
    sudo, so an operator-owned lock graded as nobody's."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-upgrade-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_the_operator_is_who_invoked_not_who_is_running(self):
        mine = os.getuid()
        self.assertEqual(operator.acting_uid({"HOME": "/var/root", "SUDO_UID": str(mine)}), mine)

    def test_a_lock_the_operator_holds_is_seen_as_theirs_under_sudo(self):
        target = self.d / "held"
        target.mkdir()
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        hostdenial.set_immutable(target)
        with mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}):
            self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)

    def test_running_with_privilege_raises_it_instead_of_failing(self):
        target = self.d / "raise-me"
        target.mkdir()
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        hostdenial.set_immutable(target)
        reached = []
        with mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
             mock.patch.object(denial, "_take_ownership",
                               side_effect=lambda p: reached.append(p) or
                               denial.PathOutcome(p, denial.ENFORCING, "raised")):
            out = denial.apply_one(target)
        self.assertTrue(reached, "the only path that raises a lock must be reachable")
        self.assertEqual(out.state, denial.ENFORCING)

    def test_an_upgrade_that_did_not_take_is_unknown_never_enforcing(self):
        target = self.d / "pretend"
        target.mkdir()
        self.addCleanup(lambda: hostdenial.clear_immutable(target))
        hostdenial.set_immutable(target)
        with mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
             mock.patch.object(denial.os, "chown", lambda *a, **k: None):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)


class TestAPrefixIsAbsoluteAndNormalised(unittest.TestCase):
    def test_a_relative_prefix_is_refused(self):
        """`PREFIX=.` had a host-level control create an immutable `lib/node` inside whatever
        repository it was run from — against this module's own stated invariant."""
        for raw in (".", "..", "build", "lib/node"):
            with self.subTest(raw=raw):
                self.assertIsNone(host_artifacts._usable_prefix(raw))

    def test_a_prefix_carrying_dot_dot_is_refused(self):
        """The kernel resolves `..` while walking, so the per-component symlink check never sees
        the link it exists to refuse."""
        self.assertIsNone(host_artifacts._usable_prefix("/usr/local/../../etc"))

    def test_an_absolute_normalised_prefix_is_accepted(self):
        self.assertEqual(host_artifacts._usable_prefix("/usr/local"), Path("/usr/local"))

    def test_nothing_at_all_is_refused(self):
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                self.assertIsNone(host_artifacts._usable_prefix(raw))


class TestADeclaredPrefixIsNotDropped(unittest.TestCase):
    def test_a_prefix_the_operator_declared_is_targeted_even_when_absent(self):
        """Filtering it out removed it from the list entirely — so no line was printed, no note
        fired, and the run still exited claiming the staging path was denied."""
        with mock.patch.dict(os.environ, {"PREFIX": "/opt/declared-but-absent"}):
            targets = [str(p) for p in host_artifacts._global_folders()]
        self.assertIn("/opt/declared-but-absent/lib/node", targets)

    def test_a_platform_default_the_host_lacks_is_still_dropped(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            targets = [str(p) for p in host_artifacts._global_folders()]
        self.assertNotIn("/opt/no-such-prefix/lib/node", targets)


class TestALiveInstallIsLeftRemovable(unittest.TestCase):
    """`<prefix>/lib/node` is a real resolution path and also a directory inside the install. A
    version manager removes a version with `rm -rf <prefix>`, which an immutable child defeats."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-nvm-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_prefix_holding_a_node_binary_is_not_locked(self):
        prefix = self.d / "versions" / "node" / "v22.11.0"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")

        out = denial.apply_one(prefix / "lib" / "node")

        self.assertEqual(out.state, denial.IN_A_LIVE_INSTALL)
        self.assertFalse((prefix / "lib" / "node").exists(), "nothing was created")

    def test_the_version_can_still_be_removed_afterwards(self):
        prefix = self.d / "v1"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")
        denial.apply_one(prefix / "lib" / "node")

        __import__("shutil").rmtree(prefix)

        self.assertFalse(prefix.exists())

    def test_a_prefix_with_no_node_in_it_is_still_taken(self):
        prefix = self.d / "bare"
        (prefix / "lib").mkdir(parents=True)
        target = prefix / "lib" / "node"
        self.addCleanup(lambda: hostdenial.clear_immutable(target))

        self.assertEqual(denial.apply_one(target).state, denial.SELF_ENFORCING)


if __name__ == "__main__":
    unittest.main()

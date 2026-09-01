#!/usr/bin/env python3
"""Host-level denials: enforcing only after read-back; never remove what is already there."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
import contextlib
import pwd
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import denial
from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import HygieneIssue, PROCESSES_NOT_READABLE_ID
from stayawake.utils import hostdenial, operator


@contextlib.contextmanager
def locked(*paths: Path):
    """Make `paths` read back as immutable, without needing the OS to allow it.

    `chattr +i` needs a capability an ordinary CI account does not have, and the filesystems those
    runners use often cannot carry the flag at all — so a fixture that sets it for real tests the
    grading logic on one platform and nothing on the other. The flag is the OS's business and is
    covered separately, where it can actually be set.
    """
    held = {Path(p).resolve() for p in paths}
    with mock.patch.object(hostdenial, "immutable", lambda p: Path(p).resolve() in held), \
         mock.patch.object(hostdenial, "set_immutable",
                           lambda p: bool(held.add(Path(p).resolve()) or True)), \
         mock.patch.object(hostdenial, "clear_immutable",
                           lambda p: bool(held.discard(Path(p).resolve()) or True)):
        yield held


def _issue(id_):
    return HygieneIssue(id=id_, severity="unknown", title=id_, detail=id_, remediation="x")


class TestRunContract(unittest.TestCase):
    def test_not_implemented_is_not_success(self):
        code, text = harden.run(supported=lambda: False, live=lambda: [])
        self.assertEqual(code, 2)
        self.assertIn("not implemented", text.lower())

    def test_without_root_it_still_takes_what_it_can(self):
        """Root is asked of the PATH, not of the command. Refusing the whole run because one
        location needs privilege withheld a control from everyone unwilling to give a security
        tool root — and the locations that need it are named rather than skipped in silence."""
        mine, theirs = Path("/mine"), Path("/theirs")
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
            folders=lambda: [mine, theirs],
            apply=lambda p: denial.PathOutcome(p, denial.SELF_ENFORCING, "in place")
            if p == mine else denial.PathOutcome(p, denial.NEEDS_ROOT, "not yours to write to"))
        self.assertIn("enforcing-as-you: /mine", text)
        self.assertIn("needs-root: /theirs", text)
        self.assertIn("sudo", text)
        self.assertNotEqual(code, 0, "a location it could not take is not a complete result")

    def test_live_loader_is_refused(self):
        code, text = harden.run(supported=lambda: True, folders=lambda: [], apply=lambda p: None,
                                live=lambda: [_issue("live-obfuscated-process")])
        self.assertEqual(code, 1)
        self.assertIn("capture", text.lower())
        self.assertNotIn("enforcing", text)

    def test_unreadable_processes_are_refused(self):
        code, text = harden.run(supported=lambda: True, folders=lambda: [], apply=lambda p: None,
                                live=lambda: [_issue(PROCESSES_NOT_READABLE_ID)])
        self.assertEqual(code, 1)
        self.assertIn("could not be examined", text.lower())

    def test_an_unexamined_table_is_refused(self):
        from stayawake.bots.security.hygiene import process
        from stayawake.utils.procsnap import Snapshot
        apply = mock.Mock()
        with mock.patch.object(process, "_snapshot", return_value=Snapshot()):
            code, text = harden.run(
                supported=lambda: True, live=process.check_live_processes,
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
                supported=lambda: True, live=process.check_live_processes,
                folders=lambda: [p],
                apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)

    def test_a_run_that_denied_nothing_does_not_claim_it_did(self):
        p = Path("/usr/local/lib/node")
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
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
            supported=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply)
        self.assertEqual(code, 3)
        self.assertNotIn("is denied", text)
        self.assertIn("NOT in place", text)

    def test_enforcing_only_when_every_target_reads_back(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)
        self.assertIn("enforcing", text)
        self.assertIn("built-in transport is unaffected", text)
        self.assertNotIn("prevent", text.lower())

    def test_a_write_that_is_not_read_back_is_unknown_never_success(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.UNKNOWN, "could not be verified"))
        self.assertEqual(code, 3)
        self.assertIn("unknown", text)
        self.assertNotIn("enforcing", text.split("\n")[0])

    def test_occupied_is_not_success_and_names_that_it_was_not_changed(self):
        p = Path("/denial")
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
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
            supported=lambda: True, live=lambda: [],
            folders=lambda: [a, b], apply=apply)
        self.assertEqual(code, 3)

    def test_no_targets_is_not_success(self):
        code, _ = harden.run(
            supported=lambda: True, live=lambda: [],
            folders=lambda: [], apply=lambda p: None)
        self.assertEqual(code, 3)

    def test_every_target_is_applied(self):
        seen = []
        paths = [Path("/a"), Path("/b"), Path("/c")]
        def apply(path):
            seen.append(path)
            return denial.PathOutcome(path, denial.ENFORCING, "in place")
        code, _ = harden.run(
            supported=lambda: True, live=lambda: [],
            folders=lambda: paths, apply=apply)
        self.assertEqual(code, 0)
        self.assertEqual(seen, paths)

    def test_the_targets_are_the_same_list_the_audit_uses(self):
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        self.assertIs(harden.run.__kwdefaults__["folders"], _global_folders)

    def test_other_live_findings_do_not_refuse(self):
        p = Path("/denial")
        code, _ = harden.run(
            supported=lambda: True, live=lambda: [_issue("some-other-hygiene")],
            folders=lambda: [p],
            apply=lambda path: denial.PathOutcome(path, denial.ENFORCING, "in place"))
        self.assertEqual(code, 0)

    def test_capture_refuses_before_any_write(self):
        apply = mock.Mock()
        code, _ = harden.run(
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_without_root_it_does_write(self):
        """The inverse of what this used to pin: the run no longer stops before trying."""
        apply = mock.Mock(return_value=denial.PathOutcome(Path("/denial"),
                                                          denial.SELF_ENFORCING, "in place"))
        harden.run(supported=lambda: True, live=lambda: [],
                   folders=lambda: [Path("/denial")], apply=apply)
        apply.assert_called_once()

    def test_capture_still_comes_before_any_write_without_root(self):
        """The one gate privilege never relaxed: a live loader is the only copy of the second
        stage, and a denied write kills the process that holds it."""
        apply = mock.Mock()
        code, _ = harden.run(
            supported=lambda: True, live=lambda: [_issue("live-obfuscated-process")],
            folders=lambda: [Path("/denial")], apply=apply)
        self.assertEqual(code, 1)
        apply.assert_not_called()

    def test_a_self_held_result_is_never_reported_as_root_held(self):
        code, text = harden.run(
            supported=lambda: True, live=lambda: [],
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
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
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
        with mock.patch.object(hostdenial, "held_by", return_value=None):
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
        with mock.patch.object(hostdenial, "held_by", return_value=None):
            out = denial.apply_one(target)
        # Nothing is created above the leaf now, so this stops before the link is walked at all —
        # the victim staying empty is the property, and it holds for a stronger reason.
        self.assertEqual(out.state, denial.NOT_HERE_YET)
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
        with mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(Path, "lstat", lstat), \
             mock.patch("stayawake.bots.security.harden.denial.os.chown"), \
             mock.patch.object(hostdenial, "set_immutable", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)
        self.assertTrue((victim / "denial").is_dir())

    def test_a_missing_leaf_under_a_real_directory_is_created(self):
        (self.d / "lib").mkdir()
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

    def _dir(self, name: str) -> Path:
        target = self.d / name
        target.mkdir()
        return target

    def test_a_lock_this_account_owns_reads_back_as_self_held(self):
        target = self._dir("mine")
        with locked(target):
            self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)

    def test_the_strict_reading_still_answers_only_for_root(self):
        """`holds` is what the host-artifact probe asks. A location the operator can reopen is
        not one it may call controlled."""
        target = self._dir("mine")
        with locked(target):
            self.assertFalse(hostdenial.holds(target))

    def test_an_unlocked_directory_is_held_by_nobody(self):
        target = self.d / "open"
        target.mkdir()
        self.assertIsNone(hostdenial.held_by(target))

    def test_a_directory_with_something_in_it_is_held_by_nobody(self):
        target = self.d / "full"
        target.mkdir()
        (target / "payload.js").write_text("x")
        with locked(target):
            self.assertIsNone(hostdenial.held_by(target))

    def test_applying_without_privilege_reports_the_weaker_grade(self):
        target = self.d / "fresh"
        with locked(), mock.patch.object(hostdenial, "privileged", return_value=False):
            out = denial.apply_one(target)
        self.assertEqual(out.state, denial.SELF_ENFORCING)
        self.assertIn("running as you can remove it", out.detail)


class TestWhereItCannotWriteWithoutRoot(unittest.TestCase):
    def test_a_location_this_account_cannot_write_to_is_named_not_guessed(self):
        """A directory that IS here but is not ours — the `/usr/lib` case. A directory that is not
        here at all is a different answer, and gets one."""
        here = Path(tempfile.mkdtemp(prefix="harden-noperm-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(here, ignore_errors=True))
        with mock.patch.object(hostdenial, "privileged", return_value=False), \
             mock.patch.object(hostdenial, "held_by", return_value=None), \
             mock.patch.object(denial, "_create_where_it_was_named", return_value=False), \
             mock.patch.object(hostdenial, "can_write_into", return_value=False):
            out = denial.apply_one(here / "node")
        self.assertEqual(out.state, denial.NEEDS_ROOT)
        self.assertIn("sudo", out.detail)

    def test_a_writable_location_is_not_reported_as_needing_root(self):
        self.assertTrue(hostdenial.can_write_into(Path.home() / ".node_modules_probe"))


class TestItCreatesTheLeafNotTheTree(unittest.TestCase):
    """A control creates the location it was aimed at, never the directories above it. Building
    the tree meant a location named for a package manager the host does not have got that
    manager's prefix built for it."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-leaf-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_location_whose_directory_is_absent_is_not_created(self):
        out = denial.apply_one(self.d / "no-such-prefix" / "lib" / "node")
        self.assertEqual(out.state, denial.NOT_HERE_YET)
        self.assertFalse((self.d / "no-such-prefix").exists(), "and no tree was built for it")

    def test_a_location_whose_directory_is_here_is_taken(self):
        (self.d / "lib").mkdir()
        with locked():
            self.assertEqual(denial.apply_one(self.d / "lib" / "node").state,
                             denial.SELF_ENFORCING)

    def test_the_probe_is_still_told_about_every_location(self):
        """The list answers where the runtime resolves; what may be created is the control's
        decision. Filtering absent locations out of the list starved the probe of the platform's
        own entries, which it enumerates for coverage."""
        with mock.patch.dict(os.environ, {"PREFIX": "/opt/declared-but-absent"}):
            targets = [str(p) for p in host_artifacts._global_folders()]
        self.assertIn("/opt/declared-but-absent/lib/node", targets)


class TestALiveInstallIsLeftRemovable(unittest.TestCase):
    """`<prefix>/lib/node` is a real resolution path and also a directory inside the install. A
    version manager removes a version with `rm -rf <prefix>`, which an immutable child defeats."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-nvm-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_a_prefix_holding_a_node_binary_is_not_locked(self):
        prefix = self.d / "versions" / "node" / "v22.11.0"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "lib").mkdir()
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")

        out = denial.apply_one(prefix / "lib" / "node")

        self.assertEqual(out.state, denial.IN_A_LIVE_INSTALL)
        self.assertFalse((prefix / "lib" / "node").exists(), "nothing was created")

    def test_the_version_can_still_be_removed_afterwards(self):
        prefix = self.d / "v1"
        (prefix / "bin").mkdir(parents=True)
        (prefix / "lib").mkdir()
        (prefix / "bin" / "node").write_text("#!/bin/sh\n")
        denial.apply_one(prefix / "lib" / "node")

        __import__("shutil").rmtree(prefix)

        self.assertFalse(prefix.exists())

    def test_a_prefix_with_no_node_in_it_is_still_taken(self):
        prefix = self.d / "bare"
        (prefix / "lib").mkdir(parents=True)
        with locked():
            self.assertEqual(denial.apply_one(prefix / "lib" / "node").state,
                             denial.SELF_ENFORCING)


class TestTheReadBackDoesNotTrustPath(unittest.TestCase):
    """What decides whether a control is reported as in place must not come from `PATH`. This
    command now runs unprivileged by design, so `PATH` belongs to whoever ran it — and a program
    earlier in it that prints a flags field containing `i` would make an unlocked directory read
    back as locked."""

    def test_the_tools_are_looked_for_at_absolute_paths_only(self):
        for name, candidates in hostdenial._ATTR_TOOL_ABSOLUTE_PATHS.items():
            with self.subTest(tool=name):
                self.assertTrue(candidates, f"{name} must have somewhere to be found")
                for candidate in candidates:
                    self.assertTrue(candidate.startswith("/"),
                                    f"{candidate} would be resolved through PATH")

    def test_a_tool_that_is_not_there_is_never_looked_for_on_path(self):
        """Asserting only the return value cannot see this: on a host without the tool, a bare
        name fails too, so both answer False and the mutation hides. What has to hold is that
        nothing is executed at all — that is what keeps `PATH` out of the decision."""
        # A directory that EXISTS: the write paths check the path first, so a made-up one bails
        # before it would ever look for a tool, and the assertion passes without testing anything.
        target = Path(tempfile.mkdtemp(prefix="harden-notool-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(target, ignore_errors=True))
        with mock.patch.object(hostdenial, "_attr_tool", return_value=None), \
             mock.patch.object(hostdenial.sys, "platform", "linux"), \
             mock.patch.object(hostdenial.subprocess, "run") as ran:
            self.assertFalse(hostdenial.immutable(target))
            self.assertFalse(hostdenial.set_immutable(target))
            self.assertFalse(hostdenial.clear_immutable(target))
        ran.assert_not_called()

    def test_the_source_names_no_bare_tool(self):
        """A regression here would be one word, and it would be invisible in a diff review."""
        source = Path(hostdenial.__file__).read_text(encoding="utf-8")
        for bare in ('["lsattr"', '["chattr"', "'lsattr'", "'chattr'"):
            self.assertNotIn(bare, source)


class TestNothingIsSealedInDuringTheUpgrade(unittest.TestCase):
    """The owner cannot be changed while the flag is set, so raising a control briefly opens the
    location. Anything that arrives in that gap must not be locked in — that would put content at
    the exact location this exists to keep empty, out of the operator's reach."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-window-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _upgrade_raced(self, target: Path):
        """Run the privileged upgrade with something writing into the window it opens.

        The window opens where the flag comes off, so that is where the write goes. `chown` is a
        no-op rather than the hook: the real one is what the tool has to survive, and a mock that
        also moves modes around would satisfy the assertions below by itself.
        """
        held = {target.resolve()}

        def unlocks_and_loses_the_race(p):
            held.discard(Path(p).resolve())
            os.chmod(p, 0o755)
            (Path(p) / "payload.js").write_text("x")
            os.chmod(p, 0o555)
            return True

        with mock.patch.object(hostdenial, "immutable",
                               lambda p: Path(p).resolve() in held), \
             mock.patch.object(hostdenial, "clear_immutable", unlocks_and_loses_the_race), \
             mock.patch.object(hostdenial, "set_immutable",
                               lambda p: bool(held.add(Path(p).resolve()) or True)), \
             mock.patch.object(os, "geteuid", lambda: 0), \
             mock.patch.dict(os.environ, {"SUDO_UID": str(os.getuid())}), \
             mock.patch.object(denial.os, "chown", lambda *a, **k: None):
            return denial.apply_one(target), held

    def _control(self, name: str = "held") -> Path:
        target = self.d / name
        target.mkdir()
        os.chmod(target, 0o555)
        return target

    def test_content_arriving_in_the_gap_is_not_locked_in(self):
        target = self._control()
        out, held = self._upgrade_raced(target)
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertNotIn(target.resolve(), held, "it must not end up locked around that content")

    def test_the_gap_is_never_reported_as_a_location_that_was_not_changed(self):
        """This asserted OCCUPIED — "already had something in it, so it was not changed" — while
        the lock had just been taken off and the owner set to root. Two false statements about a
        location a payload had just written to, on the run that was meant to strengthen it."""
        out, _ = self._upgrade_raced(self._control())
        self.assertNotEqual(out.state, denial.OCCUPIED)
        self.assertNotIn("not changed", out.detail)
        self.assertIn("arrived while the lock was off", out.detail)

    def test_the_location_is_handed_back_so_the_operator_can_clear_it(self):
        """`0o555` denies the write to the owner too, so leaving it meant the file that arrived
        could not be deleted from a directory the operator owns."""
        target = self._control()
        self._upgrade_raced(target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertTrue(os.access(target, os.W_OK | os.X_OK),
                        "the operator must be able to remove what arrived")

    def test_the_run_says_so_and_does_not_pass(self):
        out, _ = self._upgrade_raced(self._control())
        code, text = harden.run(supported=lambda: True, live=lambda: [],
                                folders=lambda: [out.path], apply=lambda p: out)
        self.assertEqual(code, 3)
        self.assertIn("left-open-over-content", text)
        self.assertIn("left reachable", text)

    def test_every_note_that_applies_is_printed(self):
        """A chain of `elif`s dropped whichever note came second, and a location left open over
        content and one that needs root can both be in the same run."""
        left_open = denial.PathOutcome(Path("/open"), denial.LEFT_OPEN_OVER_CONTENT, "x")
        needs_root = denial.PathOutcome(Path("/theirs"), denial.NEEDS_ROOT, "y")
        _, text = harden.run(supported=lambda: True, live=lambda: [],
                             folders=lambda: [Path("/open"), Path("/theirs")],
                             apply=lambda p: left_open if p == Path("/open") else needs_root)
        self.assertIn("left reachable", text)
        self.assertIn("Run again with sudo to take those as well", text)


class TestTakingAControlBack(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-back-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _dir(self, name: str) -> Path:
        target = self.d / name
        target.mkdir()
        return target

    def test_a_control_this_tool_placed_is_removed(self):
        target = self._dir("denied")
        with locked(target):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.REMOVED)
        self.assertFalse(target.exists())

    def test_a_locked_directory_holding_content_is_never_opened(self):
        """The danger in this verb is the obvious implementation: one that unlocks whatever it is
        pointed at is a way to open a location on request, wearing a helpful name."""
        target = self._dir("theirs")
        (target / "keep.txt").write_text("x")
        with locked(target) as held:
            out = denial.remove_one(target)
            self.assertIn(target.resolve(), held, "it is never even unlocked")
        self.assertEqual(out.state, denial.LOCKED_OVER_CONTENT)
        self.assertTrue((target / "keep.txt").exists())

    def test_a_location_locked_over_content_is_not_a_settled_run(self):
        """It used to read as "nothing of ours here" and count toward success, so a run reported
        the machine as back to normal while an immutable directory holding someone else's content
        sat at a resolution path and the operator's own removal of it failed."""
        target = self._dir("hostile")
        (target / "evil.js").write_text("x")
        with locked(target):
            code, text = harden.take_back(supported=lambda: True, folders=lambda: [target])
        self.assertNotEqual(code, 0)
        self.assertIn("locked-over-content", text)

    def test_content_arriving_while_the_lock_is_off_is_left_reachable(self):
        """This pinned the opposite and was wrong. Locking it back seals the content in — the
        exact thing the sibling that RAISES a control refuses for the same window. Content put
        beyond the operator's reach at this location is worse than a location left open."""
        target = self._dir("racy")
        with locked(target) as held:
            def arrives(p):
                held.discard(Path(p).resolve())
                (Path(p) / "late.txt").write_text("x")
                return True
            with mock.patch.object(hostdenial, "clear_immutable", arrives):
                out = denial.remove_one(target)
            self.assertNotIn(target.resolve(), held, "it must NOT be locked around that content")
        self.assertEqual(out.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertTrue((target / "late.txt").exists())

    def test_a_location_left_open_over_content_is_not_a_settled_run(self):
        """Left open is not taken back. It reads like a location with nothing of ours in it, and
        counting it that way says the machine is back to normal over a file nobody has read."""
        target = self._dir("racy")
        with locked(target) as held:
            def arrives(p):
                held.discard(Path(p).resolve())
                (Path(p) / "late.txt").write_text("x")
                return True
            with mock.patch.object(hostdenial, "clear_immutable", arrives):
                code, text = harden.take_back(supported=lambda: True, folders=lambda: [target])
        self.assertNotEqual(code, 0)
        self.assertIn("left-open-over-content", text)
        self.assertIn("left reachable", text)

    def test_a_link_on_the_way_redirects_nothing(self):
        """Creating through a planted link puts a control somewhere unintended. Removing through
        one unlocks and deletes somewhere unintended, and this side had no check at all."""
        elsewhere = self.d / "elsewhere"
        (elsewhere / "node").mkdir(parents=True)
        prefix = self.d / "prefix"
        prefix.mkdir()
        (prefix / "lib").symlink_to(elsewhere)

        with locked(prefix / "lib" / "node"):
            out = denial.remove_one(prefix / "lib" / "node")

        self.assertEqual(out.state, denial.NOT_WHERE_IT_WAS_NAMED)
        self.assertTrue((elsewhere / "node").exists(), "the real directory is untouched")

    def test_a_location_holding_nothing_of_ours_is_not_touched(self):
        target = self.d / "plain"
        target.mkdir()
        out = denial.remove_one(target)
        self.assertEqual(out.state, denial.NOTHING_TO_REMOVE)
        self.assertTrue(target.exists())

    def test_one_root_holds_needs_privilege_to_take_back(self):
        target = self.d / "roots"
        target.mkdir()
        with mock.patch.object(hostdenial, "held_by", return_value=hostdenial.ROOT_HELD), \
             mock.patch.object(hostdenial, "privileged", return_value=False):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.NEEDS_ROOT)
        self.assertTrue(target.exists())

    def test_a_removal_that_did_not_happen_is_never_reported_as_done(self):
        target = self._dir("stubborn")
        with locked(target), mock.patch.object(denial.os, "rmdir", lambda p: None):
            out = denial.remove_one(target)
        self.assertEqual(out.state, denial.UNKNOWN)

    def test_taking_back_does_not_wait_for_capture(self):
        """Applying a control waits for a live process to be captured, because a denied write
        kills it. This opens a location rather than closing one."""
        removed = []
        code, text = harden.take_back(
            supported=lambda: True, folders=lambda: [Path("/x")],
            remove=lambda p: removed.append(p) or denial.PathOutcome(p, denial.REMOVED, "gone"))
        self.assertEqual(code, 0)
        self.assertTrue(removed)


class TestEveryWayPrivilegeIsRaised(unittest.TestCase):
    """Recognising only `sudo` fixed the grading for one tool and left the same defect under the
    next: the effective uid is root under all of them."""

    def _as_root(self, env):
        with mock.patch.object(os, "geteuid", lambda: 0):
            return operator.resolve(env)

    def test_each_escalation_resolves_to_the_invoker(self):
        me = pwd.getpwuid(os.getuid())
        for var, value in (("SUDO_UID", str(me.pw_uid)), ("SUDO_USER", me.pw_name),
                           ("DOAS_USER", me.pw_name), ("PKEXEC_UID", str(me.pw_uid))):
            with self.subTest(var=var):
                who = self._as_root({"HOME": "/var/root", var: value})
                self.assertIsNotNone(who, f"{var} names the invoker")
                self.assertEqual(who.uid, me.pw_uid)

    def test_root_with_no_marker_is_refused_not_guessed(self):
        """Answering this from `HOME` is what produced the defect in the first place."""
        self.assertIsNone(self._as_root({"HOME": "/var/root"}))

    def test_an_account_that_does_not_resolve_is_refused(self):
        self.assertIsNone(self._as_root({"HOME": "/var/root", "SUDO_USER": "no-such-account"}))

    def test_without_escalation_the_environment_answers(self):
        with mock.patch.object(os, "geteuid", lambda: os.getuid()):
            who = operator.resolve({"HOME": "/Users/x", "USER": "x"})
        self.assertEqual(who.home, Path("/Users/x"))


class TestAPlantedEscalationMarkerDecidesNothing(unittest.TestCase):
    """An escalation marker is an ordinary environment variable any unprivileged process can
    export. Reading its presence as proof that privilege was raised let one line in a shell rc —
    the surface this worm family writes to — pick the account every location is graded against."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="harden-operator-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self.me = pwd.getpwuid(os.getuid())

    def test_a_marker_on_a_process_that_is_not_root_names_nobody(self):
        with mock.patch.dict(os.environ, {"SUDO_UID": "0"}):
            self.assertEqual(operator.acting_uid(), os.geteuid())
            self.assertNotEqual(operator.resolve().uid, 0)

    def test_a_control_that_is_in_place_stays_visible(self):
        """It read as absent, and `saw harden` could never put it back: the location is immutable,
        so the write it falls through to fails for the rest of the host's life."""
        target = self.d / "denied"
        target.mkdir()
        with locked(target):
            self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)
            with mock.patch.dict(os.environ, {"SUDO_UID": "0"}):
                self.assertEqual(hostdenial.held_by(target), hostdenial.SELF_HELD)

    def test_running_as_another_account_grades_against_that_account(self):
        """`sudo -u <account>` sets the same markers and leaves the effective uid that account's.
        No attacker needed: it graded against the invoker rather than who it was running as."""
        with mock.patch.dict(os.environ, {"SUDO_UID": "1", "SUDO_USER": "daemon"}):
            self.assertEqual(operator.acting_uid(), os.geteuid())

    def test_markers_that_disagree_are_refused(self):
        """`sudo` and `doas` write the uid and the name from one decision. Two that name different
        accounts is evidence the environment was not built by one, and the first digit-valued
        variable used to win without the rest ever being read."""
        with mock.patch.object(os, "geteuid", lambda: 0):
            self.assertIsNone(operator.resolve({"HOME": "/var/root", "SUDO_UID": "0",
                                                "SUDO_USER": self.me.pw_name}))

    def test_markers_that_agree_still_name_the_invoker(self):
        with mock.patch.object(os, "geteuid", lambda: 0):
            who = operator.resolve({"HOME": "/var/root", "SUDO_UID": str(self.me.pw_uid),
                                    "SUDO_USER": self.me.pw_name})
        self.assertEqual(who.uid, self.me.pw_uid)


if __name__ == "__main__":
    unittest.main()

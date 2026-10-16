#!/usr/bin/env python3
"""Where only an administrator can lock a folder, as on Linux, `saw harden` run without sudo leaves no empty folder
behind and says to run it again with sudo; a folder that was there before, or that anything was put in, is never
removed, and a control that locked stays in place."""
from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import approvals as agentapprovals, denial, settings as editorsettings
from stayawake.utils import hostdenial
from tests.bots.security.test_harden import _hooks_already_there


class _Location(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.target = self.home / ".node_libraries"

    def _place(self, *, lock=lambda path: False, privileged=False, on_linux=True):
        with mock.patch.object(hostdenial, "set_immutable", side_effect=lock), \
                mock.patch.object(hostdenial, "privileged", return_value=privileged), \
                mock.patch.object(hostdenial, "lock_needs_privilege", return_value=on_linux, create=True), \
                mock.patch.object(denial.os, "chown"):
            return denial.apply_one(self.target)


class TestAFolderItMadeAndCouldNotLockIsNotLeft(_Location):
    def test_it_leaves_nothing_and_says_an_administrator_can_place_it(self):
        outcome = self._place()
        self.assertEqual(outcome.state, denial.NEEDS_ROOT)
        self.assertFalse(os.path.lexists(self.target))

    def test_run_as_root_where_the_lock_fails_it_leaves_nothing_either(self):
        outcome = self._place(privileged=True)
        self.assertEqual(outcome.state, denial.UNKNOWN)
        self.assertFalse(os.path.lexists(self.target))

    def test_a_folder_it_made_and_could_not_close_is_not_left(self):
        real_chmod = os.chmod

        def refuse_to_close(path, mode, **kw):
            if mode == 0o555:
                raise PermissionError("refused")
            return real_chmod(path, mode, **kw)
        with mock.patch.object(denial.os, "chmod", side_effect=refuse_to_close):
            outcome = self._place()
        self.assertEqual(outcome.state, denial.UNKNOWN)
        self.assertFalse(os.path.lexists(self.target))

    def test_harden_says_to_run_it_with_sudo_and_not_that_something_is_there(self):
        with mock.patch.object(hostdenial, "set_immutable", return_value=False), \
                mock.patch.object(hostdenial, "privileged", return_value=False), \
                mock.patch.object(hostdenial, "lock_needs_privilege", return_value=True, create=True):
            _code, text = harden.run(editor_pass=editorsettings.Correcting, agent_pass=agentapprovals.Correcting,
                                     altered=lambda: [], saw_runs=lambda: True, supported=lambda: True,
                                     live=lambda: [], folders=lambda: [self.target], apply=denial.apply_one,
                                     settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)
        self.assertIn("harden` to place the rest.", text)
        self.assertNotIn("something else is already there", text)
        self.assertFalse(os.path.lexists(self.target))


class TestWhatItDidNotMakeOrWhatHoldsAnythingIsNeverRemoved(_Location):
    def test_a_folder_that_was_there_before_is_kept(self):
        self.target.mkdir()
        outcome = self._place()
        self.assertEqual(outcome.state, denial.UNKNOWN)
        self.assertTrue(self.target.is_dir())

    def test_a_folder_something_was_put_in_while_it_was_open_is_kept_with_what_is_in_it(self):
        def arrive_then_refuse(path):
            os.chmod(path, 0o755)
            (path / "payload.js").write_text("x", encoding="utf-8")
            os.chmod(path, 0o555)
            return False
        outcome = self._place(lock=arrive_then_refuse)
        self.assertEqual(outcome.state, denial.LEFT_OPEN_OVER_CONTENT)
        self.assertTrue((self.target / "payload.js").is_file())

    def test_a_folder_that_holds_something_by_the_time_it_would_be_removed_is_kept(self):
        def arrive_then_refuse(path):
            os.chmod(path, 0o755)
            (path / "payload.js").write_text("x", encoding="utf-8")
            os.chmod(path, 0o555)
            return False
        with mock.patch.object(hostdenial, "empty_dir", return_value=True):
            self._place(lock=arrive_then_refuse)
        self.assertTrue((self.target / "payload.js").is_file())

    def test_a_folder_put_in_its_place_is_kept(self):
        def swap_then_refuse(path):
            os.rmdir(path)
            os.mkdir(path)
            return False
        self._place(lock=swap_then_refuse)
        self.assertTrue(self.target.is_dir())

    def test_a_link_put_in_its_place_is_kept_with_what_it_leads_to(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "KEEPME").write_text("x", encoding="utf-8")

        def link_then_refuse(path):
            os.rmdir(path)
            os.symlink(elsewhere, path)
            return False
        self._place(lock=link_then_refuse)
        self.assertTrue(os.path.islink(self.target))
        self.assertEqual({p.name for p in elsewhere.iterdir()}, {"KEEPME"})

    def test_the_folder_it_sits_in_and_what_sits_beside_it_are_kept(self):
        (self.home / "beside").write_text("x", encoding="utf-8")
        self._place()
        self.assertTrue(self.home.is_dir())
        self.assertEqual({p.name for p in self.home.iterdir()}, {"beside"})

    def test_a_folder_that_was_there_before_is_kept_whatever_the_platform(self):
        for on_linux in (True, False):
            with self.subTest(on_linux=on_linux):
                self.target.mkdir(exist_ok=True)
                self._place(on_linux=on_linux)
                self.assertTrue(self.target.is_dir())


class TestWhatHardenSaysWhenAFolderIsLeft(_Location):
    """Where the folder is still there after a refused lock, harden says what it said before: something else is
    there, and `saw audit` shows what."""

    def _said(self, lock=lambda path: False, rmdir=None):
        patches = [mock.patch.object(hostdenial, "set_immutable", side_effect=lock),
                   mock.patch.object(hostdenial, "privileged", return_value=False),
                   mock.patch.object(hostdenial, "lock_needs_privilege", return_value=True, create=True)]
        if rmdir is not None:
            patches.append(mock.patch.object(denial.os, "rmdir", side_effect=rmdir))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return harden.run(editor_pass=editorsettings.Correcting, agent_pass=agentapprovals.Correcting,
                              altered=lambda: [], saw_runs=lambda: True, supported=lambda: True, live=lambda: [],
                              folders=lambda: [self.target], apply=denial.apply_one,
                              settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)[1]

    def assertSaysSomethingElseIsThere(self, text):
        self.assertIn("could not be placed because something else is already there. Run `saw audit` to see what.", text)
        self.assertNotIn("harden` to place the rest.", text)
        self.assertTrue(self.target.is_dir())

    def test_a_folder_that_was_there_before(self):
        self.target.mkdir()
        self.assertSaysSomethingElseIsThere(self._said())

    def test_a_folder_put_in_place_of_the_one_it_made(self):
        def swap_then_refuse(path):
            os.rmdir(path)
            os.mkdir(path)
            return False
        self.assertSaysSomethingElseIsThere(self._said(lock=swap_then_refuse))

    def test_a_folder_it_made_that_could_not_be_removed(self):
        def refuse(path):
            raise PermissionError("refused")
        self.assertSaysSomethingElseIsThere(self._said(rmdir=refuse))

    def test_no_outcome_says_nothing_was_left_while_a_folder_is_there(self):
        self.target.mkdir()
        outcome = self._place()
        self.assertNotIn("nothing was left", outcome.detail)


class TestAControlThatLockedStaysInPlace(_Location):
    def test_a_lock_the_owner_can_set_stays(self):
        with mock.patch.object(hostdenial, "immutable", return_value=True):
            outcome = self._place(lock=lambda path: True, on_linux=False)
        self.assertEqual(outcome.state, denial.SELF_ENFORCING)
        self.assertTrue(self.target.is_dir())

    def test_a_lock_set_as_an_administrator_on_linux_stays(self):
        with mock.patch.object(hostdenial, "immutable", return_value=True):
            outcome = self._place(lock=lambda path: True, privileged=True, on_linux=True)
        self.assertIn(outcome.state, (denial.ENFORCING, denial.SELF_ENFORCING))
        self.assertTrue(self.target.is_dir())


if __name__ == "__main__":
    unittest.main()

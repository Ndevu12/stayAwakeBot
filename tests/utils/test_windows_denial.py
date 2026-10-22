#!/usr/bin/env python3
"""A Windows denial is graded from the account that holds it, and asked of the system's own program."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import hostdenial, winlock


class TestWhoHoldsIt(unittest.TestCase):
    def test_an_administrator_is_not_the_acting_account(self):
        acting = "S-1-5-21-1"
        self.assertEqual(winlock.grade(winlock.ADMINISTRATORS, acting), "root")
        self.assertEqual(winlock.grade(winlock.SYSTEM, acting), "root")
        self.assertEqual(winlock.grade(acting, acting), "self")
        self.assertEqual(winlock.grade("S-1-5-21-2", acting), "other")
        self.assertEqual(winlock.grade(None, acting), "other")

    def test_a_denial_is_graded_from_that_account(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(hostdenial.sys, "platform", "win32"), \
                 mock.patch.object(hostdenial, "immutable", return_value=True), \
                 mock.patch.object(hostdenial, "empty_dir", return_value=True), \
                 mock.patch.object(hostdenial.winlock, "owner_sid", return_value=winlock.ADMINISTRATORS), \
                 mock.patch.object(hostdenial.winlock, "current_sid", return_value="S-1-5-21-1"):
                self.assertEqual(hostdenial.held_by(Path(folder)), hostdenial.ROOT_HELD)


class TestTheDenialIsAskedOfTheSystemProgram(unittest.TestCase):
    def test_the_account_is_denied_adding_anything(self):
        seen = []

        def run(argv, **_kwargs):
            seen.append(argv)
            return mock.Mock(returncode=0)

        binary = r"C:\Windows\System32\icacls.exe"
        with mock.patch.object(winlock, "write_denied", return_value=True):
            self.assertTrue(winlock.deny_writes(Path("folder"), "S-1-5-21-1", run=run, binary=binary))
        self.assertEqual(seen[0][0], binary)
        self.assertIn("/deny", seen[0])
        self.assertIn("*S-1-5-21-1:(OI)(CI)(WD,AD,DC,DE)", seen[0])


if __name__ == "__main__":
    unittest.main()

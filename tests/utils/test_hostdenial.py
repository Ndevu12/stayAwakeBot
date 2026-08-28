#!/usr/bin/env python3
"""A denial holds only when read-back shows a root-owned immutable empty directory."""
from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import hostdenial


class TestHolds(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="hostdenial-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _as_root_dir(self):
        st = mock.Mock()
        st.st_mode = stat.S_IFDIR | 0o555
        st.st_uid = 0
        return mock.patch.object(Path, "lstat", return_value=st)

    def test_empty_root_owned_immutable_holds(self):
        target = self.d / "empty"
        target.mkdir()
        with self._as_root_dir(), \
             mock.patch.object(hostdenial, "immutable", return_value=True):
            self.assertTrue(hostdenial.holds(target))

    def test_children_mean_it_does_not_hold(self):
        target = self.d / "tree"
        target.mkdir()
        (target / "payload").write_text("x")
        with self._as_root_dir(), \
             mock.patch.object(hostdenial, "immutable", return_value=True):
            self.assertFalse(hostdenial.holds(target))

    def test_not_root_owned_does_not_hold(self):
        target = self.d / "empty"
        target.mkdir()
        st = mock.Mock()
        st.st_mode = stat.S_IFDIR | 0o555
        st.st_uid = 501
        with mock.patch.object(Path, "lstat", return_value=st), \
             mock.patch.object(hostdenial, "immutable", return_value=True):
            self.assertFalse(hostdenial.holds(target))

    def test_mutable_does_not_hold(self):
        target = self.d / "empty"
        target.mkdir()
        with self._as_root_dir(), \
             mock.patch.object(hostdenial, "immutable", return_value=False):
            self.assertFalse(hostdenial.holds(target))

    def test_a_file_does_not_hold(self):
        target = self.d / "file"
        target.write_text("x")
        self.assertFalse(hostdenial.holds(target))

    def test_a_symlink_does_not_hold(self):
        target = self.d / "link"
        target.symlink_to(self.d / "elsewhere")
        self.assertFalse(hostdenial.holds(target))


if __name__ == "__main__":
    unittest.main()

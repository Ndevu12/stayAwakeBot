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


class TestImmutableReadBack(unittest.TestCase):
    def test_a_path_token_is_not_an_attribute_set(self):
        with mock.patch.object(hostdenial, "sys") as sysmod:
            sysmod.platform = "linux"
            r = mock.Mock(returncode=0, stdout=".node_libraries --------------\n")
            with mock.patch.object(hostdenial.subprocess, "run", return_value=r):
                self.assertFalse(hostdenial.immutable(Path("/x")))

    def test_a_flags_token_with_i_is_immutable(self):
        with mock.patch.object(hostdenial, "sys") as sysmod:
            sysmod.platform = "linux"
            r = mock.Mock(returncode=0, stdout="----i--------- /x\n")
            with mock.patch.object(hostdenial.subprocess, "run", return_value=r):
                self.assertTrue(hostdenial.immutable(Path("/x")))

    def test_set_immutable_refuses_a_symlink(self):
        d = Path(tempfile.mkdtemp(prefix="hostdenial-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        target = d / "link"
        target.symlink_to(d / "elsewhere")
        self.assertFalse(hostdenial.set_immutable(target))


if __name__ == "__main__":
    unittest.main()

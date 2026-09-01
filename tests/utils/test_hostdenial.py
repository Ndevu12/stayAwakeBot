#!/usr/bin/env python3
"""A denial holds only when read-back shows a root-owned immutable empty directory."""
from __future__ import annotations

import stat
import tempfile
import contextlib
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
    """What `lsattr` prints, parsed. The Linux platform is simulated, so the tool has to be too:
    looking it up on the running host made both of these depend on whether the machine happens to
    have `lsattr`. The one below asserting False then passed on every host that does not — for the
    reason that there was no tool, never once reaching the parse it names."""

    @contextlib.contextmanager
    def _lsattr_printing(self, line: str):
        with mock.patch.object(hostdenial, "sys") as sysmod:
            sysmod.platform = "linux"
            r = mock.Mock(returncode=0, stdout=line)
            with mock.patch.object(hostdenial, "_attr_tool", lambda name: "/usr/bin/lsattr"), \
                 mock.patch.object(hostdenial.subprocess, "run", return_value=r):
                yield

    def test_a_path_token_is_not_an_attribute_set(self):
        with self._lsattr_printing(".node_libraries --------------\n"):
            self.assertFalse(hostdenial.immutable(Path("/x")))

    def test_a_flags_token_with_i_is_immutable(self):
        with self._lsattr_printing("----i--------- /x\n"):
            self.assertTrue(hostdenial.immutable(Path("/x")))

    def test_a_flags_field_without_i_is_not_immutable(self):
        """The ordinary case, and nothing pinned it: a mutation making every flags field read as
        immutable survived, which is every unlocked directory on the host reported as denied."""
        with self._lsattr_printing("-------------e--- /x\n"):
            self.assertFalse(hostdenial.immutable(Path("/x")))

    def test_a_tool_that_is_not_there_is_never_read_as_unlocked(self):
        """Absent is a different answer from "not locked", and it must not reach a success state."""
        with mock.patch.object(hostdenial, "sys") as sysmod:
            sysmod.platform = "linux"
            with mock.patch.object(hostdenial, "_attr_tool", lambda name: None), \
                 mock.patch.object(hostdenial.subprocess, "run") as ran:
                self.assertFalse(hostdenial.immutable(Path("/x")))
                self.assertFalse(hostdenial.set_immutable(Path("/x")))
            ran.assert_not_called()

    def test_set_immutable_refuses_a_symlink(self):
        d = Path(tempfile.mkdtemp(prefix="hostdenial-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        target = d / "link"
        target.symlink_to(d / "elsewhere")
        self.assertFalse(hostdenial.set_immutable(target))


if __name__ == "__main__":
    unittest.main()

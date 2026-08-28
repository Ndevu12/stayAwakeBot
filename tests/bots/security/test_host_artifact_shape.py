#!/usr/bin/env python3
"""An indicator must test the SHAPE its description claims.

`~/.node_modules` is reported as "an npm tree in your home dir", but the probe tested existence — and
`Path.exists()` is true for a regular file. A file there is not a tree, and it is precisely what
supply-chain prevention guidance tells an operator to create in order to deny the staging path. So
hardening a host manufactured the indicator, and the host was then told it might be compromised.
"""
from __future__ import annotations

import os
import pathlib
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import (incident_tier, rotation_safety,
                                                    ROTATION_UNSAFE_PERSISTENCE,
                                                    ROTATION_UNSAFE_UNKNOWN)


class TestTheIndicatorTestsTheShapeItDescribes(unittest.TestCase):
    def _issues(self, build):
        home = pathlib.Path(tempfile.mkdtemp(prefix="ha-home-"))
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="ha-tmp-"))
        for d in (home, tmp):
            self.addCleanup(lambda p=d: __import__("shutil").rmtree(p, ignore_errors=True))
        build(home, tmp)
        with mock.patch.object(host_artifacts, "Path") as patched:
            patched.home.return_value = home
            patched.side_effect = pathlib.Path
            with mock.patch.object(host_artifacts.tempfile, "gettempdir", return_value=str(tmp)):
                return host_artifacts.check_host_artifacts()

    def test_the_hardened_shape_is_not_reported_as_a_tree(self):
        # A file is not a tree. Putting a file at the path must not produce a corroborated
        # finding, nor withhold the rotation all-clear.
        issues = self._issues(lambda home, tmp: (
            (home / ".node_modules").write_text(""),
            (tmp / "get-pip.py").write_text("#")))
        ids = {i.id for i in issues}
        self.assertNotIn("host-drop-artifacts", ids, "a file was corroborated as an npm tree")
        self.assertIsNone(incident_tier(ids))
        # The claim is that hardening does not WITHHOLD the all-clear. A lone weak indicator makes
        # it conditional ("safe once you confirm"), which is not withheld — the unsafe states are.
        self.assertNotIn(rotation_safety(ids),
                         (ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN))

    def test_a_real_tree_is_still_reported(self):
        issues = self._issues(lambda home, tmp: (
            (home / ".node_modules").mkdir(),
            (tmp / "get-pip.py").write_text("#")))
        self.assertIn("host-drop-artifacts", {i.id for i in issues})
        self.assertIn("warning", {i.severity for i in issues})

    def test_a_file_indicator_is_still_accepted_where_a_file_is_the_shape(self):
        # Not a blanket change: `get-pip.py` is legitimately a file and must still count.
        issues = self._issues(lambda home, tmp: (tmp / "get-pip.py").write_text("#"))
        self.assertTrue(issues, "the pip bootstrap indicator was dropped")


class TestBothHomeRelativeGlobalFoldersAreCovered(TestTheIndicatorTestsTheShapeItDescribes):
    """Node resolves global modules through GLOBAL_FOLDERS: `~/.node_modules`, then
    `~/.node_libraries`, then `$PREFIX/lib/node`. Probing only the first drew the line one entry
    above where an attacker reading the same documentation would step over it."""

    def test_the_second_entry_is_reported_like_the_first(self):
        for entry in (".node_modules", ".node_libraries"):
            with self.subTest(entry=entry):
                issues = self._issues(lambda home, tmp, e=entry: (
                    (home / e).mkdir(),
                    (tmp / "get-pip.py").write_text("#")))
                self.assertIn("host-drop-artifacts", {i.id for i in issues})

    def test_the_shape_rule_applies_to_it_too(self):
        # A FILE at either is not a tree — the same rule, not a special case.
        issues = self._issues(lambda home, tmp: (
            (home / ".node_libraries").write_text(""),
            (tmp / "get-pip.py").write_text("#")))
        self.assertNotIn("host-drop-artifacts", {i.id for i in issues})

    def test_the_prefix_entry_is_covered_too(self):
        # Not excluded as "system-only": `/usr/local` is user-owned on a Homebrew Mac, so this entry
        # is reachable by a worm that never gets root. An uncovered load path is a gap to close.
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        with mock.patch.dict(os.environ, {"PREFIX": "/opt/node"}):
            resolved = {str(p) for p in _global_folders()}
        self.assertIn("/opt/node/lib/node", resolved, "$PREFIX from the environment is honoured")
        self.assertIn("/usr/local/lib/node", resolved, "the default prefix is checked as well")

    def test_it_resolves_on_every_platform_not_just_posix(self):
        # A POSIX-only prefix list would leave the equivalent Windows locations uncovered — the same
        # partial coverage this probe exists to remove, one platform over.
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        windows_env = {"APPDATA": r"C:\Users\u\AppData\Roaming", "ProgramFiles": r"C:\Program Files"}
        with mock.patch("sys.platform", "win32"), mock.patch.dict(os.environ, windows_env):
            resolved = {str(path) for path in _global_folders()}
        self.assertTrue(any("AppData" in path for path in resolved), resolved)
        self.assertFalse(any(path.startswith("/usr/") for path in resolved),
                         "POSIX prefixes must not be offered on Windows")

        with mock.patch("sys.platform", "linux"), mock.patch.dict(os.environ, {}, clear=False):
            for var in ("PREFIX", "NODE_PREFIX", "npm_config_prefix"):
                os.environ.pop(var, None)
            posix = {str(path) for path in _global_folders()}
        self.assertIn("/usr/local/lib/node", posix)

    def test_every_documented_resolution_path_is_probed(self):
        from stayawake.bots.security.hygiene.host_artifacts import _global_folders
        resolved = {str(p) for p in _global_folders()}
        home = str(pathlib.Path.home())
        for entry in (f"{home}/.node_modules", f"{home}/.node_libraries"):
            self.assertIn(entry, resolved)
        self.assertTrue(any(p.endswith("/lib/node") for p in resolved))


class TestTheBenignExplanationNamesACauseThatCanProduceThePath(unittest.TestCase):
    def test_it_no_longer_blames_a_command_that_makes_a_different_path(self):
        # `npm install` in $HOME creates `~/node_modules` — no dot — so telling the user that was the
        # cause pointed them at a path this probe never looks at, and broke their route to self-clear.
        issues = TestTheIndicatorTestsTheShapeItDescribes._issues(
            self, lambda home, tmp: (tmp / "get-pip.py").write_text("#"))
        detail = " ".join(i.detail for i in issues)
        self.assertNotIn("manual `npm install`", detail)
        self.assertIn("GLOBAL_FOLDERS", detail)


if __name__ == "__main__":
    unittest.main()

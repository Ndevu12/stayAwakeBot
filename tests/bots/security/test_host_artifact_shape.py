#!/usr/bin/env python3
"""An indicator must test the SHAPE its description claims.

`~/.node_modules` is reported as "an npm tree in your home dir", but the probe tested existence — and
`Path.exists()` is true for a regular file. A file there is not a tree, and it is precisely what
supply-chain prevention guidance tells an operator to create in order to deny the staging path. So
hardening a host manufactured the indicator, and the host was then told it might be compromised.
"""
from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts
from stayawake.bots.security.hygiene.models import incident_tier, rotation_safety, ROTATION_SAFE


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
        # The control says: make `~/.node_modules` a NON-DIRECTORY. Following it must not produce a
        # corroborated finding, nor withhold the rotation all-clear.
        issues = self._issues(lambda home, tmp: (
            (home / ".node_modules").write_text(""),
            (tmp / "get-pip.py").write_text("#")))
        ids = {i.id for i in issues}
        self.assertNotIn("host-drop-artifacts", ids, "a file was corroborated as an npm tree")
        self.assertIsNone(incident_tier(ids))
        self.assertEqual(rotation_safety(ids), ROTATION_SAFE)

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

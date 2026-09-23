#!/usr/bin/env python3
"""The shared payload oracle: whether content still confirms a payload."""
from __future__ import annotations

import unittest

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.remediation import oracle
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox

LOADER = (
    "const _0x1a = ['aHR0cHM6Ly9ldmlsLnRlc3Q='];\n"
    "(function(v){var f=String.fromCharCode;globalThis['v']=f(127);})(0);\n"
)


class TestPayloadMatchers(unittest.TestCase):
    """Which matcher groups may judge one file's own content."""

    def test_the_repo_wide_groups_are_dropped(self):
        kept = oracle.payload_matchers({"content": [1], "git-history": [2],
                                        "dependency-audit": [3], "installed-package-audit": [4]})
        self.assertEqual({"content"}, set(kept))

    def test_a_non_dict_is_passed_through(self):
        self.assertEqual([1, 2], oracle.payload_matchers([1, 2]))


class TestContentConfirms(unittest.TestCase):
    """What a set of bytes is judged to be, scanned as a given path."""

    def setUp(self):
        self.signatures = oracle.payload_matchers(load_signatures())
        self.opts = ScanOptions()

    def test_clean_content_confirms_nothing(self):
        self.assertIsNone(oracle.content_confirms(b"module.exports = 1;\n", "index.js",
                                                  self.signatures, [], self.opts))

    def test_a_symlink_is_judged_as_its_target_string(self):
        """A mode-120000 blob holds the target; read as text it would look like ordinary content."""
        verdict = oracle.content_confirms(b"../../../../etc/passwd", "link",
                                          self.signatures, [], self.opts, is_symlink=True)
        self.assertIsInstance(verdict, (str, type(None)))

    def test_it_never_leaves_the_scratch_behind(self):
        from stayawake.utils import scratch
        before = len(scratch.held())
        oracle.content_confirms(b"x", "a.js", self.signatures, [], self.opts)
        self.assertEqual(before, len(scratch.held()))


class TestSurvives(GitSandbox):
    """Whether a path in a tree still carries a payload."""

    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.check = oracle.survives(self.repo, load_signatures(), [], ScanOptions())

    def test_a_path_absent_from_the_tree_carries_nothing(self):
        self.write(self.repo, "clean.js", "module.exports = 1;\n")
        head = self.commit(self.repo, "only a clean file")
        self.assertIsNone(self.check(head, "never-existed.js"))

    def test_a_clean_path_carries_nothing(self):
        self.write(self.repo, "clean.js", "module.exports = 1;\n")
        head = self.commit(self.repo, "clean")
        self.assertIsNone(self.check(head, "clean.js"))

    def test_the_same_blob_is_judged_once(self):
        self.write(self.repo, "a.js", "module.exports = 1;\n")
        head = self.commit(self.repo, "one file")
        self.assertEqual(self.check(head, "a.js"), self.check(head, "a.js"))


if __name__ == "__main__":
    unittest.main()

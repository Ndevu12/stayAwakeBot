#!/usr/bin/env python3
"""What a removal takes, against what `saw fix` documents it takes."""
from __future__ import annotations

import unittest

from stayawake.bots.security.pr.fix import _committed_under
from stayawake.bots.security.remediation import installed
from tests.support.gitrepo import GitSandbox


class _Project(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        for name in ("dist", "build"):
            (self.d / name).mkdir()
            (self.d / name / "artifact.js").write_text("generated\n")

    def _names(self, **kw):
        return sorted(p.name for p in installed.build_output_dirs(self.d, **kw))


class TestADirectoryTheOperatorExcluded(_Project):
    """`exclude_dirs` entries are documented as never removed."""

    def test_an_excluded_tree_is_not_collected(self):
        self.assertNotIn("dist", self._names(exclude={"dist"}))

    def test_the_others_are_still_collected(self):
        self.assertIn("build", self._names(exclude={"dist"}))

    def test_excluding_nothing_collects_both(self):
        self.assertEqual(["build", "dist"], self._names())


class TestADirectoryTheProjectCommits(_Project):
    """What a project commits is documented as not touched."""

    def test_a_committed_tree_is_not_collected(self):
        self.commit(self.d, "commits dist and build deliberately")
        self.assertEqual([], self._names(committed=_committed_under(self.d)))

    def test_a_generated_tree_is_still_collected(self):
        self.git(self.d, "add", "dist")
        self.git(self.d, "commit", "-qm", "commits dist only")
        self.assertEqual(["build"], self._names(committed=_committed_under(self.d)))

    def test_a_tree_git_cannot_answer_for_is_not_collected(self):
        self.assertEqual([], self._names(committed=lambda _p: True))


class TestTheCheckItself(_Project):
    def test_it_sees_a_tracked_tree(self):
        self.commit(self.d, "commits both")
        self.assertTrue(_committed_under(self.d)(self.d / "dist"))

    def test_it_does_not_see_an_untracked_tree(self):
        self.assertFalse(_committed_under(self.d)(self.d / "dist"))

    def test_a_path_outside_the_repository_is_treated_as_committed(self):
        self.assertTrue(_committed_under(self.d)(self.root / "elsewhere"))


if __name__ == "__main__":
    unittest.main()

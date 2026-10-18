#!/usr/bin/env python3
"""`saw fix amend` removes a payload from every branch that brings in the same bytes a delivery on
another branch proves, and puts what came in beside it to the operator."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.pr.outcome import Cause
from stayawake.bots.security.pr.resolve import KEEP, TAKE_OUT, DeliveryAnswer, DeliveryQuestion, Resolution
from tests.bots.security.test_amend import _AmendFixture, _git

_MAINLINE_LOADER = "eval(String.fromCharCode(1, 2, 3));\n"
_SIDE_LOADER = "eval(String.fromCharCode(4, 5, 6));\n"


class TestAmendCleansEveryBranch(_AmendFixture):
    def _forged_merge(self, branch: str, path: str, payload: str, label: str, root: str) -> str:
        _git(self.d, "checkout", "-q", "-b", f"{label}-work", root)
        self.write(self.d, f"{label}.txt", f"{label} work\n")
        self.commit(self.d, f"{label} work")
        _git(self.d, "checkout", "-q", branch)
        _git(self.d, "merge", "--no-ff", "--no-commit", "-q", f"{label}-work")
        self.write(self.d, path, payload)
        _git(self.d, "add", "-A")
        _git(self.d, "-c", "user.name=Injected", "-c", "user.email=inj@t.test",
             "commit", "-qm", f"merge {label} (smuggled loader)")
        return self._rev()

    def _two_branches(self, side_path: str = "z.js") -> str:
        root = self._rev(self.base)
        _git(self.d, "branch", "side", root)
        self.merges = [(self._forged_merge(self.base, "y.js", _MAINLINE_LOADER, "mainline", root), ("y.js",)),
                       (self._forged_merge("side", side_path, _SIDE_LOADER, "sideline", root), (side_path,))]
        self.write(self.d, "y.js", _MAINLINE_LOADER)
        self.write(self.d, "extra.txt", "came in beside it\n")
        self.commit(self.d, "brings in the other line's loader")
        _git(self.d, "checkout", "-q", self.base)
        return self._rev("side")

    def _amend_both(self):
        scan = ScanResult(target=str(self.d), source="local",
                          findings=[self._confirmed_finding(sha, paths) for sha, paths in self.merges])
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return self._act()

    def _holds(self, ref: str, path: str) -> bool:
        return self.git_may_fail(self.d, "rev-parse", f"{ref}:{path}").returncode == 0

    def test_both_branches_lose_the_payload_the_other_line_proves(self):
        side_before = self._two_branches()

        outcome = self._amend_both()

        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertNotEqual(self._rev("side"), side_before)
        for ref in (self.base, "side"):
            with self.subTest(branch=ref):
                self.assertFalse(self._holds(ref, "y.js"))
        self.assertFalse(self._holds("side", "z.js"))

    def test_what_came_in_beside_it_is_kept_and_put_to_the_operator(self):
        self._two_branches()

        outcome = self._amend_both()

        self.assertTrue(self._holds("side", "extra.txt"))
        undecided = [r for r in outcome.reasons if r.cause is Cause.ARRIVALS_UNDECIDED]
        self.assertTrue(undecided, self._causes(outcome))
        self.assertIn("extra.txt", undecided[0].subjects)


    def test_it_is_put_to_the_operator_when_both_branches_carry_that_file(self):
        self._two_branches(side_path="y.js")

        outcome = self._amend_both()

        self.assertTrue(self._holds("side", "extra.txt"))
        undecided = [r for r in outcome.reasons if r.cause is Cause.ARRIVALS_UNDECIDED]
        self.assertTrue(undecided, self._causes(outcome))
        self.assertIn("extra.txt", undecided[0].subjects)
        self.assertTrue(outcome.needs_review)

    def test_an_answer_about_one_branch_leaves_the_other_branchs_own_copy(self):
        self.write(self.d, "y.js", "var a = 0;\nvar b = 0;\nvar c = 0;\n")
        root = self.commit(self.d, "add y.js")
        _git(self.d, "checkout", "-q", "-b", "side", root)
        self.write(self.d, "y.js", "var a = 1;\nvar b = 0;\nvar c = 0;\n")
        side_edit = self.commit(self.d, "side edits y.js")
        _git(self.d, "checkout", "-q", self.base)
        self.write(self.d, "docs/guide.md", "written on main long ago\n")
        self.commit(self.d, "main docs")
        self.write(self.d, "y.js", "var a = 0;\nvar b = 0;\nvar c = 1;\n")
        main_edit = self.commit(self.d, "main edits y.js")
        self.merges = [(self._forged_merge(self.base, "y.js", _MAINLINE_LOADER, "mainline", main_edit), ("y.js",)),
                       (self._forged_merge("side", "z.js", _SIDE_LOADER, "sideline", side_edit), ("z.js",))]
        self.write(self.d, "y.js", _MAINLINE_LOADER)
        self.write(self.d, "docs/guide.md", "written on main long ago\n")
        self.commit(self.d, "copies y.js and the docs from main")
        _git(self.d, "checkout", "-q", self.base)
        _git(self.d, "merge", "--no-ff", "-q", "-m", "merge side", "side")
        _git(self.d, "update-ref", "-d", "ORIG_HEAD")
        asked = []

        def take_out_everything(question):
            if not isinstance(question, DeliveryQuestion):
                return Resolution(KEEP)
            asked.append([f.path for f in question.files])
            return DeliveryAnswer(TAKE_OUT, tuple(f.path for f in question.files))

        scan = ScanResult(target=str(self.d), source="local",
                          findings=[self._confirmed_finding(sha, paths) for sha, paths in self.merges])
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            outcome = self._act(resolver=take_out_everything)

        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertIn(["docs/guide.md"], asked)
        self.assertEqual(self._show(f"{self.base}:docs/guide.md"), "written on main long ago\n")

if __name__ == "__main__":
    unittest.main()

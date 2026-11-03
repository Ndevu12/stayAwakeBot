#!/usr/bin/env python3
"""`saw guard setup -b dev -b main` installs one workflow that scans pushes to both branches, the
same file whichever branch it is written on; one branch is gated as before."""
from __future__ import annotations

import unittest

from stayawake.bots.security import guard

_PIN = guard.Pin("c" * 40, "v0.2.0")


class TestSeveralProtectedBranches(unittest.TestCase):
    def test_pushes_to_every_named_branch_are_scanned(self):
        plan = guard.plan_setup({}, "dev", _PIN, push_branches=("dev", "main"))
        self.assertIn("    branches: [dev, main]\n", plan.content)

    def test_the_file_is_the_same_whichever_branch_comes_first(self):
        a = guard.render_workflow(_PIN, "dev", "0.15.0", push_branches=("dev", "main"))
        b = guard.render_workflow(_PIN, "main", "0.15.0", push_branches=("dev", "main"))
        self.assertEqual(a, b)

    def test_one_branch_is_gated_as_before(self):
        self.assertIn("    branches: [main]\n", guard.render_workflow(_PIN, "main"))

    def test_a_gate_with_several_branches_is_current(self):
        wf = guard.render_workflow(_PIN, "dev", push_branches=("dev", "main"))
        self.assertEqual("noop", guard.plan_setup({guard.SAW_GUARD_FILE: wf}, "main", _PIN).action)

    def test_the_branch_option_can_be_repeated(self):
        from stayawake.cli import build_parser
        args = build_parser().parse_args(["guard", "setup", "-b", "dev", "-b", "main"])
        self.assertEqual(["dev", "main"], args.branch)


if __name__ == "__main__":
    unittest.main()

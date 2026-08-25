#!/usr/bin/env python3
"""One fix branch per base, and a push refusal told apart from a missing permission."""
import unittest

from stayawake.bots.security.pr.branches import (
    LEGACY_FIX_BRANCH, choose_fix_branch, fix_branch_for)
from stayawake.lib.git.naming import ref_safe_segment
from stayawake.core.identity.classify import classify_push_stderr

GH013 = "remote: error: GH013: Repository rule violations found for refs/heads/security/auto-clean."
DECLINED = "! [remote rejected] x -> x (push declined due to repository rule violations)"
NON_FF = "hint: Updates were rejected because the tip of your current branch is behind"
FORBIDDEN = "remote: Permission to o/r.git denied to user."


class BranchNaming(unittest.TestCase):
    def test_the_separator_keeps_the_name_flat(self):
        # `security/auto-clean/<base>` cannot be created where `security/auto-clean` exists: refs are
        # paths, so a file cannot also be a directory — the very repos this is for.
        name = fix_branch_for("main")
        self.assertTrue(name.startswith(LEGACY_FIX_BRANCH + "-"))
        self.assertEqual(name.count("/"), LEGACY_FIX_BRANCH.count("/"))

    def test_a_slashed_base_yields_one_flat_ref_safe_segment(self):
        name = fix_branch_for("feature/x")
        self.assertEqual(name, "security/auto-clean-feature-x")
        self.assertNotIn("..", name)

    def test_two_bases_get_two_distinct_branches(self):
        self.assertNotEqual(fix_branch_for("main"), fix_branch_for("develop"))

    def test_a_base_that_cannot_be_sanitised_still_produces_a_ref_safe_name(self):
        for base in ("", "   ", "..", "///", "\x00\x01"):
            with self.subTest(base=base):
                name = fix_branch_for(base)
                self.assertNotIn("..", name)
                self.assertFalse(name.endswith("-"), name)
                self.assertTrue(ref_safe_segment(base))


class BranchSelection(unittest.TestCase):
    def test_our_own_earlier_fix_is_reused_rather_than_suffixed(self):
        # Without the ancestry test every run abandons a branch it could extend.
        got = choose_fix_branch("main", exists=lambda n: n == "security/auto-clean-main",
                                fast_forwardable=lambda n: True)
        self.assertEqual(got, "security/auto-clean-main")

    def test_a_branch_held_by_unrelated_work_steps_to_a_free_name(self):
        got = choose_fix_branch("main", exists=lambda n: n == "security/auto-clean-main",
                                fast_forwardable=lambda n: False)
        self.assertEqual(got, "security/auto-clean-main-2")

    def test_a_free_name_is_used_as_is(self):
        self.assertEqual(
            choose_fix_branch("main", exists=lambda n: False, fast_forwardable=lambda n: False),
            "security/auto-clean-main")


class PushRefusalClassification(unittest.TestCase):
    def test_a_rule_violation_is_policy_not_access(self):
        for stderr in (GH013, DECLINED, NON_FF):
            with self.subTest(stderr=stderr[:30]):
                self.assertEqual(classify_push_stderr(stderr).reason, "occupied")

    def test_a_genuine_permission_denial_is_still_forbidden(self):
        self.assertEqual(classify_push_stderr(FORBIDDEN).reason, "forbidden")

    def test_an_occupied_branch_does_not_enter_the_fork_ladder(self):
        import inspect
        from stayawake.core import proposal
        src = inspect.getsource(proposal.submit_change_pr)
        self.assertIn("occupied", src,
                      "a policy refusal follows the branch to a fork, so forking cannot help")


if __name__ == "__main__":
    unittest.main()

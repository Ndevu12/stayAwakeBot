#!/usr/bin/env python3
"""`saw fix --branch` targets a branch other than the repository default."""
import unittest
from unittest import mock

from stayawake.bots.security import remediator


class BaseSelection(unittest.TestCase):
    def test_no_branch_means_the_repository_default(self):
        bases, missing = remediator._bases_for("/repo", None)
        self.assertEqual((bases, missing), ([None], []))

    def test_a_named_branch_becomes_its_own_base(self):
        with mock.patch.object(remediator.gitutil, "ref_exists", return_value=True):
            bases, missing = remediator._bases_for("/repo", ["develop"])
        self.assertEqual((bases, missing), (["develop"], []))

    def test_several_branches_become_several_bases(self):
        with mock.patch.object(remediator.gitutil, "ref_exists", return_value=True):
            bases, _ = remediator._bases_for("/repo", ["develop", "release/2"])
        self.assertEqual(bases, ["develop", "release/2"])

    def test_a_branch_that_does_not_exist_is_refused_not_defaulted(self):
        # Silently fixing the default instead would remediate a branch the user did not name.
        with mock.patch.object(remediator.gitutil, "ref_exists", return_value=False):
            bases, missing = remediator._bases_for("/repo", ["typo"])
        self.assertEqual(bases, [])
        self.assertEqual(missing, ["typo"])

    def test_a_remote_tracking_branch_counts_as_present(self):
        def only_remote(_repo, ref):
            return ref.startswith("origin/")
        with mock.patch.object(remediator.gitutil, "ref_exists", side_effect=only_remote):
            bases, missing = remediator._bases_for("/repo", ["develop"])
        self.assertEqual((bases, missing), (["develop"], []))


class ItemLabel(unittest.TestCase):
    def test_the_default_base_is_not_labelled(self):
        self.assertEqual(remediator._item_label("~/repo", None), "~/repo")

    def test_a_named_base_is_shown_so_the_board_is_unambiguous(self):
        self.assertEqual(remediator._item_label("~/repo", "develop"), "~/repo@develop")


if __name__ == "__main__":
    unittest.main()

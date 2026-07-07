#!/usr/bin/env python3
"""Semver comparator + OSV range evaluation (#1124)."""
from __future__ import annotations

import unittest

from stayawake.bots.security.dependencies.comparators import (
    gem_key, is_version_in_range, maven_key, pep440_key, semver_key, version_in_any_range)
from stayawake.bots.security.dependencies.osv import OsvRange


def _range(rtype, *events):
    return OsvRange(rtype, tuple(events))


class TestSemverKey(unittest.TestCase):
    def _lt(self, a, b):
        self.assertLess(semver_key(a), semver_key(b), f"{a} should sort below {b}")

    def test_ordering(self):
        for a, b in [("1.0.0", "1.0.1"), ("1.0.9", "1.1.0"), ("1.9.0", "2.0.0"),
                     ("1.0.0-alpha", "1.0.0"),           # prerelease < release
                     ("1.0.0-alpha", "1.0.0-beta"),      # lexical prerelease
                     ("1.0.0-1", "1.0.0-2"),             # numeric prerelease
                     ("1.0.0-1", "1.0.0-alpha")]:        # numeric id < alphanumeric id
            self._lt(a, b)

    def test_v_prefix_and_build_metadata(self):
        self.assertEqual(semver_key("v1.2.3"), semver_key("1.2.3"))
        self.assertEqual(semver_key("1.2.3+build.5"), semver_key("1.2.3"))

    def test_short_and_four_part_versions(self):
        self.assertEqual(semver_key("1.2"), semver_key("1.2.0"))       # padded
        self.assertLess(semver_key("1.2.3.4"), semver_key("1.2.3.5"))  # NuGet 4-part

    def test_non_numeric_release_is_none(self):
        self.assertIsNone(semver_key("not-a-version"))
        self.assertIsNone(semver_key("1.x"))


class TestRangeEvaluation(unittest.TestCase):
    def test_semver_introduced_fixed(self):
        r = _range("SEMVER", ("introduced", "1.0.0"), ("fixed", "2.0.0"))
        self.assertFalse(is_version_in_range("0.9.0", r, "npm"))
        self.assertTrue(is_version_in_range("1.0.0", r, "npm"))
        self.assertTrue(is_version_in_range("1.9.9", r, "npm"))
        self.assertFalse(is_version_in_range("2.0.0", r, "npm"))       # fixed is exclusive

    def test_introduced_zero_is_all_versions(self):
        r = _range("SEMVER", ("introduced", "0"))
        self.assertTrue(is_version_in_range("0.0.1", r, "npm"))
        self.assertTrue(is_version_in_range("99.0.0", r, "npm"))

    def test_last_affected_is_inclusive(self):
        r = _range("ECOSYSTEM", ("introduced", "1.0.0"), ("last_affected", "1.5.0"))
        self.assertTrue(is_version_in_range("1.5.0", r, "cargo"))       # inclusive
        self.assertFalse(is_version_in_range("1.5.1", r, "cargo"))

    def test_ecosystem_semver_family(self):
        r = _range("ECOSYSTEM", ("introduced", "0"), ("fixed", "4.6.5"))
        for eco in ("npm", "cargo", "golang", "composer", "nuget"):
            self.assertTrue(is_version_in_range("4.0.0", r, eco))
            self.assertFalse(is_version_in_range("4.6.5", r, eco))

    def test_all_ecosystems_evaluate_ranges(self):
        # Every supported ecosystem now has a comparator (#1124 completed).
        r = _range("ECOSYSTEM", ("introduced", "0"), ("fixed", "2.0.0"))
        for eco in ("npm", "cargo", "golang", "composer", "nuget", "pypi", "gem", "maven"):
            self.assertTrue(is_version_in_range("1.0.0", r, eco), eco)
            self.assertFalse(is_version_in_range("2.0.0", r, eco), eco)

    def test_git_and_unparseable_are_false(self):
        self.assertFalse(is_version_in_range("1.0.0", _range("GIT", ("introduced", "abcdef")), "npm"))
        # unparseable target version → False, never a crash
        self.assertFalse(is_version_in_range("not-a-version",
                                             _range("SEMVER", ("introduced", "0")), "npm"))
        # unparseable bound → conservative False
        self.assertFalse(is_version_in_range("1.0.0",
                                             _range("SEMVER", ("introduced", "1.x")), "npm"))

    def test_version_in_any_range(self):
        ranges = [_range("SEMVER", ("introduced", "1.0.0"), ("fixed", "1.5.0")),
                  _range("SEMVER", ("introduced", "2.0.0"), ("fixed", "2.5.0"))]
        self.assertTrue(version_in_any_range("2.1.0", ranges, "npm"))
        self.assertFalse(version_in_any_range("1.7.0", ranges, "npm"))   # between the two windows


class TestPep440(unittest.TestCase):
    def _lt(self, a, b):
        self.assertLess(pep440_key(a), pep440_key(b), f"{a} < {b}")

    def test_ordering(self):
        for a, b in [("1.0.dev1", "1.0a1"), ("1.0a1", "1.0b1"), ("1.0b1", "1.0rc1"),
                     ("1.0rc1", "1.0"), ("1.0", "1.0.post1"), ("1.0.post1", "1.1"),
                     ("1.0a1.dev1", "1.0a1"), ("1!1.0", "2!0.1")]:
            self._lt(a, b)

    def test_equalities_and_aliases(self):
        self.assertEqual(pep440_key("1.0"), pep440_key("1.0.0"))
        self.assertEqual(pep440_key("1.0c1"), pep440_key("1.0rc1"))     # c == rc
        self.assertIsNone(pep440_key("not-a-version"))

    def test_range_membership(self):
        r = _range("ECOSYSTEM", ("introduced", "1.0"), ("fixed", "2.0"))
        self.assertTrue(is_version_in_range("1.5.post1", r, "pypi"))
        self.assertFalse(is_version_in_range("2.0", r, "pypi"))
        self.assertFalse(is_version_in_range("1.0.dev1", r, "pypi"))    # dev is below 1.0


class TestGem(unittest.TestCase):
    def test_prerelease_below_release(self):
        self.assertLess(gem_key("1.0.0.beta"), gem_key("1.0.0"))
        self.assertLess(gem_key("1.0.0.alpha"), gem_key("1.0.0.beta"))
        self.assertEqual(gem_key("1.0"), gem_key("1.0.0"))

    def test_range_membership(self):
        r = _range("ECOSYSTEM", ("introduced", "1.0.0"), ("fixed", "2.0.0"))
        self.assertTrue(is_version_in_range("1.5.0", r, "gem"))
        self.assertFalse(is_version_in_range("1.0.0.beta", r, "gem"))   # prerelease < introduced
        self.assertFalse(is_version_in_range("2.0.0", r, "gem"))


class TestMaven(unittest.TestCase):
    def test_qualifier_ordering(self):
        order = ["1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc", "1.0-snapshot", "1.0", "1.0-sp"]
        for a, b in zip(order, order[1:]):
            self.assertLess(maven_key(a), maven_key(b), f"{a} < {b}")

    def test_release_equivalences(self):
        self.assertEqual(maven_key("1.0"), maven_key("1.0.0"))
        self.assertEqual(maven_key("1.0"), maven_key("1.0-ga"))

    def test_range_membership(self):
        r = _range("ECOSYSTEM", ("introduced", "0"), ("fixed", "2.0.0"))
        self.assertTrue(is_version_in_range("1.9", r, "maven"))
        self.assertTrue(is_version_in_range("2.0-rc1", r, "maven"))     # rc < 2.0 → still affected
        self.assertFalse(is_version_in_range("2.0.0", r, "maven"))


if __name__ == "__main__":
    unittest.main()

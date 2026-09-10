#!/usr/bin/env python3
"""`saw fix amend` judges the credential before it starts, and says which identity it used."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.lib.git import authority


def _reads(repo_value, user_value, user_cause=None):
    def read(path, token):
        if path.startswith("/repos"):
            return mock.Mock(cause=None, value=repo_value)
        return mock.Mock(cause=user_cause, value=user_value)
    return read


class TestARefusalNamesTheIdentityItUsed(unittest.TestCase):
    def test_it_says_who_the_credential_is_and_what_it_does_not_own(self):
        repo = {"owner": {"login": "Owner"}, "permissions": {"admin": False, "push": False}}
        with mock.patch.object(authority, "_read", _reads(repo, {"login": "someone-else"})):
            verdict = authority.may_rewrite("Owner/thing", "tok")
        self.assertEqual(verdict.reason, "no_admin_permission")
        self.assertIn("someone-else", verdict.detail)
        self.assertIn("Owner", verdict.detail)

    def test_the_owner_is_permitted(self):
        repo = {"owner": {"login": "Owner"}, "permissions": {"admin": False, "push": True}}
        with mock.patch.object(authority, "_read", _reads(repo, {"login": "owner"})):
            self.assertTrue(authority.may_rewrite("Owner/thing", "tok").permitted)


class TestAnIdentityItCouldNotReadIsNotADefiniteRefusal(unittest.TestCase):
    """Whether the credential owns the repository is unanswered when its login cannot be read.
    Reporting that as "no admin" tells the operator something that was never established."""

    def test_an_unreadable_login_is_inconclusive(self):
        repo = {"owner": {"login": "Owner"}, "permissions": {"admin": False, "push": True}}
        with mock.patch.object(authority, "_read", _reads(repo, None, user_cause="forbidden")):
            verdict = authority.may_rewrite("Owner/thing", "tok")
        self.assertFalse(verdict.permitted)
        self.assertFalse(verdict.conclusive)
        self.assertEqual(verdict.reason, "identity_unknown")

    def test_and_it_still_refuses(self):
        repo = {"owner": {"login": "Owner"}, "permissions": {"admin": False, "push": True}}
        with mock.patch.object(authority, "_read", _reads(repo, None, user_cause="forbidden")):
            self.assertFalse(authority.may_rewrite("Owner/thing", "tok").permitted)

    def test_admin_still_qualifies_without_a_readable_login(self):
        repo = {"owner": {"login": "Owner"}, "permissions": {"admin": True}}
        with mock.patch.object(authority, "_read", _reads(repo, None, user_cause="forbidden")):
            verdict = authority.may_rewrite("Owner/thing", "tok")
        self.assertTrue(verdict.permitted)
        self.assertEqual(verdict.reason, "admin")


class TestItAuthorizesBeforeItWorks(unittest.TestCase):
    """Every other acting verb gates on `_preflight` before touching a repository. The local amend
    path did not, so a dead credential was met one repository at a time."""

    def test_the_local_path_preflights_like_the_remote_one(self):
        import ast
        import pathlib
        source = pathlib.Path("src/stayawake/bots/security/remediator.py").read_text()
        tree = ast.parse(source)
        for name in ("_amend_local", "_amend_remote"):
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == name)
            calls = {getattr(c.func, "id", "") for c in ast.walk(fn) if isinstance(c, ast.Call)}
            with self.subTest(function=name):
                self.assertIn("_preflight", calls)


class TestATypoIsReportedAsATypo(unittest.TestCase):
    """Naming a path that is not there is a mistake in the command. Answering it with a credential
    error sends the operator to the wrong problem, and checking a path is not privileged work."""

    def test_a_missing_path_is_named_before_the_credential_is_judged(self):
        import io
        from stayawake.bots.security import remediator
        from stayawake.bots.security.resolution import ScanOptions
        from stayawake.utils.streaming import Streamer
        out = io.StringIO()
        with mock.patch.object(remediator, "_preflight",
                               side_effect=AssertionError("judged before the path was checked")):
            outcomes = remediator._amend_local({}, ScanOptions(), {}, [], ["/nowhere-at-all"],
                                               Streamer(enabled=False, out=out), jobs=1)
        self.assertEqual(outcomes, [])
        self.assertIn("no such path", out.getvalue())

    def test_and_the_remote_path_names_a_bad_slug_the_same_way(self):
        import ast
        import pathlib
        source = pathlib.Path("src/stayawake/bots/security/remediator.py").read_text()
        tree = ast.parse(source)
        for name, typed in (("_amend_local", "no such path"),
                            ("_amend_remote", "must be owner/repo slugs")):
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == name)
            body = ast.get_source_segment(source, fn) or ""
            with self.subTest(function=name):
                self.assertLess(body.index(typed), body.index("_preflight("),
                                "what the operator typed is checked before their credential is")


if __name__ == "__main__":
    unittest.main()

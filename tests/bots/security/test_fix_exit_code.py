#!/usr/bin/env python3
"""A repo `saw fix` never fixed must never read as success.

The remote arm returned "o/r: App not installed on owner" and "o/r: clone failed", neither of which
matched the substring test the tally used, so an unreachable repository exited 0. Automation reading
that exit code believed it was remediated.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security import remediator


class RemoteFixExitCase(unittest.TestCase):
    CONFIG = {"settings": {}, "targets": {}, "allowlist": []}

    def _run(self, *, act_token=None, clone=None, submit=None):
        cm = mock.MagicMock()
        cm.__enter__ = mock.Mock(return_value=clone)
        cm.__exit__ = mock.Mock(return_value=False)
        with mock.patch.object(remediator, "_resolve_config", return_value=self.CONFIG), \
             mock.patch.object(remediator, "load_signatures", return_value={}), \
             mock.patch.object(remediator, "_preflight", return_value=None), \
             mock.patch.object(remediator.auth, "act_token",
                               return_value=act_token or ("tok", None)), \
             mock.patch.object(remediator, "_resolve_remote",
                               return_value=(["owner/repo"], "tok", "app")), \
             mock.patch.object(remediator.resolution, "cloned_repo", return_value=cm), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value=submit or "owner/repo: fixed"):
            return remediator.fix(remote=True, slugs=["owner/repo"], no_stream=True, jobs=1)


class TestAnUnfixedRepoFailsClosed(RemoteFixExitCase):
    def test_auth_unreachable_exits_non_zero(self):
        rc = self._run(act_token=(None, "App not installed on owner"))
        self.assertNotEqual(0, rc, "a repo no credential can reach reported success")

    def test_clone_failure_exits_non_zero(self):
        self.assertNotEqual(0, self._run(clone=None))

    def test_an_aborted_fix_still_exits_non_zero(self):
        self.assertNotEqual(0, self._run(clone=mock.Mock(), submit="owner/repo: ABORTED — dirty"))

    def test_a_partial_fix_still_exits_non_zero(self):
        self.assertNotEqual(0, self._run(clone=mock.Mock(), submit="owner/repo: PARTIAL — 1 left"))

    def test_a_real_fix_still_exits_zero(self):
        # The gate must not become "always fail" — that would be a different kind of useless.
        self.assertEqual(0, self._run(clone=mock.Mock(), submit="owner/repo: fixed 2 file(s)"))


class TestTheGradeIsCarriedNotReparsed(unittest.TestCase):
    """The tally reads a flag set where the failure is known, so wording can change freely."""

    def test_a_failure_worded_without_any_marker_still_counts(self):
        outcome = remediator.FixOutcome("owner/repo: App not installed", needs_review=True)
        for marker in ("ABORTED", ": error", "PARTIAL"):
            self.assertNotIn(marker, outcome.summary)
        self.assertTrue(outcome.needs_review)

    def test_the_default_does_not_claim_success(self):
        # A plain summary defaults to not-needing-review, so every FAILURE site must say so; the
        # tests above are what hold that line.
        self.assertFalse(remediator.FixOutcome("owner/repo: fixed").needs_review)


if __name__ == "__main__":
    unittest.main()


class TestAMissingConfigIsTheSameEverywhere(unittest.TestCase):
    """One resolver, so naming a config that is not there fails the same way in every command."""

    MISSING = "/no/such/security.yml"

    def test_every_command_refuses_and_says_why(self):
        import io
        from contextlib import redirect_stderr
        from stayawake.bots.security import hook
        from stayawake.bots.security.guard import sweep
        from stayawake.bots.security.service import run as scan_run
        for name, call in (("fix", lambda: remediator.fix(self.MISSING, no_stream=True)),
                           ("discard", lambda: remediator.discard(self.MISSING, branch=True,
                                                                  no_stream=True)),
                           ("scan", lambda: scan_run.scan(config_path=self.MISSING,
                                                          no_stream=True)),
                           ("guard", lambda: sweep._guard_config(self.MISSING)),
                           ("hook", lambda: hook.install(self.MISSING))):
            with self.subTest(command=name):
                buf = io.StringIO()
                with redirect_stderr(buf):
                    result = call()
                self.assertIn("not found", buf.getvalue(), f"{name} said nothing")
                self.assertNotEqual(0, result if isinstance(result, int) else 2,
                                    f"{name} treated a missing config as success")

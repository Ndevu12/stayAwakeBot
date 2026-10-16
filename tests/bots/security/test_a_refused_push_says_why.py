#!/usr/bin/env python3
"""A push GitHub refuses says why, in GitHub's own words with no address or credential in them; a refusal
over a private email address names the step that clears it; nothing refused is reported as moved."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.pr import amend
from stayawake.bots.security.pr.outcome import BranchResult, Cause, Reason, amended, render_amend_line
from stayawake.core.identity.classify import (NOREPLY_NEXT_STEP, classify_push_stderr, push_failure_message,
                                              what_the_remote_said)
from stayawake.lib.git.write.push import PushResult

_TOKEN = "ghs_" + "a1b2c3d4e5" * 4
_PAT = "github_pat_" + "Z9y8X7w6V5" * 4
_PRIVATE_EMAIL = (
    "remote: error: GH007: Your push would publish a private email address.\n"
    "remote: You can make your email public or disable this protection by visiting:\n"
    "remote: https://github.com/settings/emails\n"
    f"To https://x-access-token:{_TOKEN}@github.com/o/r.git\n"
    " ! [remote rejected] c6057e4f6d1a -> main (push declined due to email privacy restrictions)\n"
    "error: failed to push some refs to 'https://github.com/o/r.git'\n")
_RULES = (
    "remote: error: GH013: Repository rule violations found for refs/heads/main.\n"
    "remote: - Cannot force-push to this branch\n"
    "To https://github.com/o/r.git\n"
    " ! [remote rejected] c6057e4f6d1a -> main (push declined due to repository rule violations)\n"
    "error: failed to push some refs to 'https://github.com/o/r.git'\n")
_UNREACHABLE = f"fatal: unable to access 'https://{_PAT}@github.com/o/r.git/': Could not resolve host"


def _line(stderr: str, dest: tuple[str, Reason | None] = ("main", None)) -> str:
    refused = lambda branch, to, lease: PushResult(False, stderr)  # noqa: E731
    with mock.patch.object(amend, "_destination", return_value=dest):
        result = amend._force_update_branch(Path("."), "o/r", "main", None, pusher=refused, lease="abc",
                                            sha12="c6057e4f6d1a")
    return render_amend_line(amended("o/r", "c6057e4f6d1a", [result]))


class TestARefusedPushSaysWhy(unittest.TestCase):
    def test_the_report_carries_what_github_said(self):
        line = _line(_RULES)
        self.assertIn("the push was refused (main) — the remote said: GH013: Repository rule violations "
                      "found for refs/heads/main.", line)
        self.assertIn("push declined due to repository rule violations", line)

    def test_a_branch_pushed_aside_says_why_too(self):
        aside_branch = "security/amend-c6057e4f6d1a"
        aside = (aside_branch, Reason(Cause.BRANCH_PROTECTED, aside_branch))
        self.assertIn("the remote said: GH013", _line(_RULES, aside))

    def test_a_refusal_over_a_private_email_address_names_the_step_that_clears_it(self):
        line = _line(_PRIVATE_EMAIL)
        self.assertIn("the push of main was refused because GitHub keeps your email address private", line)
        self.assertIn("@users.noreply.github.com", line)
        self.assertIn(NOREPLY_NEXT_STEP, line)

    def test_nothing_refused_is_reported_as_moved(self):
        for stderr in (_RULES, _PRIVATE_EMAIL, _UNREACHABLE, ""):
            with self.subTest(stderr=stderr[:20]):
                line = _line(stderr)
                self.assertIn("'main' was not force-updated", line)
                self.assertNotIn("force-updated 'main'", line)
                self.assertIn("the remote was not fully updated", line)

    def test_no_address_or_credential_reaches_the_report(self):
        for stderr in (_RULES, _PRIVATE_EMAIL, _UNREACHABLE, f"error: {_TOKEN} {_PAT}"):
            with self.subTest(stderr=stderr[:20]):
                line = _line(stderr)
                for secret in (_TOKEN, _PAT, "x-access-token", "https://", "github.com/o/r.git"):
                    self.assertNotIn(secret, line)

    def test_what_the_remote_said_is_bounded(self):
        words = what_the_remote_said("remote: error: " + "x" * 10_000)
        self.assertLessEqual(len(words), 240)


class TestARefusalOverAPrivateEmailAddressIsItsOwnKind(unittest.TestCase):
    def test_it_reads_as_a_refusal_over_a_private_address(self):
        self.assertEqual(classify_push_stderr(_PRIVATE_EMAIL).reason, "private_email")
        self.assertEqual(classify_push_stderr(_RULES).reason, "occupied")

    def test_the_pull_request_path_names_the_step_too(self):
        failure = classify_push_stderr(_PRIVATE_EMAIL)
        self.assertIn(NOREPLY_NEXT_STEP, push_failure_message(failure))

    def test_the_pull_request_path_does_not_try_a_fork_that_would_be_refused_the_same_way(self):
        from stayawake.core import proposal
        forked = []
        with mock.patch.object(proposal.gitutil, "push_branch_result",
                               return_value=PushResult(False, _PRIVATE_EMAIL)), \
                mock.patch.object(proposal, "_fork_and_pr", side_effect=lambda *a, **k: forked.append(a)), \
                mock.patch.object(proposal, "_save_patch", return_value=None):
            result = proposal.submit_change_pr(Path("."), "o/r", "main", branch="b", title="t", body="b",
                                               token="t")
        self.assertEqual(forked, [])
        self.assertEqual(result.push_reason, "private_email")


if __name__ == "__main__":
    unittest.main()

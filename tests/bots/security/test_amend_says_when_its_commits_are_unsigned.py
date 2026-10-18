#!/usr/bin/env python3
"""When `saw fix amend` cannot sign, it amends anyway, says the new commits are not signed, and gives
no setup steps."""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.lib.signing.commits import SigningStatus
from tests.bots.security.test_amend import _AmendFixture

_NO_SIGNATURE = SigningStatus(required=True, available=False, signature_format="openpgp",
                              reason="the commits being replaced are signed but no openpgp signature "
                                     "could be produced: error: gpg failed to sign the data:")


class TestAnAmendThatCannotSignSaysSo(_AmendFixture):
    AT = "stayawake.bots.security.pr.amend."

    def _unsigned(self):
        self._loader_merge()
        with mock.patch(self.AT + "commit_signing.signing_status", return_value=_NO_SIGNATURE):
            return self._act()

    def _headers(self, rev="HEAD"):
        return subprocess.run(["git", "-C", str(self.d), "cat-file", "commit", rev],
                              capture_output=True, text=True, check=True).stdout.split("\n\n", 1)[0]

    def test_it_force_updates_the_branch(self):
        outcome = self._unsigned()
        self.assertTrue(outcome.completed)
        self.assertIn("force-updated", render_amend_line(outcome))

    def test_it_says_the_new_commits_are_not_signed(self):
        self.assertIn("the new commits are not signed", render_amend_line(self._unsigned()))

    def test_it_gives_no_setup_steps(self):
        line = render_amend_line(self._unsigned())
        for words in ("gpg", "git config", "GPG_TTY", "signingkey", "run `saw fix amend` again"):
            with self.subTest(words=words):
                self.assertNotIn(words, line)

    def test_the_new_commits_carry_no_signature(self):
        self._unsigned()
        self.assertNotIn("gpgsig", self._headers())

    def test_saying_so_asks_nothing_more_of_you(self):
        self.assertFalse(self._unsigned().needs_review)

    def test_a_rewrite_that_owes_no_signature_adds_no_note(self):
        self._loader_merge()
        outcome = self._act()
        self.assertNotIn(Cause.REPLACEMENTS_UNSIGNED, [r.cause for r in outcome.reasons])


class TestAmendReadsTheKeysOfTheTokensAccount(unittest.TestCase):
    def test_without_a_token_github_is_not_asked(self):
        with mock.patch.object(amendmod, "get_authenticated_user", side_effect=AssertionError):
            self.assertEqual(amendmod._signing_keys_on_github(None), [])

    def test_the_tokens_account_is_the_one_asked(self):
        with mock.patch.object(amendmod, "get_authenticated_user", return_value={"login": "your-user"}), \
                mock.patch.object(amendmod, "list_ssh_signing_keys", return_value=["ssh-ed25519 AAAA"]) as listed:
            self.assertEqual(amendmod._signing_keys_on_github("t"), ["ssh-ed25519 AAAA"])
        listed.assert_called_once_with("your-user", "t")

    def test_an_account_that_cannot_be_read_lists_nothing(self):
        with mock.patch.object(amendmod, "get_authenticated_user", return_value=None):
            self.assertEqual(amendmod._signing_keys_on_github("t"), [])


if __name__ == "__main__":
    unittest.main()

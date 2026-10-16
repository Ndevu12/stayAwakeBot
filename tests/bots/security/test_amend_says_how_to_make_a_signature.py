#!/usr/bin/env python3
"""When `saw fix amend` stops because this repository signs commits and no signature can be made, it says how to make
one and to run `saw fix amend` again, keeps the signer's own words, and moves nothing."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from tests.bots.security.test_amend import _AmendFixture

_SIGNER_SAID = ("the commits being replaced are signed but no openpgp signature could be produced: error: gpg "
                "failed to sign the data:")


class TestASignatureThatCannotBeMadeNamesTheNextSteps(_AmendFixture):
    AT = "stayawake.bots.security.pr.amend."

    def _refused(self):
        self._loader_merge()
        before = self._rev()
        unavailable = mock.Mock(must_refuse=True, available=False, required=True, signature_format="openpgp",
                                reason=_SIGNER_SAID, config=())
        with mock.patch(self.AT + "sign.signing_status", return_value=unavailable):
            outcome = self._act()
        return before, outcome

    def test_it_says_how_to_make_a_signature_and_to_run_amend_again(self):
        _before, outcome = self._refused()
        line = render_amend_line(outcome)
        for words in ("run `saw fix amend` again", "`echo test | gpg --clearsign`", "`export GPG_TTY=$(tty)`",
                      "`git config --global gpg.format ssh`", "`git config --global user.signingkey <your key>.pub`"):
            with self.subTest(words=words):
                self.assertIn(words, line)

    def test_it_keeps_the_signers_own_words(self):
        _before, outcome = self._refused()
        self.assertIn("error: gpg failed to sign the data", render_amend_line(outcome))

    def test_nothing_is_force_updated(self):
        before, outcome = self._refused()
        self.assertIn(Cause.SIGNING_UNAVAILABLE, [r.cause for r in outcome.reasons])
        self.assertTrue(render_amend_line(outcome).startswith("acme/app: nothing was force-updated"))
        self.assertEqual(before, self._rev())


if __name__ == "__main__":
    unittest.main()

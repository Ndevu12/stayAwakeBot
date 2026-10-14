#!/usr/bin/env python3
"""A command refused for its GitHub credential says what it was doing, what the credential must be
able to do, and the command to run."""
from __future__ import annotations

import unittest

from stayawake.core.identity import Capability, Intent, require
from stayawake.core.identity.capabilities import capabilities_from_oauth_scopes, what_it_allows
from stayawake.core.identity.intents import what_it_does
from stayawake.core.identity.session import Session


def _refused(intent, session):
    decision = require(intent, session=session)
    assert not decision.allowed
    return decision.message


class TestNoCredential(unittest.TestCase):
    def setUp(self):
        self.message = _refused(Intent.AMEND_REFS,
                                Session(token=None, source=None, kind="none", live=False))

    def test_it_says_what_saw_was_doing_and_what_the_credential_must_do(self):
        self.assertIn("No GitHub credential for replacing infected commits on GitHub.", self.message)
        self.assertIn("It needs a credential that can push to the repository.", self.message)

    def test_it_names_each_command_to_run_once(self):
        self.assertEqual(self.message.count("gh auth login"), 1)
        self.assertEqual(self.message.count("saw auth app register"), 1)

    def test_it_uses_no_internal_names(self):
        for internal in ("amend_refs", "amend refs", "contents_write", "missing:", "authenticate first"):
            self.assertNotIn(internal, self.message)


class TestACredentialThatCannotDoIt(unittest.TestCase):
    def test_it_names_what_the_credential_must_be_able_to_do(self):
        session = Session(token="t", source="gh", kind="user", actor="me", live=True,
                          capabilities=capabilities_from_oauth_scopes({"read:org"}),
                          scopes=frozenset({"read:org"}))
        message = _refused(Intent.OPEN_FIX_PR, session)
        self.assertIn("me cannot be used for opening fix pull requests.", message)
        self.assertIn("It needs a credential that can push to the repository and open pull requests.",
                      message)
        self.assertNotIn("open_fix_pr", message)
        self.assertNotIn("pull_requests_write", message)


class TestEveryActAndPermissionHasPlainWords(unittest.TestCase):
    def test_every_intent_says_what_it_does(self):
        for intent in Intent:
            self.assertNotIn("_", what_it_does(intent), intent)

    def test_every_capability_says_what_it_allows(self):
        for capability in Capability:
            self.assertNotIn("_", what_it_allows(capability), capability)


if __name__ == "__main__":
    unittest.main()

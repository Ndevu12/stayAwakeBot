#!/usr/bin/env python3
"""A rewrite saw publishes to GitHub is committed under the account's GitHub noreply address, so the
operator's own address is not published, and the report says so; an address that already is a noreply
one, or an account that cannot be read, keeps the configured identity; authors are untouched, and a
signature is still made with the operator's own key."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.bots.security.targets.base import ScanOptions
from stayawake.core.identity.publishing import keeps_the_address_private, noreply_address, publishing_identity
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.sign import signer_pinned, signing_env, signing_status
from tests.bots.security.test_amend import _AmendFixture, _ok_push, _sigs
from tests.core.test_git_sign import _GPG_THAT_SIGNS, _repo, _script, SigningFixture
from tests.support.offline_github import github_answers

_ACCOUNT = {"id": 140616733, "login": "octo-cat"}
_NOREPLY = "140616733+octo-cat@users.noreply.github.com"
_OWN = ("Ada", "ada@example.com")


class TestTheAddressSawPublishesUnder(unittest.TestCase):
    def test_an_account_gives_its_id_based_noreply_address(self):
        self.assertEqual(noreply_address(_ACCOUNT), _NOREPLY)

    def test_a_configured_address_of_your_own_is_replaced_by_the_noreply_one(self):
        chosen = publishing_identity(_OWN, "t", account_of=lambda t, quiet: _ACCOUNT)
        self.assertEqual(chosen, ("Ada", _NOREPLY))

    def test_a_configured_noreply_address_is_kept_and_no_account_is_read(self):
        read = []
        for email in (_NOREPLY, "octo-cat@users.noreply.github.com", "1+X@Users.NoReply.GitHub.com"):
            with self.subTest(email=email):
                chosen = publishing_identity(("Ada", email), "t", account_of=lambda t, quiet: read.append(t))
                self.assertEqual(chosen, ("Ada", email))
                self.assertTrue(keeps_the_address_private(email))
        self.assertEqual(read, [])

    def test_an_account_that_cannot_be_read_keeps_the_configured_identity(self):
        for account in (None, {}, [], {"id": 0, "login": "a"}, {"id": -1, "login": "a"},
                        {"id": True, "login": "a"}, {"id": "7", "login": "a"}, {"id": 7, "login": "a b"},
                        {"id": 7, "login": "-a"}, {"id": 7, "login": "a" * 40},
                        {"id": 7, "login": "a@evil.example"}, {"id": 7}):
            with self.subTest(account=account):
                self.assertEqual(publishing_identity(_OWN, "t", account_of=lambda t, quiet: account), _OWN)

    def test_without_a_token_no_account_is_read(self):
        read = []
        chosen = publishing_identity(_OWN, None, account_of=lambda t, quiet: read.append(t))
        self.assertEqual((chosen, read), (_OWN, []))


class TestAPublishedRewriteKeepsYourAddressPrivate(_AmendFixture):
    def _amend_as(self, account):
        with github_answers(self._rev, account=account):
            return amend_outcome(self.d, "acme/app", ScanOptions(), _sigs(), [], "t", pusher=_ok_push)

    def _identities(self, rev="HEAD"):
        return self.git(self.d, "log", "-1", "--format=%an <%ae>|%cn <%ce>", rev).strip().split("|")

    def test_the_rewrite_is_committed_under_the_noreply_address_and_authors_are_untouched(self):
        self._loader_merge()
        outcome = self._amend_as(_ACCOUNT)
        self.assertTrue(outcome.completed, [r.cause for r in outcome.reasons])
        author, committer = self._identities()
        self.assertEqual(author, "Injected <inj@t.test>")
        self.assertEqual(committer, f"Tester <{_NOREPLY}>")
        self.assertIn(f"committed as Tester <{_NOREPLY}> so your own address is not published",
                      render_amend_line(outcome))
        self.assertFalse(outcome.needs_review)

    def test_a_signed_rewrite_is_signed_with_the_key_of_the_configured_identity(self):
        folder = Path(tempfile.mkdtemp(prefix="saw-signer-"))
        asked = folder / "asked"
        signer = _script(f'#!/bin/sh\nprintf "%s\\n" "$@" >> "{asked}"\n' + _GPG_THAT_SIGNS.split("\n", 1)[1])
        operator = folder / "gitconfig"
        operator.write_text(f"[gpg]\n\tprogram = {signer}\n")
        self._loader_merge()
        self.git(self.d, "config", "commit.gpgsign", "true")
        self.git(self.d, "config", "gpg.format", "openpgp")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(operator)}):
            outcome = self._amend_as(_ACCOUNT)
        self.assertTrue(outcome.completed, [r.cause for r in outcome.reasons])
        self.assertIn("gpgsig ", self.git(self.d, "cat-file", "commit", "HEAD"))
        self.assertEqual(self._identities()[1], f"Tester <{_NOREPLY}>")
        keys = asked.read_text().splitlines()
        self.assertIn("Tester <t@t.test>", keys)
        self.assertNotIn(f"Tester <{_NOREPLY}>", keys)

    def test_a_configured_noreply_address_is_published_as_it_is(self):
        self.git(self.d, "config", "user.email", "octo-cat@users.noreply.github.com")
        self._loader_merge()
        outcome = self._amend_as(_ACCOUNT)
        self.assertEqual(self._identities()[1], "Tester <octo-cat@users.noreply.github.com>")
        self.assertNotIn(Cause.COMMITTED_UNDER_NOREPLY, [r.cause for r in outcome.reasons])

    def test_an_account_that_cannot_be_read_keeps_the_configured_identity(self):
        self._loader_merge()
        outcome = self._amend_as(None)
        self.assertEqual(self._identities()[1], "Tester <t@t.test>")
        self.assertNotIn("committed as", render_amend_line(outcome))


class TestTheSignatureIsStillTheOperators(SigningFixture):
    def _rewrite_under_noreply(self, repo: Path):
        status = signing_status(repo)
        self.assertTrue(status.available, status.reason)
        configured = ("The Operator", "operator@example.test")
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        tree = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], capture_output=True,
                              text=True, check=True).stdout.strip()
        sha, kind, refusal = gitamend.rewrite_commit(repo, head, tree, [], signer_pinned(status, configured),
                                                     committer=("The Operator", _NOREPLY))
        self.assertTrue(sha, f"{kind}: {refusal}")
        return subprocess.run(["git", "-C", str(repo), "cat-file", "commit", sha], capture_output=True,
                              text=True, check=True).stdout

    def test_an_openpgp_signature_is_made_with_the_key_of_the_configured_identity(self):
        asked = Path(tempfile.mkdtemp(prefix="saw-signer-asked-")) / "args"
        signer = _script(f'#!/bin/sh\nprintf "%s\\n" "$@" >> "{asked}"\n' + _GPG_THAT_SIGNS.split("\n", 1)[1])
        repo = _repo(commit__gpgsign="true", gpg__format="openpgp")
        self.operator_sets("gpg.program", str(signer))
        commit = self._rewrite_under_noreply(repo)
        self.assertIn(f"committer The Operator <{_NOREPLY}>", commit)
        self.assertIn("gpgsig ", commit)
        self.assertIn("The Operator <operator@example.test>", asked.read_text().splitlines())
        self.assertNotIn(_NOREPLY, asked.read_text())

    def test_an_ssh_signature_is_made_under_the_noreply_committer(self):
        key = Path(tempfile.mkdtemp(prefix="saw-signkey-")) / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "saw-test", "-f", str(key)],
                       check=True, capture_output=True, stdin=subprocess.DEVNULL)
        repo = _repo(commit__gpgsign="true", gpg__format="ssh", user__signingkey=str(key))
        commit = self._rewrite_under_noreply(repo)
        self.assertIn(f"committer The Operator <{_NOREPLY}>", commit)
        self.assertIn("gpgsig -----BEGIN SSH SIGNATURE-----", commit)

    def test_a_key_already_named_is_kept(self):
        repo = _repo(commit__gpgsign="true", gpg__format="openpgp", user__signingkey="DEADBEEF")
        self.operator_sets("gpg.program", str(_script(_GPG_THAT_SIGNS)))
        status = signing_status(repo)
        self.assertEqual(signer_pinned(status, ("A", "a@example.com")), status)

    def test_the_committer_given_replaces_any_in_the_environment_and_leaves_the_author(self):
        repo = _repo()
        with mock.patch.dict(os.environ, {"GIT_COMMITTER_EMAIL": "replayed@example.test",
                                          "GIT_AUTHOR_EMAIL": "author@example.test"}):
            env = signing_env(repo, committer=("The Operator", _NOREPLY))
        self.assertEqual((env["GIT_COMMITTER_NAME"], env["GIT_COMMITTER_EMAIL"]), ("The Operator", _NOREPLY))
        self.assertEqual(env["GIT_AUTHOR_EMAIL"], "author@example.test")


if __name__ == "__main__":
    unittest.main()

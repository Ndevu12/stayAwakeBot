#!/usr/bin/env python3
"""lib.git.write.sign — signing a history rewrite, exercised against REAL local git repos.

`saw fix amend` keeps each rewritten commit's ORIGINAL author, so an unsigned rewrite attributes
commits to people who never made them and destroys the signature that attested that authorship.
These tests pin the model: author preserved, committer the operator, signed by the operator — and
pin the three states a caller must tell apart, each built as an actual repository:

    signing off              -> not configured, not a refusal
    signing on and working   -> available, proven by a real signature
    signing on but broken    -> `must_refuse`, BEFORE any ref moves

The config flag is never taken as proof: a repository whose `commit.gpgsign` is true but whose key
cannot sign must come back unavailable.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git.run import run
from stayawake.lib.git.write import sign
from stayawake.lib.git.write.sign import (
    SigningStatus, any_signed, carries_signature, sign_flags, signing_args,
    signing_available, signing_env, signing_status,
)


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                         check=True)
    return res.stdout


def _repo(**config: str) -> Path:
    """A repo on `main` with one unsigned commit and `config` applied locally."""
    d = Path(tempfile.mkdtemp(prefix="saw-signtest-"))
    subprocess.run(["git", "init", "-q", "-b", "main", str(d)], check=True, capture_output=True)
    _git(d, "config", "user.email", "operator@example.test")
    _git(d, "config", "user.name", "The Operator")
    for key, value in config.items():
        _git(d, "config", key.replace("__", "."), value)
    (d / "app.js").write_text("ok\n", encoding="utf-8")
    _git(d, "add", "-A")
    _git(d, "-c", "commit.gpgsign=false", "commit", "-qm", "init")
    return d


def _ssh_signing_key() -> Path:
    key = Path(tempfile.mkdtemp(prefix="saw-signkey-")) / "id_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "saw-test",
                    "-f", str(key)], check=True, capture_output=True, stdin=subprocess.DEVNULL)
    return key


def _script(body: str) -> Path:
    path = Path(tempfile.mkdtemp(prefix="saw-signprog-")) / "signer.sh"
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


# git's openpgp signer is any program that prints a signature and reports SIG_CREATED on its
# status fd; there is no gpg on every host, so the format's code path is exercised through one.
_GPG_THAT_SIGNS = ("#!/bin/sh\n"
                   "printf '[GNUPG:] SIG_CREATED B 1 8 00 0 0\\n' >&2\n"
                   "cat > /dev/null\n"
                   "printf -- '-----BEGIN PGP SIGNATURE-----\\n\\nZmFrZQ==\\n"
                   "-----END PGP SIGNATURE-----\\n'\n")
_GPG_THAT_FAILS = ("#!/bin/sh\ncat > /dev/null\n"
                   "echo 'gpg: signing failed: No secret key' >&2\nexit 2\n")
# MEASURED on git 2.39: a signer that reports SIG_CREATED and emits nothing makes `git commit -S`
# exit 0 and write an UNSIGNED commit. Grading the exit code alone certifies that as signed.
_GPG_THAT_CLAIMS_SUCCESS_AND_SIGNS_NOTHING = ("#!/bin/sh\n"
                                              "printf '[GNUPG:] SIG_CREATED B 1 8 00 0 0\\n' >&2\n"
                                              "cat > /dev/null\n")
_SIGNER_THAT_BLOCKS = "#!/bin/sh\nsleep 20\n"


def _headers(repo: Path, rev: str = "HEAD") -> str:
    return _git(repo, "cat-file", "commit", rev).split("\n\n", 1)[0]


class SigningFixture(unittest.TestCase):
    """Every test runs against a repo whose signing config is fully local: the host's own global
    config already enables ssh signing, which would otherwise decide these outcomes."""

    def setUp(self):
        isolated = mock.patch.dict(os.environ,
                                   {"GIT_CONFIG_GLOBAL": "/dev/null",
                                    "GIT_CONFIG_SYSTEM": "/dev/null"})
        isolated.start()
        self.addCleanup(isolated.stop)

    def signing_off(self) -> Path:
        return _repo(commit__gpgsign="false")

    def signing_works(self) -> Path:
        return _repo(commit__gpgsign="true", gpg__format="ssh",
                     user__signingkey=str(_ssh_signing_key()))

    def signing_broken(self) -> Path:
        missing = Path(tempfile.mkdtemp(prefix="saw-nokey-")) / "absent_key"
        return _repo(commit__gpgsign="true", gpg__format="ssh", user__signingkey=str(missing))


class TestThreeStates(SigningFixture):
    def test_signing_off_is_unconfigured_and_not_a_refusal(self):
        status = signing_status(self.signing_off())
        self.assertFalse(status.required)
        self.assertFalse(status.available)
        self.assertFalse(status.must_refuse, "an unsigned repo must not block remediation")
        self.assertIn("commit.gpgsign", status.reason)

    def test_working_signing_is_available_only_once_a_signature_was_made(self):
        status = signing_status(self.signing_works())
        self.assertTrue(status.required)
        self.assertTrue(status.available, status.reason)
        self.assertFalse(status.must_refuse)
        self.assertEqual(status.signature_format, "ssh")

    def test_broken_key_is_a_refusal_not_a_silent_downgrade(self):
        status = signing_status(self.signing_broken())
        self.assertTrue(status.required, "commit.gpgsign=true is still configured")
        self.assertFalse(status.available, "an unloadable key cannot produce a signature")
        self.assertTrue(status.must_refuse, "the caller must refuse before any ref moves")
        self.assertIn("no ssh signature could be produced", status.reason)

    def test_the_three_states_are_distinguishable_from_each_other(self):
        off = signing_status(self.signing_off())
        works = signing_status(self.signing_works())
        broken = signing_status(self.signing_broken())
        self.assertEqual(
            [(s.required, s.available, s.must_refuse) for s in (off, works, broken)],
            [(False, False, False), (True, True, False), (True, False, True)])

    def test_available_tuple_agrees_with_the_status(self):
        repo = self.signing_broken()
        available, reason = signing_available(repo)
        status = signing_status(repo)
        self.assertEqual((available, reason), (status.available, status.reason))


class TestSignatureFormats(SigningFixture):
    def test_ssh_format_signs_through_ssh_keygen(self):
        status = signing_status(self.signing_works())
        self.assertTrue(status.available, status.reason)
        self.assertEqual(status.signature_format, "ssh")

    def test_openpgp_format_signs_through_the_configured_gpg_program(self):
        repo = _repo(commit__gpgsign="true", gpg__format="openpgp",
                     user__signingkey="DEADBEEF",
                     gpg__program=str(_script(_GPG_THAT_SIGNS)))
        status = signing_status(repo)
        self.assertTrue(status.available, status.reason)
        self.assertEqual(status.signature_format, "openpgp")

    def test_openpgp_that_cannot_sign_is_a_refusal(self):
        repo = _repo(commit__gpgsign="true", gpg__format="openpgp",
                     user__signingkey="DEADBEEF",
                     gpg__program=str(_script(_GPG_THAT_FAILS)))
        status = signing_status(repo)
        self.assertTrue(status.must_refuse)
        self.assertIn("gpg", status.reason.lower())

    def test_a_signer_that_reports_success_but_signs_nothing_is_a_refusal(self):
        repo = _repo(commit__gpgsign="true", gpg__format="openpgp",
                     user__signingkey="DEADBEEF",
                     gpg__program=str(_script(_GPG_THAT_CLAIMS_SUCCESS_AND_SIGNS_NOTHING)))
        status = signing_status(repo)
        self.assertTrue(status.must_refuse,
                        "git exits 0 here and writes an unsigned commit; only inspecting the "
                        "object catches it")
        self.assertIn("no signature", status.reason)


class TestProbeSafety(SigningFixture):
    def test_the_probe_writes_nothing_to_the_repository(self):
        repo = self.signing_works()
        before = (_git(repo, "rev-list", "--all"), _git(repo, "show-ref"),
                  sorted(p.name for p in (repo / ".git" / "objects").rglob("*")))
        signing_status(repo)
        after = (_git(repo, "rev-list", "--all"), _git(repo, "show-ref"),
                 sorted(p.name for p in (repo / ".git" / "objects").rglob("*")))
        self.assertEqual(before, after, "probing must not add an object or move a ref")

    def test_a_signer_that_blocks_resolves_to_unavailable_within_the_timeout(self):
        repo = _repo(commit__gpgsign="true", gpg__format="ssh",
                     user__signingkey=str(_ssh_signing_key()),
                     gpg__ssh__program=str(_script(_SIGNER_THAT_BLOCKS)))
        with mock.patch.object(sign, "PROBE_TIMEOUT", 2):
            started = time.monotonic()
            status = signing_status(repo)
            elapsed = time.monotonic() - started
        self.assertTrue(status.must_refuse, "a hung signer is a refusal, never an unsigned rewrite")
        self.assertLess(elapsed, 15, "the probe must be bounded, not wait on the signer")

    def test_no_signing_attempt_may_ask_a_human_anything(self):
        env = signing_env(self.signing_works())
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertFalse(Path(env["SSH_ASKPASS"]).exists(),
                         "the askpass helper must not exist, so a passphrase prompt fails fast")
        self.assertNotIn("GPG_TTY", env)


class TestArgumentsActuallySign(SigningFixture):
    """The interface is judged by the object git produces, not by the strings it returns."""

    def _commit_tree(self, repo: Path, status: SigningStatus, env: dict | None = None) -> str:
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        res = run(repo, [*signing_args(status), "commit-tree",
                         *sign_flags(status, "commit-tree"), tree, "-m", "rewritten"],
                  env=env or signing_env(repo))
        self.assertIsNotNone(res)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout.strip()

    def test_commit_tree_arguments_produce_a_real_signature(self):
        # MEASURED on git 2.39: commit-tree reads no signing config, so `-c commit.gpgsign=true`
        # alone leaves this object UNSIGNED. This asserts the produced object, not the argv.
        repo = self.signing_works()
        status = signing_status(repo)
        self.assertTrue(status.available, status.reason)
        self.assertIn("gpgsig", _headers(repo, self._commit_tree(repo, status)))

    def test_unavailable_signing_produces_an_unsigned_object(self):
        repo = self.signing_works()
        unsigned = SigningStatus(required=False, available=False, reason="", signature_format="")
        self.assertNotIn("gpgsig", _headers(repo, self._commit_tree(repo, unsigned)))

    def test_rebase_flag_overrides_a_repository_that_signs_by_default(self):
        repo = self.signing_works()
        _git(repo, "branch", "-q", "start")
        (repo / "app.js").write_text("replayed\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "suffix")
        _git(repo, "checkout", "-q", "-b", "newbase", "start")
        (repo / "other.js").write_text("base\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "new base")
        _git(repo, "checkout", "-q", "main")
        unsigned = SigningStatus(required=False, available=False, reason="", signature_format="")
        self.assertEqual(sign_flags(unsigned, "rebase"), ("--no-gpg-sign",))
        _git(repo, *signing_args(unsigned), "rebase", *sign_flags(unsigned, "rebase"),
             "--rebase-merges", "--onto", "newbase", "start")
        self.assertNotIn("gpgsig", _headers(repo))

    def test_an_unknown_command_raises_rather_than_falling_through_to_unsigned(self):
        status = signing_status(self.signing_off())
        with self.assertRaises(ValueError):
            sign_flags(status, "merge")


class TestCommitterIsTheOperator(SigningFixture):
    def test_the_rewrite_is_committed_by_the_operator_and_keeps_its_author(self):
        repo = self.signing_works()
        ambient = {**os.environ,
                   "GIT_COMMITTER_NAME": "Replayed Impostor",
                   "GIT_COMMITTER_EMAIL": "impostor@example.test",
                   "GIT_AUTHOR_NAME": "Original Author",
                   "GIT_AUTHOR_EMAIL": "original@example.test"}
        env = signing_env(repo, base=ambient)
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        res = run(repo, ["commit-tree", tree, "-m", "rewritten"], env=env)
        headers = _headers(repo, res.stdout.strip())
        self.assertIn("author Original Author <original@example.test>", headers)
        self.assertIn("committer The Operator <operator@example.test>", headers)
        self.assertNotIn("Impostor", headers)

    def test_an_ambient_committer_cannot_take_over_a_repo_with_no_configured_identity(self):
        # MEASURED: with no user.name/user.email, git auto-detects an identity but an ambient
        # GIT_COMMITTER_NAME still wins — so dropping those variables is what holds the line.
        repo = self.signing_works()
        _git(repo, "config", "--unset", "user.name")
        _git(repo, "config", "--unset", "user.email")
        env = signing_env(repo, base={**os.environ,
                                      "GIT_COMMITTER_NAME": "Replayed Impostor",
                                      "GIT_COMMITTER_EMAIL": "impostor@example.test"})
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        res = run(repo, ["commit-tree", tree, "-m", "rewritten"], env=env)
        self.assertNotIn("Impostor", _headers(repo, res.stdout.strip()))

    def test_the_operator_comes_from_the_repository_being_remediated(self):
        # The replay runs in a throwaway worktree, not in `repo`. Dropping the ambient variables
        # and letting git resolve `user.*` would then take the identity from wherever the command
        # happens to run; the committer must be the operator of the repository being fixed.
        repo = self.signing_works()
        elsewhere = _repo()
        _git(elsewhere, "config", "user.name", "Someone Else")
        _git(elsewhere, "config", "user.email", "someone@elsewhere.test")
        env = signing_env(repo)
        tree = _git(elsewhere, "rev-parse", "HEAD^{tree}").strip()
        res = run(elsewhere, ["commit-tree", tree, "-m", "rewritten"], env=env)
        self.assertIn("committer The Operator <operator@example.test>",
                      _headers(elsewhere, res.stdout.strip()))

    def test_a_stale_committer_date_is_never_inherited(self):
        repo = self.signing_works()
        env = signing_env(repo, base={**os.environ,
                                      "GIT_COMMITTER_DATE": "2001-01-01T00:00:00+00:00"})
        tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
        res = run(repo, ["commit-tree", tree, "-m", "rewritten"], env=env)
        committer = [ln for ln in _headers(repo, res.stdout.strip()).splitlines()
                     if ln.startswith("committer ")][0]
        committed_at = int(committer.split()[-2])
        self.assertGreater(committed_at, 1_600_000_000,
                           "a rewrite must be dated when it happened, not by an ambient "
                           f"GIT_COMMITTER_DATE ({committer})")


class TestTheHistoryDecidesWhatIsOwed(SigningFixture):
    """`commit.gpgsign` is a property of THIS clone. Whether the commits being replaced are signed
    is a property of the history, and it is the one that decides what a rewrite owes.

    A merge made with GitHub's merge button is signed server-side with no local config at all, and
    a CI checkout sets `commit.gpgsign` essentially never — reading the config alone reported
    "nothing asked for a signature" and the rewrite went out with `--no-gpg-sign`.
    """

    def _signed_then_config_off(self) -> Path:
        repo = self.signing_works()
        (repo / "later.js").write_text("later\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "signed later")
        _git(repo, "config", "--unset", "commit.gpgsign")
        return repo

    def test_signed_history_still_owes_a_signature_when_the_config_never_asked(self):
        repo = self._signed_then_config_off()
        self.assertFalse(signing_status(repo).required,
                         "the config alone asks for nothing — that is the trap")
        status = signing_status(repo, history_is_signed=True)
        self.assertTrue(status.required, "the commits being replaced are signed")
        self.assertTrue(status.available)
        self.assertFalse(status.must_refuse)
        self.assertEqual(sign_flags(status, "rebase"), ("--gpg-sign",))
        self.assertEqual(sign_flags(status, "commit-tree"), ("-S",))

    def test_signed_history_with_no_usable_key_is_a_refusal_not_a_downgrade(self):
        repo = self.signing_broken()
        _git(repo, "config", "--unset", "commit.gpgsign")
        status = signing_status(repo, history_is_signed=True)
        self.assertTrue(status.required)
        self.assertFalse(status.available)
        self.assertTrue(status.must_refuse)

    def test_unsigned_history_and_no_config_owes_nothing(self):
        status = signing_status(self.signing_off(), history_is_signed=False)
        self.assertFalse(status.required)
        self.assertFalse(status.must_refuse)


class TestSignaturePresenceIsReadFromTheObject(SigningFixture):
    """Presence, never `%G?`. That reports VERIFICATION, so a correctly signed ssh commit reads as
    `N` on any host with no `allowedSignersFile` — and a rewrite would strip a signature it had
    just decided was not there."""

    def test_a_signed_commit_counts_even_when_it_cannot_be_verified(self):
        repo = self.signing_works()
        head = _git(repo, "rev-parse", "HEAD~0").strip()
        _git(repo, "commit", "--allow-empty", "-qm", "signed")
        signed = _git(repo, "rev-parse", "HEAD").strip()
        self.assertIn("gpgsig", _headers(repo, signed))
        self.assertEqual(_git(repo, "log", "-1", "--format=%G?", signed).strip(), "N",
                         "this host cannot verify it, which must not mean unsigned")
        self.assertTrue(carries_signature(repo, signed))
        self.assertTrue(any_signed(repo, [head, signed]))

    def test_an_unsigned_commit_does_not_count(self):
        repo = self.signing_off()
        head = _git(repo, "rev-parse", "HEAD").strip()
        self.assertFalse(carries_signature(repo, head))
        self.assertFalse(any_signed(repo, [head]))

    def test_a_commit_git_cannot_read_is_not_evidence_of_nothing_signed(self):
        repo = self.signing_off()
        self.assertIsNone(carries_signature(repo, "0" * 40))
        self.assertTrue(any_signed(repo, ["0" * 40]))


if __name__ == "__main__":
    unittest.main()

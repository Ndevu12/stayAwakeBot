#!/usr/bin/env python3
"""With no signing set up, a rewrite signs with a key on this machine that GitHub lists as the
operator's signing key, never with any other key, and never asks for a passphrase."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.signing.commits import keys, sign_flags, signing_args, signing_status
from stayawake.lib.signing.commits.keys import agent_signing_key, public_key_of
from stayawake.utils.systembin import system_binary
from tests.lib.signing.test_commit_signing import (_GPG_THAT_FAILS, SigningFixture, _git, _headers,
                                                  _repo, _script)

_HAS_SSH_TOOLS = all(system_binary((f"/usr/bin/{tool}", f"/bin/{tool}"))
                     for tool in ("ssh-keygen", "ssh-add", "ssh-agent"))


def _key(folder: Path, name: str = "id_ed25519", passphrase: str = "") -> tuple[Path, str]:
    """Make an ed25519 key in `folder`. Returns its private key file and its public key line."""
    folder.mkdir(parents=True, exist_ok=True)
    private = folder / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-C", "saw-test",
                    "-f", str(private)], check=True, capture_output=True, stdin=subprocess.DEVNULL)
    return private, (folder / f"{name}.pub").read_text(encoding="utf-8").strip()


@unittest.skipUnless(_HAS_SSH_TOOLS, "needs the system's ssh-keygen, ssh-add and ssh-agent")
class TestAKeyYouHaveSigns(SigningFixture):
    def setUp(self):
        super().setUp()
        self.home = Path(tempfile.mkdtemp(prefix="saw-signhome-"))
        environment = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("SSH_AUTH_SOCK", None)
        self.operator_sets("gpg.program", str(_script(_GPG_THAT_FAILS)))
        self.repo = _repo()

    def _status(self, listed):
        return signing_status(self.repo, history_is_signed=True,
                              registered_signing_keys=lambda: listed)

    def _signs_a_commit(self, status) -> bool:
        _git(self.repo, *signing_args(status), "commit", "--allow-empty", "-qm", "signed",
             *sign_flags(status, "commit"))
        return "gpgsig" in _headers(self.repo)

    def _agent_holding(self, private: Path) -> None:
        started = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True, check=True).stdout
        agent = dict(re.findall(r"(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;]+);", started))
        self.addCleanup(subprocess.run, ["ssh-agent", "-k"], env={**os.environ, **agent},
                        capture_output=True)
        subprocess.run(["ssh-add", "-q", str(private)], env={**os.environ, **agent}, check=True,
                       capture_output=True, stdin=subprocess.DEVNULL)
        os.environ["SSH_AUTH_SOCK"] = agent["SSH_AUTH_SOCK"]

    def test_a_key_in_your_ssh_folder_that_github_lists_signs_the_rewrite(self):
        private, public = _key(self.home / ".ssh")
        status = self._status([public])
        self.assertTrue(status.available)
        self.assertEqual(dict(status.config)["user.signingkey"], str(private))
        self.assertTrue(self._signs_a_commit(status))

    def test_a_key_in_your_ssh_agent_that_github_lists_signs_the_rewrite(self):
        private, public = _key(Path(tempfile.mkdtemp(prefix="saw-agentkey-")))
        self._agent_holding(private)
        private.unlink()
        status = self._status([public])
        self.assertTrue(status.available)
        self.assertTrue(self._signs_a_commit(status))

    def test_a_key_github_does_not_list_is_never_used(self):
        _key(self.home / ".ssh")
        _other, listed = _key(Path(tempfile.mkdtemp(prefix="saw-otherkey-")))
        status = self._status([listed])
        self.assertTrue(status.signature_owed_but_unavailable)

    def test_a_key_that_needs_a_passphrase_is_skipped_without_asking(self):
        _private, public = _key(self.home / ".ssh", passphrase="not-typed-by-anyone")
        started = time.monotonic()
        status = self._status([public])
        self.assertTrue(status.signature_owed_but_unavailable)
        self.assertLess(time.monotonic() - started, 8)

    def test_github_is_not_asked_while_your_own_setup_signs(self):
        asked = mock.Mock(return_value=[])
        status = signing_status(self.signing_works(), history_is_signed=True,
                                registered_signing_keys=asked)
        self.assertTrue(status.available)
        asked.assert_not_called()

    def test_when_github_lists_no_key_nothing_on_this_machine_is_read(self):
        source = mock.Mock(return_value=[])
        with mock.patch.object(keys, "KEY_SOURCES", (source,)):
            status = self._status([])
        self.assertTrue(status.signature_owed_but_unavailable)
        source.assert_not_called()


class TestPublicKeys(unittest.TestCase):
    def test_a_public_key_line_is_read_without_its_comment(self):
        self.assertEqual(public_key_of("ssh-ed25519 AAAAC3Nz you@host"), "ssh-ed25519 AAAAC3Nz")

    def test_a_line_that_is_not_a_public_key_reads_as_none(self):
        for line in ("", "not a key", "The agent has no identities."):
            with self.subTest(line=line):
                self.assertIsNone(public_key_of(line))

    def test_an_agent_key_is_named_the_way_git_takes_it(self):
        self.assertEqual(agent_signing_key("ssh-ed25519 AAAA"), "ssh-ed25519 AAAA")
        self.assertEqual(agent_signing_key("ecdsa-sha2-nistp256 AAAA"),
                         "key::ecdsa-sha2-nistp256 AAAA")


if __name__ == "__main__":
    unittest.main()

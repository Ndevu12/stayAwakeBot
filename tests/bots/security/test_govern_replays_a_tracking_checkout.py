#!/usr/bin/env python3
"""Every governed git command replays from a checkout that tracks a remote, as git would run it."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from stayawake.lib.git import incoming
from tests.support.gitrepo import GitSandbox
from tests.support.local_remotes import allow_local_remotes


class _TrackingCheckout(GitSandbox):
    """A checkout cloned from a local upstream that has moved on since."""

    def setUp(self):
        super().setUp()
        allow_local_remotes(self)
        self.upstream = self.new_repo("upstream")
        self.write(self.upstream, "kept.txt", "kept\n")
        self.commit(self.upstream, "start")
        self.git(self.upstream, "branch", "feature")
        self.open = self.owned(self.root / "open")
        subprocess.run(["git", "clone", "-q", str(self.upstream), str(self.open)], check=True, capture_output=True)
        for key, value in (("user.name", "Operator"), ("user.email", "operator@example.invalid"),
                           ("commit.gpgsign", "false")):
            self.git(self.open, "config", key, value)
        self.write(self.upstream, "new.txt", "new\n")
        self.commit(self.upstream, "arrives")
        self.into = self.root / "holding"

    def _prepared(self, *args: str):
        arrived = incoming.prepare(self.open, self.into, "git", list(args))
        self.assertIsInstance(arrived, incoming.Arrived, f"{args}: {arrived}")
        return arrived

    def _copy_config(self) -> str:
        return (self.into / "repo.git" / "config").read_text()

class AReplayFromATrackingCheckout(_TrackingCheckout):

    def test_a_pull_brings_what_the_upstream_has(self):
        for args in (["pull"], ["pull", "--ff-only"], ["pull", "--rebase"], ["pull", "origin", "main"]):
            with self.subTest(args=args):
                self.assertIn("new.txt", self._prepared(*args).paths)

    def test_a_pull_follows_the_repositorys_own_rebase_setting(self):
        self.write(self.open, "local.txt", "local\n")
        self.commit(self.open, "local work")
        self.git(self.open, "config", "pull.rebase", "true")
        arrived = self._prepared("pull")
        self.assertIn("new.txt", arrived.paths)
        parents = self.git(arrived.root, "rev-list", "--parents", "-n", "1", arrived.commit).split()
        self.assertEqual(len(parents), 2, "a rebase makes no merge commit")

    def test_a_fetch_moves_the_remote_tracking_branch(self):
        for args in (["fetch"], ["fetch", "origin"], ["fetch", "--all"]):
            with self.subTest(args=args):
                moved = {ref for ref, _new, _old in self._prepared(*args).refs}
                self.assertIn("refs/remotes/origin/main", moved)

    def test_a_merge_that_makes_a_commit_carries_the_repositorys_identity(self):
        self.git(self.open, "fetch", "-q")
        arrived = self._prepared("merge", "--no-ff", "origin/main")
        author = self.git(arrived.root, "log", "-1", "--format=%an <%ae>", arrived.commit).strip()
        self.assertEqual(author, "Operator <operator@example.invalid>")

    def test_a_rebase_onto_the_upstream_brings_it(self):
        self.git(self.open, "fetch", "-q")
        self.write(self.open, "local.txt", "local\n")
        self.commit(self.open, "local work")
        self.assertIn("new.txt", self._prepared("rebase").paths)

    def test_a_branch_that_exists_only_on_the_remote_is_checked_out(self):
        for args in (["checkout", "feature"], ["switch", "feature"]):
            with self.subTest(args=args):
                self.assertIsInstance(incoming.prepare(self.open, self.into, "git", args), incoming.Arrived)

    def test_a_fetch_with_no_remote_is_never_reported_as_clean(self):
        self.git(self.open, "remote", "remove", "origin")
        for args in (["fetch"], ["fetch", "--all"]):
            with self.subTest(args=args):
                self.assertIsInstance(incoming.prepare(self.open, self.into, "git", args), str)

    def test_nothing_in_the_repositorys_config_that_runs_a_program_reaches_the_copy(self):
        for key, value in (("remote.origin.uploadpack", "touch /tmp/never"),
                           ("remote.origin.receivepack", "touch /tmp/never"),
                           ("remote.origin.proxy", "http://example.invalid"),
                           ("url.http://example.invalid/.insteadOf", "origin"),
                           ("core.sshCommand", "touch /tmp/never"),
                           ("core.fsmonitor", "touch /tmp/never")):
            self.git(self.open, "config", key, value)
        self._prepared("fetch")
        copied = self._copy_config().lower()
        for word in ("uploadpack", "receivepack", "proxy", "insteadof", "sshcommand", "fsmonitor", "/tmp/never"):
            self.assertNotIn(word, copied)
        self.assertIn("[remote \"origin\"]", copied)
        self.assertIn("[branch \"main\"]", copied)

    def test_a_remote_url_that_names_a_program_runs_nothing(self):
        mark = Path(tempfile.mkdtemp()) / "ran"
        self.git(self.open, "config", "remote.origin.url", f"ext::sh -c touch% {mark}")
        self.assertIsInstance(incoming.prepare(self.open, self.into, "git", ["fetch"]), str)
        self.assertFalse(mark.exists())

    def test_an_included_config_brings_nothing_into_the_copy(self):
        mark = Path(tempfile.mkdtemp()) / "ran"
        included = self.root / "included.cfg"
        included.write_text(f'[url "ext::sh -c touch% {mark}"]\n\tinsteadOf = {self.upstream}\n'
                            f'[remote "origin"]\n\tuploadpack = touch {mark}\n')
        self.git(self.open, "config", "include.path", str(included))
        incoming.prepare(self.open, self.into, "git", ["fetch"])
        copied = self._copy_config().lower()
        self.assertNotIn("insteadof", copied)
        self.assertNotIn("uploadpack", copied)
        self.assertFalse(mark.exists())


class AnUpdateSawCannotCheckIsTheUsersToDecide(_TrackingCheckout):

    def test_the_answer_offers_to_run_it_as_typed_or_leave_it(self):
        from stayawake.bots.security import govern
        self.git(self.open, "remote", "remove", "origin")
        payload, code = govern.prepare(str(self.open), str(self.into), "git", ["fetch"])
        self.assertEqual(code, 2)
        self.assertTrue(payload["reason"])
        self.assertEqual(payload["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
        self.assertEqual(payload["decision"]["scan_after"], ["saw", "scan", str(self.open)])

    def test_an_update_that_was_checked_carries_no_decision(self):
        from stayawake.bots.security import govern
        payload, _ = govern.prepare(str(self.open), str(self.into), "git", ["pull"])
        self.assertIn("scan", payload)
        self.assertNotIn("decision", payload)

    def test_a_check_that_reaches_its_deadline_is_the_users_to_decide(self):
        import time
        from unittest import mock
        from stayawake.bots.security import govern
        with mock.patch.object(govern, "scan_target", side_effect=lambda *a, **k: time.sleep(5)):
            payload, code = govern.prepare(str(self.open), str(self.into), "git", ["pull"], deadline=0.3)
        self.assertEqual(code, 2)
        self.assertIn("deadline", payload["reason"])
        self.assertIn("decision", payload)

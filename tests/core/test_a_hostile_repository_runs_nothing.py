#!/usr/bin/env python3
"""saw's git runs no program a scanned repository names. Every program the fixture repository names
leaves a marker; the tests drive saw over the repository and require that none was left."""
from __future__ import annotations

import io
import os
import subprocess
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.bots.security import remediator
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.query import fetch_refs
from stayawake.lib.git.run import GitRefused, run, stdout_bytes_fed
from stayawake.lib.git.write.push import PushResult
from tests.support.hostile_repo import HostileRepoSandbox
from tests.support.local_remotes import allow_local_remotes

try:
    from stayawake.bots.security.remediation import preserve as uncommitted_work
except ImportError:
    uncommitted_work = None

RAN = "saw's git ran programs the repository names"


def _quietly(call, *args, **kwargs):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return call(*args, **kwargs)


def _no_remote_tags(*_args, **_kwargs):
    return mock.Mock(returncode=0, stdout="", stderr="")


class TestTheHostileFixture(HostileRepoSandbox):
    """The fixture is armed, and silent until something runs."""

    def test_it_arms_every_trigger_and_nothing_has_run(self):
        hostile = self.hostile_repo()
        self.assertEqual([], hostile.fired())
        for expected in ("hook-post-checkout", "core.fsmonitor", "filter.clean",
                         "filter-named-a=b.clean", "filter.process", "diff.textconv",
                         "diff.command", "merge.driver", "merge-named-a=b.driver",
                         "includeIf.onbranch", "includeIf.gitdir", "include.path",
                         "url.insteadOf", "credential.helper", "gpg.program",
                         "core.sshCommand", "uploadpack.packObjectsHook", "refs-replace"):
            self.assertIn(expected, hostile.triggers)


class TestSawRunsNoRepositoryCode(HostileRepoSandbox):
    """Every verb that reaches git, driven end to end over the hostile repository."""

    maxDiff = None

    def _step(self, hostile, fired: dict, name: str, call, *args, **kwargs):
        hostile.clear()
        try:
            _quietly(call, *args, **kwargs)
        finally:
            if hostile.fired():
                fired[name] = hostile.fired()

    def test_no_verb_runs_a_program_the_repository_names(self):
        hostile = self.hostile_repo()
        allow_local_remotes(self)
        self._operator_signs_with_ssh()
        repo = str(hostile.repo)
        fired: dict[str, list[str]] = {}
        self._step(hostile, fired, "saw scan", cli.main, ["scan", "--json", repo])
        self._step(hostile, fired, "saw scan --history", cli.main,
                   ["scan", "--json", "--history", repo])
        self._step(hostile, fired, "fetch the remote refs", fetch_refs, repo)
        self._step(hostile, fired, "saw fix", remediator.fix, None, paths=[repo], no_stream=True)
        self._step(hostile, fired, "saw fix amend", self._amend, hostile)
        self.assertEqual({}, fired, RAN)

    def test_capturing_the_uncommitted_work_runs_no_program_the_repository_names(self):
        if uncommitted_work is None:
            self.skipTest("the uncommitted-work capture (remediation.preserve) is not on this "
                          "branch; this case runs once it is")
        hostile = self.hostile_repo()
        self.write(hostile.repo, "draft.txt", "work in progress\n")
        fired: dict[str, list[str]] = {}
        self._step(hostile, fired, "capture the uncommitted work",
                   uncommitted_work.preserve, str(hostile.repo))
        self.assertEqual({}, fired)

    def _operator_signs_with_ssh(self):
        """Give the operator a global configuration that signs with an ssh key."""
        key = self.owned(self.root / "operator-key")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       check=True, capture_output=True, stdin=subprocess.DEVNULL)
        config = self.owned(self.root / "operator-gitconfig")
        config.write_text("[user]\n\tname = Operator\n\temail = operator@example.test\n"
                          f"\tsigningkey = {key}\n[gpg]\n\tformat = ssh\n", encoding="utf-8")
        patched = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config)})
        patched.start()
        self.addCleanup(patched.stop)

    def _remote_head(self, hostile, branch: str):
        found = self.git_may_fail(hostile.repo, "rev-parse", "--verify", "-q",
                                  f"refs/remotes/origin/{branch}")
        return True, (found.stdout.strip() or None)

    def _amend(self, hostile):
        """`saw fix amend` on the local checkout, with its GitHub answers supplied and nothing
        pushed.
        """
        at = "stayawake.bots.security.pr.amend."
        with ExitStack() as stack:
            for target, patch in (
                ("gitutil.origin_slug", dict(return_value="acme/app")),
                ("authority.may_rewrite", dict(return_value=mock.Mock(
                    permitted=True, conclusive=True, reason="owner", detail=""))),
                ("authority.ref_protection", dict(return_value=mock.Mock(
                    protected=False, reason="rule_read"))),
                ("authority.fork_count", dict(return_value=0)),
                ("gitutil.fetch_refs", dict(return_value=mock.Mock(ok=True, reason=""))),
                ("_read_remote_head", dict(side_effect=lambda r, s, b, tk: (
                    self._remote_head(hostile, b)))),
                # The remote's tags, asked with `ls-remote`, which would leave the machine.
                ("gitremote.ls_remote", dict(side_effect=_no_remote_tags)),
            ):
                stack.enter_context(mock.patch(at + target, **patch))
            return amend_outcome(hostile.repo, "acme/app", ScanOptions(), load_signatures(), [],
                                 None, pusher=lambda branch, dest, lease: PushResult(True))



# Each subcommand saw may run over a repository it did not create, with its arguments and stdin.
_PLUMBING = (
    ("cat-file", ["cat-file", "-p", "HEAD"], None),
    ("cat-file --batch", ["cat-file", "--batch"], b"HEAD\n"),
    ("ls-tree", ["ls-tree", "-r", "HEAD"], None),
    ("rev-list", ["rev-list", "--all"], None),
    ("rev-parse", ["rev-parse", "HEAD"], None),
    ("for-each-ref", ["for-each-ref"], None),
    ("show-ref", ["show-ref"], None),
    ("merge-base", ["merge-base", "main", "conflict"], None),
    ("diff-tree", ["diff-tree", "--no-textconv", "--no-ext-diff", "-r", "-p", "HEAD~3", "HEAD"],
     None),
    ("diff", ["diff", "--no-textconv", "--no-ext-diff", "HEAD~3", "HEAD"], None),
    ("ls-files", ["ls-files"], None),
    ("hash-object", ["hash-object", "--no-filters", "notes.txt"], None),
    ("config --get", ["config", "--get", "core.fsmonitor"], None),
    ("config --list", ["config", "--list"], None),
    ("symbolic-ref", ["symbolic-ref", "HEAD"], None),
    ("read-tree", ["read-tree", "HEAD"], None),
    ("update-index", ["update-index", "-z", "--index-info"], b""),
    ("write-tree", ["write-tree"], None),
    ("mktree", ["mktree"], b""),
    ("commit-tree", ["commit-tree", "HEAD^{tree}", "-p", "HEAD", "-m", "plumbing"], None),
    ("update-ref", ["update-ref", "refs/saw-test/plumbing", "HEAD"], None),
)


class TestPlumbingRunsNoRepositoryCode(HostileRepoSandbox):
    """Each allowlisted subcommand, run through `stayawake.lib.git.run` over the hostile repo."""

    maxDiff = None

    def _fired_by_plumbing(self, hostile) -> dict[str, list[str]]:
        env = dict(os.environ, GIT_INDEX_FILE=str(self.owned(self.root / "private-index")))
        fired: dict[str, list[str]] = {}
        for name, args, stdin in _PLUMBING:
            hostile.clear()
            if stdin is None:
                run(hostile.repo, args, env=env)
            else:
                stdout_bytes_fed(hostile.repo, args, stdin, env=env)
            if hostile.fired():
                fired[name] = hostile.fired()
        return fired

    def test_no_allowlisted_subcommand_runs_a_program_the_repository_names(self):
        self.assertEqual({}, self._fired_by_plumbing(self.hostile_repo()), RAN)

    def test_a_subcommand_that_reads_the_working_tree_through_a_filter_is_refused(self):
        hostile = self.hostile_repo()
        env = dict(os.environ, GIT_INDEX_FILE=str(self.owned(self.root / "private-index")))
        for args in (["update-index", "--refresh"], ["status"], ["add", "-A"]):
            with self.subTest(args=args), self.assertRaises(GitRefused):
                run(hostile.repo, args, env=env)
        self.assertEqual([], hostile.fired())

    def test_a_redirected_worktree_runs_no_program_the_repository_names(self):
        hostile = self.hostile_repo(redirect_worktree=True)
        self.assertEqual({}, self._fired_by_plumbing(hostile), RAN)


if __name__ == "__main__":
    unittest.main()

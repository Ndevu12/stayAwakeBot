#!/usr/bin/env python3
"""saw's write work (fix, guard, push, fetch, amend's ref move, capture) runs no code the operator's
repository configures. Each test drives the real verb over a repository whose configured programs
leave a marker, and asserts the verb did its job and no marker was left."""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tests.support.gitrepo import GitSandbox
from tests.support.local_remotes import allow_local_remotes

from stayawake.bots.security import pr
from stayawake.bots.security.pr import fix as prfix
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from stayawake.core import proposal
from stayawake.lib.git import auth
from stayawake.lib.git.query import fetch_refs
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write import push as gitpush
from stayawake.lib.git.write.capture import capture_bundle

SIGNATURES = load_signatures()
INFECTED_GITIGNORE = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"
HOOKS = ("post-checkout", "reference-transaction", "pre-commit", "prepare-commit-msg",
         "commit-msg", "post-commit", "pre-push", "post-index-change", "pre-auto-gc",
         "post-rewrite", "push-to-checkout")


class HostileRepository(GitSandbox):
    PROTOCOLS = "file:ext"

    def setUp(self):
        super().setUp()
        self.sentinel = self.owned(self.root / "sentinel")
        self.sentinel.mkdir()
        self.remote = self.owned(self.root / "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)],
                       check=True, capture_output=True)
        self.op = self.new_repo("op")
        self.write(self.op, ".gitignore", INFECTED_GITIGNORE)
        self.write(self.op, "app.js", "console.log('ok');\n")
        self.write(self.op, ".gitattributes", "* filter=evil\n")
        self.base = self.commit(self.op, "init")
        self.git(self.op, "checkout", "-q", "-b", "next")
        self.write(self.op, "app.js", "console.log('next');\n")
        self.next = self.commit(self.op, "next")
        self.git(self.op, "checkout", "-q", "main")
        self.git(self.op, "remote", "add", "origin", str(self.remote))
        self.git(self.op, "push", "-q", "origin", "main")
        self.git(self.op, "fetch", "-q", "origin")
        self._arm()
        allow_local_remotes(self)
        local = mock.patch.object(auth, "run_remote_git",
                                  lambda slug, token, attempt: attempt(str(self.remote),
                                                                       dict(os.environ)))
        local.start()
        self.addCleanup(local.stop)
        pushed = mock.patch.object(gitpush, "run_remote_git", auth.run_remote_git)
        pushed.start()
        self.addCleanup(pushed.stop)

    def _script(self, name: str, tail: str = "") -> Path:
        path = self.owned(self.root / "armed" / name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\ntouch '{self.sentinel / name}'\n{tail}", encoding="utf-8")
        path.chmod(0o755)
        return path

    def _arm(self):
        hooks = self.op / ".git" / "hooks"
        for name in HOOKS:
            target = hooks / name
            target.write_text(f"#!/bin/sh\ntouch '{self.sentinel / name}'\n", encoding="utf-8")
            target.chmod(0o755)
        armed = {
            "filter.evil.smudge": f"{self._script('smudge', 'cat')}",
            "filter.evil.clean": f"{self._script('clean', 'cat')}",
            "core.fsmonitor": f"{self._script('fsmonitor', 'exit 1')}",
            "gpg.program": f"{self._script('gpg-program', 'exit 1')}",
            "commit.gpgsign": "true",
            "protocol.ext.allow": "always",
            f"url.ext::sh -c touch% {self.sentinel / 'ext'}.insteadOf": str(self.remote),
        }
        for key, value in armed.items():
            self.git(self.op, "config", key, value)

    def assertNothingRan(self):
        self.assertEqual([], sorted(p.name for p in self.sentinel.iterdir()),
                         "the operator's repository ran code on saw's behalf")

    def _fix_branch_tip(self) -> str:
        return self.git(self.op, "rev-parse", "--verify", "-q",
                        "refs/heads/security/auto-clean-main").strip()


class TestFixRunsNoRepositoryCode(HostileRepository):
    def test_preparing_the_fix_builds_the_branch_and_runs_nothing(self):
        with mock.patch.object(prfix.gitutil, "origin_slug", lambda repo: "acme/app"):
            outcome = pr.prepare_fix(self.op, ScanOptions(), SIGNATURES, [])
        self.assertIn("prepared 1 change", outcome)
        tip = self._fix_branch_tip()
        self.assertEqual(self.base, self.rev(self.op, f"{tip}^"))
        self.assertNotIn("temp_auto_push.bat", self.git(self.op, "cat-file", "blob",
                                                       f"{tip}:.gitignore"))
        self.assertNothingRan()

    def test_the_fix_commit_is_not_signed_by_the_repository_program(self):
        with mock.patch.object(prfix.gitutil, "origin_slug", lambda repo: "acme/app"):
            pr.prepare_fix(self.op, ScanOptions(), SIGNATURES, [])
        self.assertTrue(self._fix_branch_tip())
        self.assertFalse((self.sentinel / "gpg-program").exists(),
                         "a repo-local gpg.program ran while signing saw's commit")

    def test_opening_the_pr_pushes_the_branch_and_runs_nothing(self):
        with mock.patch.object(prfix.gitutil, "origin_slug", lambda repo: "acme/app"), \
             mock.patch.object(proposal.github_api, "open_or_update_pr",
                               return_value={"action": "created", "number": 7,
                                             "html_url": "u"}), \
             mock.patch.object(prfix.github_api, "add_labels"), \
             mock.patch.object(prfix.github_api, "remove_label"):
            outcome = pr.submit_fix_pr(self.op, ScanOptions(), SIGNATURES, [], token="t")
        self.assertIn("opened PR #7", outcome)
        self.assertEqual(self._fix_branch_tip(),
                         self.git(self.remote, "rev-parse", "refs/heads/security/auto-clean-main")
                         .strip())
        self.assertNothingRan()


class TestGuardRunsNoRepositoryCode(HostileRepository):
    def test_the_guard_pr_commits_the_workflow_and_runs_nothing(self):
        from stayawake.bots.security.guard import provision
        from stayawake.core.identity import Decision, Intent
        plan = provision.SetupPlan("create", ".github/workflows/worm-guard.yml",
                                   content="name: worm-guard\n", new_ref="a" * 40)
        allow = Decision(allowed=True, intent=Intent.OPEN_GUARD_PR)
        with mock.patch.object(provision.gitutil, "origin_slug", lambda repo: "acme/app"), \
             mock.patch("stayawake.core.identity.require", return_value=allow), \
             mock.patch.object(proposal.github_api, "open_or_update_pr",
                               return_value={"action": "created", "number": 3,
                                             "html_url": "u"}):
            result = provision._setup_pr(self.op, plan, "main", "t", False)
        self.assertIsNone(result.error, result.error)
        pushed = self.git(self.remote, "show",
                          f"refs/heads/{provision.SETUP_BRANCH}:.github/workflows/worm-guard.yml")
        self.assertEqual("name: worm-guard\n", pushed)
        self.assertNothingRan()


class TestNetworkRunsNoRepositoryCode(HostileRepository):
    def _advance_remote(self) -> str:
        other = self.owned(self.root / "other")
        subprocess.run(["git", "clone", "-q", str(self.remote), str(other)], check=True,
                       capture_output=True)
        self.git(other, "config", "user.name", "O")
        self.git(other, "config", "user.email", "o@o.test")
        self.write(other, "later.js", "later\n")
        tip = self.commit(other, "later")
        self.git(other, "push", "-q", "origin", "main", "main:extra")
        return tip

    def test_fetch_refreshes_remote_branches_and_runs_nothing(self):
        tip = self._advance_remote()
        result = fetch_refs(self.op)
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(tip, self.rev(self.op, "refs/remotes/origin/main"))
        self.assertEqual(tip, self.rev(self.op, "refs/remotes/origin/extra"))
        self.git(self.op, "cat-file", "-e", f"{tip}^{{tree}}")
        self.assertNothingRan()

    def test_deleting_a_remote_branch_runs_nothing(self):
        self._advance_remote()
        self.assertTrue(gitpush.delete_remote_branch("origin", "extra", repo=self.op))
        self.assertEqual("", self.git(self.remote, "for-each-ref", "refs/heads/extra").strip())
        self.assertNothingRan()

    def test_publishing_a_local_branch_runs_nothing(self):
        result = gitpush.publish_head(self.op, "acme/app", "next", "t", dest="aside")
        self.assertTrue(result.ok, result.stderr)
        self.assertEqual(self.next, self.rev(self.remote, "refs/heads/aside"))
        self.assertNothingRan()


class TestAmendRunsNoRepositoryCode(HostileRepository):
    def test_the_dirty_check_reads_a_clean_tree_as_clean_and_runs_nothing(self):
        self.assertFalse(gitamend.is_dirty(self.op))
        self.assertNothingRan()

    def test_the_dirty_check_sees_an_edit(self):
        (self.op / "app.js").write_text("edited\n", encoding="utf-8")
        self.assertTrue(gitamend.is_dirty(self.op))
        self.assertNothingRan()

    def test_the_dirty_check_sees_an_untracked_file(self):
        (self.op / "new.js").write_text("new\n", encoding="utf-8")
        self.assertTrue(gitamend.is_dirty(self.op))

    def test_moving_a_checked_out_branch_moves_its_tree_and_runs_nothing(self):
        self.assertTrue(gitamend.point_branch_at(self.op, "main", self.next, self.base))
        self.assertEqual(self.next, self.rev(self.op, "refs/heads/main"))
        self.assertEqual("console.log('next');\n", (self.op / "app.js").read_text())
        self.assertFalse(gitamend.is_dirty(self.op))
        self.assertNothingRan()

    def test_capture_writes_a_verified_bundle_and_runs_nothing(self):
        captured = capture_bundle(self.op, [(self.next, self.base)],
                                  self.root / "capture" / "c.bundle")
        self.assertTrue(captured.ok, captured.reason)
        self.assertTrue(captured.verified)
        self.assertNothingRan()


if __name__ == "__main__":
    unittest.main()

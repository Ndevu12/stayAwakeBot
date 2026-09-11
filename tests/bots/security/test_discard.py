#!/usr/bin/env python3
"""`saw discard --branch` deletes every auto-clean branch, including on a remote by slug."""
from __future__ import annotations

import contextlib
import subprocess
from unittest import mock

from stayawake.bots.security.pr import discard as discardmod
from stayawake.bots.security.pr.constants import FIX_BRANCH
from stayawake.lib import git as gitutil
from tests.support.gitrepo import GitSandbox


class TestDiscardRemoteBranch(GitSandbox):
    def _bare_with(self, *heads: str):
        remote = self.owned(self.root / "acme" / "app.git")
        remote.parent.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       check=True, capture_output=True)
        work = self.new_repo("work")
        self.write(work, "a", "1\n")
        self.commit(work, "init")
        self.git(work, "remote", "add", "origin", str(remote))
        self.git(work, "push", "-q", "origin", "HEAD:main")
        for head in heads:
            self.git(work, "push", "-q", "origin", f"HEAD:{head}")
        return remote

    def _aim_at(self, remote):
        def run_remote(_slug, _token, attempt):
            return attempt(str(remote), None)

        @contextlib.contextmanager
        def gh_remote(_slug, _token):
            yield str(remote), None

        return (mock.patch.object(discardmod.gitutil, "run_remote_git", run_remote),
                mock.patch.object(discardmod.gitutil, "github_remote", gh_remote))

    def test_deletes_every_auto_clean_branch_not_only_the_original_name(self):
        remote = self._bare_with(f"{FIX_BRANCH}-main", f"{FIX_BRANCH}-develop")
        run_p, gh_p = self._aim_at(remote)
        with run_p, gh_p:
            out = discardmod.discard_remote_branch("acme/app", "tok")
        self.assertIn("discarded", out)
        self.assertIn(f"remote {FIX_BRANCH}-main", out)
        self.assertIn(f"remote {FIX_BRANCH}-develop", out)
        self.assertFalse(gitutil.remote_has_branch(str(remote), f"{FIX_BRANCH}-main"))
        self.assertFalse(gitutil.remote_has_branch(str(remote), f"{FIX_BRANCH}-develop"))
        self.assertTrue(gitutil.remote_has_branch(str(remote), "main"))

    def test_a_listing_that_cannot_run_is_not_nothing_to_discard(self):
        def run_remote(_slug, _token, attempt):
            return attempt("/no/such/remote.git", None)

        with mock.patch.object(discardmod.gitutil, "run_remote_git", run_remote):
            out = discardmod.discard_remote_branch("acme/app", "tok")
        self.assertIn("FAILED", out)
        self.assertNotIn("nothing to discard", out)

    def test_looking_only_for_the_original_name_would_leave_the_others(self):
        remote = self._bare_with(f"{FIX_BRANCH}-main")
        run_p, gh_p = self._aim_at(remote)
        with run_p, gh_p:
            stale = _only_the_original_name("acme/app", "tok")
            self.assertIn("nothing to discard", stale)
            self.assertTrue(gitutil.remote_has_branch(str(remote), f"{FIX_BRANCH}-main"))
            live = discardmod.discard_remote_branch("acme/app", "tok")
        self.assertIn("discarded", live)
        self.assertFalse(gitutil.remote_has_branch(str(remote), f"{FIX_BRANCH}-main"))


def _only_the_original_name(slug, token):
    """The previous by-slug path — used to prove the live function does not still do this."""
    with discardmod.gitutil.github_remote(slug, token) as (url, env):
        if not discardmod.gitutil.remote_has_branch(url, FIX_BRANCH, env=env):
            return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"
        ok = discardmod.gitutil.delete_remote_branch(url, FIX_BRANCH, env=env)
    return f"{slug}: deleted {FIX_BRANCH}" if ok else f"{slug}: remote delete failed"


class TestDiscardRemotePr(GitSandbox):
    def test_closes_a_pr_whose_head_is_not_the_original_name(self):
        closed = []

        def listed(_slug, _token):
            return [f"{FIX_BRANCH}-main"]

        def pulls(_owner, _repo, head, _token, head_owner=None):
            return [{"number": 9}] if head == f"{FIX_BRANCH}-main" else []

        with mock.patch.object(discardmod, "_listed_on_github", listed), \
                mock.patch.object(discardmod.github_api, "list_open_pulls", pulls), \
                mock.patch.object(discardmod.github_api, "close_pull",
                                  side_effect=lambda *a: closed.append(a) or True):
            out = discardmod.discard_remote_pr("acme/app", "tok")
        self.assertIn("#9", out)
        self.assertEqual(closed[0][2], 9)


class TestDiscardBranchStillSweepsOrigin(GitSandbox):
    def test_local_discard_deletes_the_family_on_origin(self):
        remote = self.owned(self.root / "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       check=True, capture_output=True)
        work = self.new_repo("work")
        self.write(work, "a", "1\n")
        self.commit(work, "init")
        self.git(work, "remote", "add", "origin", str(remote))
        self.git(work, "push", "-q", "origin", "HEAD:main")
        self.git(work, "branch", f"{FIX_BRANCH}-main")
        self.git(work, "push", "-q", "origin", f"{FIX_BRANCH}-main")
        out = discardmod.discard_branch(work)
        self.assertIn("discarded", out)
        self.assertFalse(gitutil.ref_exists(work, f"refs/heads/{FIX_BRANCH}-main"))
        self.assertFalse(gitutil.remote_has_branch("origin", f"{FIX_BRANCH}-main", repo=work))
        self.assertTrue(gitutil.remote_has_branch("origin", "main", repo=work))

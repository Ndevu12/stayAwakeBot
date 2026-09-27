#!/usr/bin/env python3
"""lib.git.write — the mutation helpers, exercised against REAL local git repos (no network).

The headline is `commit_fix`: the historical `saw fix` bug was a commit whose return code went
unchecked, so when signing couldn't complete the commit silently failed and the branch stayed
EMPTY while the caller reported a prepared fix. These tests pin the fix: signing failure → the
commit still lands (unsigned) and the branch advances; only a genuine commit failure returns
committed=False (never a phantom empty branch).

The fix is built in a checkout saw owns (`add_worktree`) and lands on the operator's branch when
committed; the operator's own global config decides the signer.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib import git as gitutil
from stayawake.lib.git.write.commit import CommitResult
from tests.support.local_remotes import allow_local_remotes

BRANCH = "security/auto-clean"


def _init(files: dict[str, str]) -> Path:
    """A git repo on `main` with an initial (unsigned) commit of `files`."""
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", "-b", "main", str(d)], check=True, capture_output=True)
    for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(d), *cmd], check=True, capture_output=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(d), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(d), "-c", "commit.gpgsign=false", "commit", "-qm", "init"],
                   check=True, capture_output=True)
    return d


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                          text=True).stdout.strip()


def _branch_commits(repo: Path) -> int:
    out = _git(repo, "rev-list", "--count", f"refs/heads/{BRANCH}")
    return int(out) if out.isdigit() else 0


class _OperatorConfig(unittest.TestCase):
    """The operator's global git config is a file this test writes, never the host's."""

    def setUp(self):
        super().setUp()
        self.home = Path(tempfile.mkdtemp())
        self.global_config = self.home / "gitconfig"
        self.global_config.write_text("", encoding="utf-8")
        isolated = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(self.global_config),
                                                "GIT_CONFIG_SYSTEM": os.devnull})
        isolated.start()
        self.addCleanup(isolated.stop)

    def operator_sets(self, key: str, value: str) -> None:
        subprocess.run(["git", "config", "--file", str(self.global_config), key, value],
                       check=True, capture_output=True)

    def checkout(self, d: Path) -> Path:
        wt = Path(tempfile.mkdtemp()) / "wt"
        self.assertTrue(gitutil.add_worktree(d, wt, BRANCH, "main"))
        self.addCleanup(gitutil.remove_worktree, d, wt)
        return wt


def _failing_signer() -> Path:
    signer = Path(tempfile.mkdtemp()) / "fail-sign.sh"
    signer.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    signer.chmod(0o755)
    return signer


class TestCommitFix(_OperatorConfig):
    def test_lands_signed_when_config_allows(self):
        # Nothing forces signing → the first attempt succeeds and is reported "signed"
        # (nothing forced off → no warning), and the operator's branch advances.
        d = _init({"app.js": "ok\n"})
        wt = self.checkout(d)
        before = _branch_commits(d)
        (wt / "app.js").write_text("fixed\n", encoding="utf-8")
        self.assertTrue(gitutil.stage_all(wt))
        res = gitutil.commit_fix(wt, "security: fix")
        self.assertEqual(res, CommitResult(committed=True, signed=True))
        self.assertEqual(_branch_commits(d), before + 1)
        self.assertEqual(_git(d, "show", f"refs/heads/{BRANCH}:app.js"), "fixed")

    def test_lands_unsigned_when_signing_fails(self):
        # THE REGRESSION: signing can't complete → commit_fix retries with gpgsign=false so the
        # fix STILL lands (branch advances), and reports it unsigned so the caller can warn.
        d = _init({"app.js": "ok\n"})
        subprocess.run(["git", "-C", str(d), "config", "commit.gpgsign", "true"], check=True)
        self.operator_sets("gpg.program", str(_failing_signer()))
        wt = self.checkout(d)
        before = _branch_commits(d)
        (wt / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(wt)
        res = gitutil.commit_fix(wt, "security: fix")
        self.assertTrue(res.committed, "fix must land even when signing fails (no empty branch)")
        self.assertFalse(res.signed, "a forced-off signature must be reported unsigned")
        self.assertEqual(_branch_commits(d), before + 1)

    def test_signs_with_the_operators_global_key(self):
        d = _init({"app.js": "ok\n"})
        key = Path(tempfile.mkdtemp()) / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "saw-test",
                        "-f", str(key)], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        self.operator_sets("commit.gpgsign", "true")
        self.operator_sets("gpg.format", "ssh")
        self.operator_sets("user.signingkey", str(key))
        wt = self.checkout(d)
        (wt / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(wt)
        self.assertEqual(gitutil.commit_fix(wt, "security: fix"),
                         CommitResult(committed=True, signed=True))
        self.assertIn("gpgsig", _git(d, "cat-file", "commit", f"refs/heads/{BRANCH}"))

    def test_a_repository_signer_program_is_never_run(self):
        d = _init({"app.js": "ok\n"})
        ran = Path(tempfile.mkdtemp()) / "ran"
        program = Path(tempfile.mkdtemp()) / "signer.sh"
        program.write_text(f"#!/bin/sh\ntouch '{ran}'\nexit 1\n", encoding="utf-8")
        program.chmod(0o755)
        for key, value in (("commit.gpgsign", "true"), ("gpg.program", str(program))):
            subprocess.run(["git", "-C", str(d), "config", key, value], check=True)
        wt = self.checkout(d)
        (wt / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(wt)
        self.assertTrue(gitutil.commit_fix(wt, "security: fix").committed)
        self.assertFalse(ran.exists())

    def test_reports_failure_when_nothing_to_commit(self):
        # Both attempts fail (clean tree, nothing staged) → committed=False and the branch does
        # NOT advance. An honest failure, never a claimed-but-empty commit.
        d = _init({"app.js": "ok\n"})
        wt = self.checkout(d)
        before = _branch_commits(d)
        res = gitutil.commit_fix(wt, "security: fix")
        self.assertEqual(res, CommitResult(committed=False, signed=False))
        self.assertEqual(_branch_commits(d), before)

    def test_bot_identity_authors_the_commit(self):
        d = _init({"app.js": "ok\n"})
        wt = self.checkout(d)
        (wt / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(wt)
        gitutil.commit_fix(wt, "security: fix")
        self.assertEqual(_git(d, "log", "-1", "--format=%an <%ae>", f"refs/heads/{BRANCH}"),
                         "StayAwakeBot Security <security-bot@stayawake.local>")

    def test_staging_and_committing_refuse_a_directory_saw_did_not_make(self):
        d = _init({"app.js": "ok\n"})
        (d / "app.js").write_text("fixed\n", encoding="utf-8")
        self.assertFalse(gitutil.stage_all(d))
        self.assertEqual(gitutil.commit_fix(d, "security: fix"),
                         CommitResult(committed=False, signed=False))


class TestWorktree(_OperatorConfig):
    def test_add_then_remove_keeps_branch(self):
        d = _init({"a.txt": "1\n"})
        wt = Path(tempfile.mkdtemp()) / "wt"
        self.assertTrue(gitutil.add_worktree(d, wt, BRANCH, "main"))
        self.assertTrue((wt / "a.txt").is_file())                        # checked out
        self.assertTrue(gitutil.ref_exists(d, f"refs/heads/{BRANCH}"))
        self.assertTrue(gitutil.remove_worktree(d, wt))
        self.assertFalse(wt.exists())                                    # checkout gone
        self.assertTrue(gitutil.ref_exists(d, f"refs/heads/{BRANCH}"))    # branch persists

    def test_add_worktree_fails_on_bad_baseref(self):
        d = _init({"a.txt": "1\n"})
        wt = Path(tempfile.mkdtemp()) / "wt"
        self.assertFalse(gitutil.add_worktree(d, wt, BRANCH, "no-such-ref"))

    def test_the_checkout_holds_the_bytes_the_commit_records(self):
        d = _init({"a.txt": "1\n"})
        (d / ".gitattributes").write_text("*.txt text eol=crlf\n", encoding="utf-8")
        _git(d, "add", "-A")
        _git(d, "-c", "commit.gpgsign=false", "commit", "-qm", "attrs")
        wt = self.checkout(d)
        self.assertEqual((wt / "a.txt").read_bytes(), b"1\n")


class TestReadHelpers(_OperatorConfig):
    def test_ref_exists(self):
        d = _init({"a": "1\n"})
        self.assertTrue(gitutil.ref_exists(d, "HEAD"))
        self.assertTrue(gitutil.ref_exists(d, "main"))
        self.assertFalse(gitutil.ref_exists(d, "definitely-not-a-ref"))

    def test_default_branch_falls_back_without_origin(self):
        d = _init({"a": "1\n"})
        self.assertEqual(gitutil.default_branch(d), "main")   # no origin/HEAD → fallback

    def test_origin_slug(self):
        d = _init({"a": "1\n"})
        self.assertIsNone(gitutil.origin_slug(d))             # no origin
        subprocess.run(["git", "-C", str(d), "remote", "add", "origin",
                        "git@github.com:o/r.git"], check=True, capture_output=True)
        self.assertEqual(gitutil.origin_slug(d), "o/r")

    def test_tracked_under_and_unstage_cached(self):
        d = _init({"keep.txt": "1\n", "q/bak.txt": "x\n"})   # q/ is committed (tracked)
        wt = self.checkout(d)
        self.assertTrue(gitutil.tracked_under(wt, "q"))
        self.assertTrue(gitutil.unstage_cached(wt, "q"))
        self.assertEqual(gitutil.tracked_under(wt, "q"), [])  # untracked now
        self.assertTrue((wt / "q" / "bak.txt").is_file())     # …but still on disk (rm --cached)


class TestStageAndPatch(_OperatorConfig):
    def test_stage_all_then_format_patch(self):
        d = _init({"a.txt": "1\n"})
        wt = self.checkout(d)
        (wt / "a.txt").write_text("2\n", encoding="utf-8")
        self.assertTrue(gitutil.stage_all(wt))
        self.assertTrue(gitutil.commit_fix(wt, "change a").committed)
        patch = gitutil.format_patch(wt, "HEAD")
        self.assertIsNotNone(patch)
        self.assertIn("change a", patch)      # the subject
        self.assertIn("+2", patch)            # the added line
        self.assertEqual(patch, gitutil.format_patch(d, f"refs/heads/{BRANCH}"))

    def test_format_patch_none_when_no_commit(self):
        # A repo with no HEAD → nothing to format → None (never a bogus empty patch).
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", "-b", "main", str(d)], check=True, capture_output=True)
        self.assertIsNone(gitutil.format_patch(d, "HEAD"))


class TestBranchAndRemote(_OperatorConfig):
    def setUp(self):
        super().setUp()
        allow_local_remotes(self)

    def test_delete_branch(self):
        d = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(d), "branch", "tmp"], check=True, capture_output=True)
        self.assertTrue(gitutil.ref_exists(d, "refs/heads/tmp"))
        self.assertTrue(gitutil.delete_branch(d, "tmp"))
        self.assertFalse(gitutil.ref_exists(d, "refs/heads/tmp"))

    def test_a_checked_out_branch_is_not_deleted(self):
        d = _init({"a": "1\n"})
        self.assertFalse(gitutil.delete_branch(d, "main"))
        self.assertTrue(gitutil.ref_exists(d, "refs/heads/main"))

    def _pushed_work(self) -> tuple[Path, Path]:
        remote = Path(tempfile.mkdtemp()) / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       check=True, capture_output=True)
        work = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(remote)],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"],
                       check=True, capture_output=True)
        return remote, work

    def test_remote_has_branch_and_delete(self):
        _remote, work = self._pushed_work()
        self.assertTrue(gitutil.remote_has_branch("origin", "main", repo=work))
        self.assertFalse(gitutil.remote_has_branch("origin", "nope", repo=work))
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main:doomed"],
                       check=True, capture_output=True)
        self.assertTrue(gitutil.remote_has_branch("origin", "doomed", repo=work))
        self.assertTrue(gitutil.delete_remote_branch("origin", "doomed", repo=work))
        self.assertFalse(gitutil.remote_has_branch("origin", "doomed", repo=work))

    def test_remote_has_branch_by_url_no_local_repo(self):
        remote, _work = self._pushed_work()
        self.assertTrue(gitutil.remote_has_branch(str(remote), "main"))   # repo=None
        self.assertFalse(gitutil.remote_has_branch(str(remote), "nope"))

    def test_remote_branches_matching_none_when_unreachable(self):
        work = _init({"a": "1\n"})
        self.assertIsNone(gitutil.remote_branches_matching("origin", "security/auto-clean*",
                                                           repo=work))
        self.assertEqual(gitutil.remote_branches_matching(str(work), "no-such-head*", repo=None),
                         [])

    def test_a_remote_that_names_a_command_is_refused(self):
        work = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(work), "remote", "add", "origin",
                        "ext::sh -c touch% /nonexistent/saw"], check=True, capture_output=True)
        self.assertFalse(gitutil.delete_remote_branch("origin", "x", repo=work))
        self.assertIsNone(gitutil.remote_branches_matching("origin", "x*", repo=work))


class TestRemoteAddress(unittest.TestCase):
    """Which addresses saw lets git reach: the operator-push protocols, and nothing that git would
    hand to a helper program or run on this host."""

    def test_network_addresses_are_accepted(self):
        from stayawake.lib.git.remote import checked_url
        for url in ("https://github.com/o/r.git", "ssh://git@github.com/o/r.git",
                    "git@github.com:o/r.git"):
            self.assertEqual(checked_url(url), url)

    def test_helper_transports_local_paths_and_options_are_refused(self):
        from stayawake.lib.git.remote import checked_url
        for url in ("ext::sh -c touch% /tmp/x", "fd::3", "file:///srv/r.git", "/srv/r.git",
                    "./r.git", "-uhack", "http://github.com/o/r.git", "https://x\n", ""):
            self.assertIsNone(checked_url(url), url)


class TestPushBranch(_OperatorConfig):
    """The refspec each push verb hands git: by commit id, to a full heads ref."""

    def setUp(self):
        super().setUp()
        self.repo = _init({"a": "1\n"})
        _git(self.repo, "branch", BRANCH)
        self.tip = _git(self.repo, "rev-parse", "HEAD")
        self.gitpush = importlib.import_module("stayawake.lib.git.write.push")

    def _capture(self, call):
        seen = []
        real = self.gitpush.run

        def fake_run(repo, args, **kw):
            if args[:1] == ["push"]:
                seen.append(list(args))
                return subprocess.CompletedProcess(args, 0, "", "")
            return real(repo, args, **kw)

        remote = lambda slug, token, attempt: attempt("https://github.com/acme/app.git", {})
        with mock.patch.object(self.gitpush, "run", fake_run), \
             mock.patch.object(self.gitpush, "run_remote_git", remote):
            result = call(self.gitpush)
        return result, seen

    def test_publishes_the_named_branch(self):
        res, seen = self._capture(lambda p: p.push_branch_result(self.repo, "acme/app", BRANCH,
                                                                 "tok"))
        self.assertTrue(res.ok)
        args = seen[0]
        self.assertEqual(args[0], "push")
        self.assertTrue(all(not a.startswith("--force") for a in args))
        self.assertEqual(args[-1], f"{self.tip}:refs/heads/{BRANCH}")

    def test_pr_push_does_not_take_a_lease(self):
        from stayawake.lib.git.write.push import push_branch_result
        with self.assertRaises(TypeError):
            push_branch_result(self.repo, "acme/app", BRANCH, "tok", lease="abc")

    def test_pr_push_does_not_take_force(self):
        from stayawake.lib.git.write.push import push_branch_result
        with self.assertRaises(TypeError):
            push_branch_result(self.repo, "acme/app", BRANCH, "tok", force=True)

    def test_force_update_head_is_not_the_pr_push(self):
        res, seen = self._capture(lambda p: p.force_update_head(self.repo, "acme/app", "main",
                                                                "tok", lease="abc"))
        self.assertTrue(res.ok)
        args = seen[0]
        self.assertTrue(any(a.startswith("--force-with-lease=refs/heads/main:") for a in args))
        self.assertEqual(args[-1], f"{self.tip}:refs/heads/main")
        self.assertNotIn("--force", args)

    def test_force_update_head_without_a_lease_does_not_push(self):
        res, seen = self._capture(lambda p: p.force_update_head(self.repo, "acme/app", "main",
                                                                "tok", lease=""))
        self.assertFalse(res.ok)
        self.assertEqual(seen, [])

    def test_publish_head_does_not_force(self):
        _git(self.repo, "branch", "also")
        res, seen = self._capture(lambda p: p.publish_head(self.repo, "acme/app", "also", "tok"))
        self.assertTrue(res.ok)
        args = seen[0]
        self.assertTrue(all(not a.startswith("--force") for a in args))
        self.assertEqual(args[-1], f"{self.tip}:refs/heads/also")

    def test_a_branch_the_repository_does_not_have_is_not_pushed(self):
        res, seen = self._capture(lambda p: p.publish_head(self.repo, "acme/app", "absent",
                                                           "tok"))
        self.assertFalse(res.ok)
        self.assertEqual(seen, [])


if __name__ == "__main__":
    unittest.main()

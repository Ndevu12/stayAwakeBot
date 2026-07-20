#!/usr/bin/env python3
"""core.git.write — the mutation helpers, exercised against REAL local git repos (no network).

The headline is `commit_fix`: the historical `saw fix` bug was a commit whose return code went
unchecked, so when `commit.gpgsign=true` couldn't sign in the throwaway worktree the commit
silently failed and the branch stayed EMPTY while the caller reported a prepared fix. These
tests pin the fix: signing failure → the commit still lands (unsigned) and the branch advances;
only a genuine commit failure returns committed=False (never a phantom empty branch)."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib import git as gitutil
from stayawake.lib.git.write.commit import CommitResult


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


def _demand_failing_signing(repo: Path) -> None:
    """Configure `repo` to REQUIRE signed commits via a signer program that always fails — so
    the next signed commit aborts exactly as a real worktree with an unavailable key would."""
    signer = Path(tempfile.mkdtemp()) / "fail-sign.sh"
    signer.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    signer.chmod(0o755)
    for cmd in (["config", "commit.gpgsign", "true"], ["config", "gpg.program", str(signer)]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, capture_output=True)


def _commit_count(repo: Path) -> int:
    out = subprocess.run(["git", "-C", str(repo), "rev-list", "--count", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else 0


class TestCommitFix(unittest.TestCase):
    def test_lands_signed_when_config_allows(self):
        # Repo doesn't force signing → the first attempt succeeds and is reported "signed"
        # (i.e. committed under the repo's own config, nothing forced off → no warning).
        d = _init({"app.js": "ok\n"})
        before = _commit_count(d)
        (d / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(d)
        res = gitutil.commit_fix(d, "security: fix")
        self.assertEqual(res, CommitResult(committed=True, signed=True))
        self.assertEqual(_commit_count(d), before + 1)      # branch advanced

    def test_lands_unsigned_when_signing_fails(self):
        # THE REGRESSION: signing can't complete → commit_fix retries with gpgsign=false so the
        # fix STILL lands (branch advances), and reports it unsigned so the caller can warn.
        d = _init({"app.js": "ok\n"})
        _demand_failing_signing(d)
        before = _commit_count(d)
        (d / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(d)
        res = gitutil.commit_fix(d, "security: fix")
        self.assertTrue(res.committed, "fix must land even when signing fails (no empty branch)")
        self.assertFalse(res.signed, "a forced-off signature must be reported unsigned")
        self.assertEqual(_commit_count(d), before + 1)      # <-- not a phantom empty branch

    def test_reports_failure_when_nothing_to_commit(self):
        # Both attempts fail (clean tree, nothing staged) → committed=False and the branch does
        # NOT advance. An honest failure, never a claimed-but-empty commit.
        d = _init({"app.js": "ok\n"})
        before = _commit_count(d)
        res = gitutil.commit_fix(d, "security: fix")
        self.assertEqual(res, CommitResult(committed=False, signed=False))
        self.assertEqual(_commit_count(d), before)

    def test_bot_identity_authors_the_commit(self):
        d = _init({"app.js": "ok\n"})
        (d / "app.js").write_text("fixed\n", encoding="utf-8")
        gitutil.stage_all(d)
        gitutil.commit_fix(d, "security: fix")
        author = subprocess.run(["git", "-C", str(d), "log", "-1", "--format=%an <%ae>"],
                                capture_output=True, text=True).stdout.strip()
        self.assertEqual(author, "StayAwakeBot Security <security-bot@stayawake.local>")


class TestWorktree(unittest.TestCase):
    def test_add_then_remove_keeps_branch(self):
        d = _init({"a.txt": "1\n"})
        wt = Path(tempfile.mkdtemp()) / "wt"
        self.assertTrue(gitutil.add_worktree(d, wt, "security/auto-clean", "main"))
        self.assertTrue((wt / "a.txt").is_file())                        # checked out
        self.assertTrue(gitutil.ref_exists(d, "refs/heads/security/auto-clean"))
        self.assertTrue(gitutil.remove_worktree(d, wt))
        self.assertFalse(wt.exists())                                    # worktree gone
        self.assertTrue(gitutil.ref_exists(d, "refs/heads/security/auto-clean"))  # branch persists

    def test_add_worktree_fails_on_bad_baseref(self):
        d = _init({"a.txt": "1\n"})
        wt = Path(tempfile.mkdtemp()) / "wt"
        self.assertFalse(gitutil.add_worktree(d, wt, "security/auto-clean", "no-such-ref"))


class TestReadHelpers(unittest.TestCase):
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
        self.assertTrue(gitutil.tracked_under(d, "q"))
        self.assertTrue(gitutil.unstage_cached(d, "q"))
        self.assertEqual(gitutil.tracked_under(d, "q"), [])  # untracked now
        self.assertTrue((d / "q" / "bak.txt").is_file())     # …but still on disk (rm --cached)


class TestStageAndPatch(unittest.TestCase):
    def test_stage_all_then_format_patch(self):
        d = _init({"a.txt": "1\n"})
        (d / "a.txt").write_text("2\n", encoding="utf-8")
        self.assertTrue(gitutil.stage_all(d))
        self.assertTrue(gitutil.commit_fix(d, "change a").committed)
        patch = gitutil.format_patch(d, "HEAD")
        self.assertIsNotNone(patch)
        self.assertIn("change a", patch)      # the subject
        self.assertIn("+2", patch)            # the added line

    def test_format_patch_none_when_no_commit(self):
        # A bare repo with no HEAD → nothing to format → None (never a bogus empty patch).
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", "-b", "main", str(d)], check=True, capture_output=True)
        self.assertIsNone(gitutil.format_patch(d, "HEAD"))


class TestBranchAndRemote(unittest.TestCase):
    def test_delete_branch(self):
        d = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(d), "branch", "tmp"], check=True, capture_output=True)
        self.assertTrue(gitutil.ref_exists(d, "refs/heads/tmp"))
        self.assertTrue(gitutil.delete_branch(d, "tmp"))
        self.assertFalse(gitutil.ref_exists(d, "refs/heads/tmp"))

    def test_remote_has_branch_and_delete(self):
        remote = Path(tempfile.mkdtemp()) / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       check=True, capture_output=True)
        work = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(remote)],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"],
                       check=True, capture_output=True)
        # via the origin remote (repo context)
        self.assertTrue(gitutil.remote_has_branch("origin", "main", repo=work))
        self.assertFalse(gitutil.remote_has_branch("origin", "nope", repo=work))
        # push a throwaway branch and delete it on the remote
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main:doomed"],
                       check=True, capture_output=True)
        self.assertTrue(gitutil.remote_has_branch("origin", "doomed", repo=work))
        self.assertTrue(gitutil.delete_remote_branch("origin", "doomed", repo=work))
        self.assertFalse(gitutil.remote_has_branch("origin", "doomed", repo=work))

    def test_remote_has_branch_by_url_no_local_repo(self):
        # The repo=None path (run.py drops `-C`): query an explicit remote path with no clone.
        remote = Path(tempfile.mkdtemp()) / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       check=True, capture_output=True)
        work = _init({"a": "1\n"})
        subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(remote)],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(work), "push", "-q", "origin", "main"],
                       check=True, capture_output=True)
        self.assertTrue(gitutil.remote_has_branch(str(remote), "main"))   # repo=None
        self.assertFalse(gitutil.remote_has_branch(str(remote), "nope"))


if __name__ == "__main__":
    unittest.main()

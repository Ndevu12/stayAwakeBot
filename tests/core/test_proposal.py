#!/usr/bin/env python3
"""Unit tests for core.proposal — the shared "propose a change as a reviewed PR" ladder.

The ladder was extracted from pr.py so both `saw fix` and `saw guard setup` reuse ONE hardened
implementation (push → fork → patch → dedup-issue). test_pr.py still exercises it through `saw fix`
(integration); these tests hit `submit_change_pr` / `file_dedup_issue` directly, so the ladder's
own branches are covered independently of any caller.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.core import proposal
from stayawake.lib.git.write.push import PushResult


def _git(**over):
    """Patch proposal.gitutil.* — default: upstream push succeeds, patch capture yields a body.

    `push_branch` overrides are auto-wrapped into `push_branch_result` (PushResult) so the
    AuthZ classification path keeps the old bool seam used by these tests.
    """
    base = {"push_branch": lambda repo, slug, branch, token, **k: True,
            "format_patch": lambda repo, ref="HEAD": "From abc\nSubject: x\n\nbody\n"}
    base.update(over)
    push_fn = base.get("push_branch")
    if "push_branch_result" not in base and push_fn is not None:
        def _as_result(repo, slug, branch, token, **k):
            ok = bool(push_fn(repo, slug, branch, token, **k))
            return PushResult(ok, "" if ok else "mocked push failure")
        base["push_branch_result"] = _as_result
    return [mock.patch.object(proposal.gitutil, n, f) for n, f in base.items()]


def _api(**over):
    # bind `f` per-iteration (default arg) — a bare closure would late-bind to the last value.
    return [mock.patch.object(proposal.github_api, n,
                              f if callable(f) else (lambda *a, _f=f, **k: _f))
            for n, f in over.items()]


def _run(git=None, api=None, *, issue=None, patches_dir=None):
    with tempfile.TemporaryDirectory() as wt:
        with mock.patch.object(proposal.time, "sleep", return_value=None):
            for p in _git(**(git or {})) + _api(**(api or {})):
                p.start()
            try:
                return proposal.submit_change_pr(
                    Path(wt), "up/repo", "main", branch="security/x",
                    title="t", body="b", token="tok", issue=issue, patches_dir=patches_dir)
            finally:
                mock.patch.stopall()


class TestUpstreamPr(unittest.TestCase):
    def test_open(self):
        res = _run(api={"open_or_update_pr": {"action": "opened", "number": 5, "html_url": "u"}})
        self.assertEqual((res.kind, res.action, res.number, res.url), ("pr", "opened", 5, "u"))

    def test_update(self):
        res = _run(api={"open_or_update_pr": {"action": "updated", "number": 7, "html_url": "u7"}})
        self.assertEqual((res.kind, res.action, res.number), ("pr", "updated", 7))

    def test_pr_api_failure(self):
        res = _run(api={"open_or_update_pr": None})
        self.assertEqual(res.kind, "pr-create-failed")


class TestForkRung(unittest.TestCase):
    # Upstream push is rejected; a fork under the authed user is attempted.
    def _fork_run(self, *, user, fork, repo_ready=True, fork_push_ok=True, created_pr=None,
                  patches_dir=None, issue=None):
        def push(repo, slug, branch, token, **k):
            return slug != "up/repo" and fork_push_ok          # upstream fails; fork per flag
        api = {"get_authenticated_user": user, "create_fork": fork,
               "get_repo": ({"x": 1} if repo_ready else None),
               "open_or_update_pr": created_pr,
               "list_open_issues": [], "create_issue": {"number": 9, "html_url": "iu"}}
        return _run(git={"push_branch": push}, api=api, patches_dir=patches_dir, issue=issue)

    def test_opens_cross_fork_pr(self):
        res = self._fork_run(user={"login": "me"}, fork={"full_name": "me/repo"},
                             created_pr={"action": "opened", "number": 11, "html_url": "fu"})
        self.assertEqual((res.kind, res.number, res.fork_slug), ("fork-pr", 11, "me/repo"))

    def test_fork_not_ready(self):
        res = self._fork_run(user={"login": "me"}, fork={"full_name": "me/repo"}, repo_ready=False)
        self.assertEqual((res.kind, res.fork_slug), ("fork-not-ready", "me/repo"))

    def test_fork_pr_creation_fails(self):
        res = self._fork_run(user={"login": "me"}, fork={"full_name": "me/repo"}, created_pr=None)
        self.assertEqual(res.kind, "fork-pr-create-failed")

    def test_own_repo_falls_to_floor(self):
        out = Path(tempfile.mkdtemp())
        res = self._fork_run(user={"login": "up"}, fork={"full_name": "up/repo"}, patches_dir=out,
                             issue=proposal.IssueSpec("t", "b", "lbl"))
        self.assertEqual(res.kind, "floor")
        self.assertTrue((out / "up-repo.patch").is_file())     # patch floor
        self.assertIn("#9", res.issue_note)                    # dedup issue filed

    def test_auth_failure_skips_fork_straight_to_floor(self):
        # #1291: a rejected CREDENTIAL can't push to a fork either (same token), so we must NOT
        # attempt the fork — go straight to the patch/issue floor. Assert create_fork is never called
        # and the reason carried to the floor is `auth`, not a fork-derived one.
        out = Path(tempfile.mkdtemp())
        fork_mock = mock.MagicMock(return_value={"full_name": "me/repo"})
        authed_mock = mock.MagicMock(return_value={"login": "me"})

        def push_result(repo, slug, branch, token, **k):
            return PushResult(False, "fatal: Authentication failed for 'https://github.com/up/repo.git/'")

        with tempfile.TemporaryDirectory() as wt:
            with mock.patch.object(proposal.time, "sleep", return_value=None):
                for p in (_git(push_branch_result=push_result)
                          + _api(get_authenticated_user=authed_mock, create_fork=fork_mock,
                                 list_open_issues=[], create_issue={"number": 9, "html_url": "iu"})):
                    p.start()
                try:
                    res = proposal.submit_change_pr(
                        Path(wt), "up/repo", "main", branch="security/x", title="t", body="b",
                        token="tok", issue=proposal.IssueSpec("t", "b", "lbl"), patches_dir=out)
                finally:
                    mock.patch.stopall()
        self.assertEqual(res.kind, "floor")
        self.assertEqual(res.push_reason, "auth")
        self.assertFalse(fork_mock.called)      # fork NOT attempted with a dead credential
        self.assertFalse(authed_mock.called)    # ...not even the identity probe that precedes it
        self.assertTrue((out / "up-repo.patch").is_file())


class TestFloor(unittest.TestCase):
    def test_patch_and_issue(self):
        out = Path(tempfile.mkdtemp())
        res = _run(git={"push_branch": lambda *a, **k: False},
                   api={"get_authenticated_user": None, "list_open_issues": [],
                        "create_issue": {"number": 5, "html_url": "iu"}},
                   issue=proposal.IssueSpec("t", "b", "lbl"), patches_dir=out)
        self.assertEqual(res.kind, "floor")
        self.assertTrue((out / "up-repo.patch").is_file())
        self.assertIn("opened issue #5", res.issue_note)


class TestDedupIssue(unittest.TestCase):
    def test_existing_issue_not_duplicated(self):
        with mock.patch.object(proposal.github_api, "list_open_issues", return_value=[{"number": 3}]), \
             mock.patch.object(proposal.github_api, "create_issue") as create:
            note = proposal.file_dedup_issue("o", "n", proposal.IssueSpec("t", "b", "lbl"), "tok")
        create.assert_not_called()
        self.assertIn("already tracks", note)
        self.assertIn("#3", note)

    def test_opens_when_none(self):
        with mock.patch.object(proposal.github_api, "list_open_issues", return_value=[]), \
             mock.patch.object(proposal.github_api, "create_issue",
                               return_value={"number": 8, "html_url": "u"}):
            note = proposal.file_dedup_issue("o", "n", proposal.IssueSpec("t", "b", "lbl"), "tok")
        self.assertIn("opened issue #8", note)


if __name__ == "__main__":
    unittest.main()

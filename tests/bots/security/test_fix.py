#!/usr/bin/env python3
"""`saw fix` (local-branch by default, --pr to publish) + `saw discard` + scan read-only (#1076).

#1076: `saw fix` PREPARES the fix on a local `security/auto-clean` branch and stops (no push,
no API) — `--pr` publishes via `submit_fix_pr`; `--remote` sweeps GitHub. Anything that hits
the API is pre-flighted (no force-pushes when the API is down). `saw discard` is the inverse:
`--branch` deletes the auto-clean branch (git), `--pr` closes its PR. `scan` stays read-only.
"""
from __future__ import annotations

import inspect
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import service, remediator
from stayawake.bots.security import pr as pr_submit
from stayawake.core.adapters import github_api

# A CONFIRMED, auto-fixable finding: the worm's .gitignore auto-push markers.
INFECTED_FILES = {".gitignore": "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"}


def _git_repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def _commit_repo(files: dict[str, str]) -> Path:
    d = _git_repo(files)
    for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"],
                ["config", "commit.gpgsign", "false"]):
        subprocess.run(["git", "-C", str(d), *cmd], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(d), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(d), "commit", "-qm", "init"], check=True, capture_output=True)
    return d


class TestConfigOptional(unittest.TestCase):
    def test_no_config_falls_back_to_current_repo_no_crash(self):
        # #1054: `saw fix` with no config must not raise; it falls back to the enclosing repo.
        d = _git_repo(INFECTED_FILES)
        cwd = os.getcwd()
        try:
            os.chdir(d)
            with mock.patch.object(remediator.pr_submit, "prepare_fix",
                                   return_value="repo: prepared 1 change(s)") as m_prep:
                rc = remediator.fix(None, no_stream=True)
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        m_prep.assert_called()                 # the current repo was processed (prepare, no push)

    def test_missing_explicit_config_is_clean_exit_2(self):
        self.assertEqual(remediator.fix("definitely-not-here.yml"), 2)


class TestFixLocal(unittest.TestCase):
    def test_default_fix_prepares_a_branch_no_push(self):
        d = _git_repo(INFECTED_FILES)
        before = (d / ".gitignore").read_text()
        with mock.patch.object(remediator.pr_submit, "prepare_fix",
                               return_value="repo: prepared 1 change(s) on 'security/auto-clean'") as m_prep, \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr") as m_pub:
            rc = remediator.fix(None, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m_prep.assert_called_once()            # default = prepare a local branch
        m_pub.assert_not_called()              # no push / no PR
        self.assertEqual((d / ".gitignore").read_text(), before)   # working tree untouched

    def test_pr_publishes_via_submit_fix_pr(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(remediator.github_api, "get_authenticated_user", return_value={"login": "me"}), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr",
                               return_value="repo: opened PR #1 (url)") as m_pub, \
             mock.patch.object(remediator.pr_submit, "prepare_fix") as m_prep:
            rc = remediator.fix(None, pr=True, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m_pub.assert_called_once()             # --pr = publish
        m_prep.assert_not_called()

    def test_pr_preflight_failure_publishes_nothing(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(remediator.github_api, "token_is_valid", return_value=False), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr") as m_pub:
            rc = remediator.fix(None, pr=True, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m_pub.assert_not_called()              # pre-flight aborts before any push

    def test_aborted_repo_makes_exit_one(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.pr_submit, "prepare_fix",
                               return_value="repo: ABORTED — 1 finding still present"):
            self.assertEqual(remediator.fix(None, paths=[str(d)], no_stream=True), 1)

    def test_partial_repo_makes_exit_one(self):
        # A PARTIAL fix (#1183) shipped safe changes but the tree isn't clean → exit non-zero.
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.pr_submit, "prepare_fix",
                               return_value="repo: PARTIAL — prepared 1 safe change(s), 2 need review"):
            self.assertEqual(remediator.fix(None, paths=[str(d)], no_stream=True), 1)


class TestTokenIsValid(unittest.TestCase):
    """github_api.token_is_valid — the fail-closed preflight primitive (#1176).

    `GET /user` is `enabledForGitHubApps: false`, so the Actions installation `GITHUB_TOKEN`
    can't validate through it. token_is_valid falls back to `/repos/{slug}` and `/rate_limit`
    (both `enabledForGitHubApps: true`). The invariant these lock: a live, GitHub-accepted token
    passes; an empty/bogus token or an unreachable API is REJECTED (never fail-open)."""

    def test_empty_token_rejected(self):
        self.assertFalse(github_api.token_is_valid(None, "o/r"))
        self.assertFalse(github_api.token_is_valid("", "o/r"))

    def test_user_token_passes_via_user_and_short_circuits(self):
        with mock.patch.object(github_api, "get_authenticated_user", return_value={"login": "me"}), \
             mock.patch.object(github_api, "get_repo") as m_repo, \
             mock.patch.object(github_api, "request") as m_req:
            self.assertTrue(github_api.token_is_valid("pat", "o/r"))
        m_repo.assert_not_called()      # /user succeeded → no further probes
        m_req.assert_not_called()

    def test_installation_token_passes_via_repo(self):
        # The regression case: /user 403s (None) but the repo the token is scoped to resolves.
        with mock.patch.object(github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(github_api, "get_repo", return_value={"full_name": "o/r"}) as m_repo, \
             mock.patch.object(github_api, "request") as m_req:
            self.assertTrue(github_api.token_is_valid("ghs_inst", "o/r"))
        m_repo.assert_called_once_with("o", "r", "ghs_inst")
        m_req.assert_not_called()       # /repos succeeded → no need for the rate_limit floor

    def test_installation_token_liveness_floor_when_no_repo_context(self):
        # No repo_slug (e.g. GITHUB_REPOSITORY unset) but a live token → /rate_limit floor.
        with mock.patch.object(github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(github_api, "get_repo") as m_repo, \
             mock.patch.object(github_api, "request", return_value={"rate": {}}) as m_req:
            self.assertTrue(github_api.token_is_valid("ghs_inst", None))
        m_repo.assert_not_called()      # no slug → skip the repo probe
        m_req.assert_called_once()      # fell through to /rate_limit

    def test_known_repo_context_requires_repo_access(self):
        # When a repo context is known (repo_slug present), get_repo IS the check: a token that
        # can't reach it (404/403 → None) is REJECTED, and we do NOT fall through to /rate_limit
        # (caps probes at two, and requires real reachability when we have a repo to check).
        with mock.patch.object(github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(github_api, "get_repo", return_value=None), \
             mock.patch.object(github_api, "request", return_value={"rate": {}}) as m_req:
            self.assertFalse(github_api.token_is_valid("ghs_inst", "o/r"))
        m_req.assert_not_called()       # no /rate_limit fall-through when a repo is known

    def test_bogus_token_rejected_everywhere(self):
        # The fail-open guard: a bogus token 401s on /user, /repos AND /rate_limit → all None.
        with mock.patch.object(github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(github_api, "get_repo", return_value=None), \
             mock.patch.object(github_api, "request", return_value=None):
            self.assertFalse(github_api.token_is_valid("bogus", "o/r"))

    def test_unreachable_api_rejected(self):
        # SSL/network failure: request() returns None everywhere → rejected, so the preflight
        # still catches a broken environment before force-pushing anything.
        with mock.patch.object(github_api, "get_authenticated_user", return_value=None), \
             mock.patch.object(github_api, "get_repo", return_value=None), \
             mock.patch.object(github_api, "request", return_value=None):
            self.assertFalse(github_api.token_is_valid("t", None))


class TestDiscard(unittest.TestCase):
    def test_bare_discard_requires_a_flag(self):
        self.assertEqual(remediator.discard(None, no_stream=True), 2)

    def test_discard_branch_deletes_the_local_branch(self):
        d = _commit_repo(INFECTED_FILES)
        subprocess.run(["git", "-C", str(d), "branch", pr_submit.FIX_BRANCH],
                       check=True, capture_output=True)
        out = pr_submit.discard_branch(d)      # no origin → local only
        self.assertIn("discarded", out)
        gone = subprocess.run(["git", "-C", str(d), "rev-parse", "--verify", "--quiet",
                               f"refs/heads/{pr_submit.FIX_BRANCH}"], capture_output=True)
        self.assertNotEqual(gone.returncode, 0)              # branch is gone

    def test_discard_branch_with_no_branch_is_noop(self):
        d = _commit_repo(INFECTED_FILES)
        self.assertIn("nothing to discard", pr_submit.discard_branch(d))

    def test_discard_branch_routes_per_repo(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.pr_submit, "discard_branch",
                               return_value="repo: discarded security/auto-clean (local)") as m:
            rc = remediator.discard(None, branch=True, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m.assert_called_once()

    def test_discard_pr_preflight_failure_closes_nothing(self):
        d = _git_repo(INFECTED_FILES)
        with mock.patch.object(remediator.auth, "resolve_token", return_value=("t", "env")), \
             mock.patch.object(remediator.github_api, "token_is_valid", return_value=False), \
             mock.patch.object(remediator.pr_submit, "discard_pr") as m:
            rc = remediator.discard(None, pr=True, paths=[str(d)], no_stream=True)
        self.assertEqual(rc, 0)
        m.assert_not_called()                  # pre-flight failed → no API close attempted


class TestScanIsReadOnly(unittest.TestCase):
    def test_scan_signature_has_no_remediation_params(self):
        params = inspect.signature(service.scan).parameters
        for gone in ("fix", "apply", "open_pr", "local_only"):
            self.assertNotIn(gone, params, f"scan must not expose {gone!r} anymore")
        self.assertIn("remote", params)

    def test_bare_scan_never_writes(self):
        d = _git_repo(INFECTED_FILES)
        before = (d / ".gitignore").read_text()
        rc = service.scan(None, paths=[str(d)], no_stream=True)     # read-only
        self.assertEqual((d / ".gitignore").read_text(), before)   # unchanged
        self.assertEqual(rc, 1)                                     # infected → exit 1


if __name__ == "__main__":
    unittest.main()

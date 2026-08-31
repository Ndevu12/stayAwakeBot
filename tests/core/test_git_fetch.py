#!/usr/bin/env python3
"""`fetch_refs` — the refresh that makes `branches_carrying` complete, against REAL local git
repos (a directory stands in for the remote; no network, no credentials).

The defect it closes: remote-tracking refs exist only for branches this clone fetched, so a
branch created on the remote after the clone — or excluded by a `--single-branch` clone's
refspec — carries the infected commit invisibly, and the sweep reports it force-updated every
carrier when it never saw them. These tests pin the enumeration before/after the refresh, that
a deleted remote branch stops counting, and that a fetch which does NOT happen is reported as a
refusal with a reason rather than a smaller branch set.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git.query import branches_carrying, fetch_refs
from stayawake.lib.git.run import run as real_run, NETWORK_TIMEOUT


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(["git", "-C", str(repo), *args],
                         check=True, capture_output=True, text=True)
    return res.stdout.strip()


class _Fixture(unittest.TestCase):
    def _tmpdir(self) -> Path:
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def _remote_carrying_payload(self) -> tuple[Path, str]:
        """A repo on `main` whose only commit is the infected one; returns (path, sha)."""
        d = self._tmpdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(d)],
                       check=True, capture_output=True)
        for cfg in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
            _git(d, "config", *cfg)
        (d / "app.js").write_text("payload\n", encoding="utf-8")
        _git(d, "add", "-A")
        _git(d, "commit", "-qm", "infected")
        return d, _git(d, "rev-parse", "HEAD")

    def _clone(self, remote: Path, *extra: str) -> Path:
        dst = self._tmpdir() / "clone"
        subprocess.run(["git", "clone", "-q", *extra, str(remote), str(dst)],
                       check=True, capture_output=True)
        return dst

    def _carriers(self, repo: Path, sha: str) -> set[str]:
        return {name for name, _tip, _cas in branches_carrying(repo, sha)}


class TestFetchMakesCarriersVisible(_Fixture):
    def test_branch_created_after_a_single_branch_clone_is_invisible_until_fetch(self):
        remote, sha = self._remote_carrying_payload()
        clone = self._clone(remote, "--single-branch", "--branch", "main")
        _git(remote, "branch", "late-carrier", "main")

        self.assertNotIn("late-carrier", self._carriers(clone, sha),
                         "precondition: the branch must be invisible before any fetch")

        # A bare fetch honours the clone's own narrow refspec, so it does NOT close the gap —
        # this is what makes the explicit refspec in `fetch_refs` load-bearing, not decoration.
        self.assertEqual(_git(clone, "config", "--get", "remote.origin.fetch"),
                         "+refs/heads/main:refs/remotes/origin/main")
        subprocess.run(["git", "-C", str(clone), "fetch", "--prune", "origin"],
                       check=True, capture_output=True)
        self.assertNotIn("late-carrier", self._carriers(clone, sha))

        head_before = _git(clone, "rev-parse", "HEAD")
        result = fetch_refs(clone)

        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.reason, "")
        self.assertIn("late-carrier", self._carriers(clone, sha),
                      "the branch that only the refresh can reveal must now be enumerated")
        self.assertEqual(_git(clone, "rev-parse", "HEAD"), head_before,
                         "the refresh writes remote-tracking refs only, never the local head")

    def test_branch_created_after_a_full_clone_is_invisible_until_fetch(self):
        remote, sha = self._remote_carrying_payload()
        clone = self._clone(remote)
        _git(remote, "branch", "late-carrier", "main")

        self.assertEqual(self._carriers(clone, sha), {"main"})
        self.assertTrue(fetch_refs(clone).ok)
        self.assertEqual(self._carriers(clone, sha), {"main", "late-carrier"})

    def test_prune_drops_a_branch_deleted_on_the_remote(self):
        remote, sha = self._remote_carrying_payload()
        _git(remote, "branch", "gone", "main")
        clone = self._clone(remote)
        self.assertIn("gone", self._carriers(clone, sha))

        _git(remote, "branch", "-D", "gone")
        self.assertTrue(fetch_refs(clone).ok)

        self.assertNotIn("gone", self._carriers(clone, sha),
                         "a branch deleted on the remote must stop counting as a carrier")
        self.assertIn("main", self._carriers(clone, sha))


class TestFailureIsARefusal(_Fixture):
    def test_repo_without_a_remote_is_a_refusal(self):
        solo, _sha = self._remote_carrying_payload()
        result = fetch_refs(solo)
        self.assertFalse(result.ok)
        self.assertTrue(result.reason.strip(), "a refusal must carry a reason")

    def test_unreachable_remote_is_a_refusal_and_leaves_the_known_branches_intact(self):
        remote, sha = self._remote_carrying_payload()
        _git(remote, "branch", "known", "main")
        clone = self._clone(remote)
        shutil.rmtree(remote)

        result = fetch_refs(clone)

        self.assertFalse(result.ok)
        self.assertTrue(result.reason.strip())
        self.assertEqual(self._carriers(clone, sha), {"main", "known"},
                         "a failed fetch must not silently prune the refs we already had")

    def test_git_that_cannot_run_is_a_refusal(self):
        remote, _sha = self._remote_carrying_payload()
        clone = self._clone(remote)
        with mock.patch("stayawake.lib.git.query.run", return_value=None):
            result = fetch_refs(clone)
        self.assertFalse(result.ok)
        self.assertTrue(result.reason.strip())

    def test_nonexistent_repo_path_never_raises(self):
        result = fetch_refs(Path(tempfile.gettempdir()) / "saw-absent-repo-a9f3")
        self.assertFalse(result.ok)
        self.assertTrue(result.reason.strip())


class TestCredentialSafety(_Fixture):
    def _capture_fetch_call(self, repo: Path, token: str) -> dict:
        """Run `fetch_refs` for real, recording the argv/env/timeout it hands the runner."""
        seen: dict = {}

        def recording_run(r, args, **kwargs):
            seen.update(repo=r, args=args, kwargs=kwargs)
            return real_run(r, args, **kwargs)

        with mock.patch("stayawake.lib.git.query.run", side_effect=recording_run):
            seen["result"] = fetch_refs(repo, token=token)
        return seen

    def test_token_reaches_the_child_env_only_never_argv(self):
        remote, _sha = self._remote_carrying_payload()
        clone = self._clone(remote)
        token = "ghp_SUPERSECRET_0123456789"

        seen = self._capture_fetch_call(clone, token)

        self.assertTrue(seen["result"].ok, seen["result"].reason)
        self.assertNotIn(token, " ".join(seen["args"]),
                         "the token must never appear in git's argv (it is visible in `ps`)")
        env = seen["kwargs"].get("env") or {}
        if os.name != "nt":
            self.assertEqual(env.get("SAB_GH_TOKEN"), token,
                             "auth must go through github_https_auth, not a second mechanism")
            self.assertIn("GIT_ASKPASS", env)
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0",
                         "a credential prompt would hang the fetch instead of failing it")

    def test_fetch_is_bounded_by_the_network_timeout(self):
        remote, _sha = self._remote_carrying_payload()
        clone = self._clone(remote)
        seen = self._capture_fetch_call(clone, "ghp_TIMEOUT_PROBE")
        self.assertEqual(seen["kwargs"].get("timeout"), NETWORK_TIMEOUT)

    def test_reason_is_scrubbed_of_the_token(self):
        remote, _sha = self._remote_carrying_payload()
        clone = self._clone(remote)
        _git(clone, "remote", "set-url", "origin", "https://github.com/owner/name.git")
        token = "ghp_LEAKED_9876543210"
        leaky = subprocess.CompletedProcess(
            args=["git", "fetch"], returncode=128,
            stdout="", stderr=f"fatal: could not read from https://x-access-token:{token}@...")

        with mock.patch("stayawake.lib.git.query.run", return_value=leaky) as ran:
            result = fetch_refs(clone, token=token)

        self.assertFalse(result.ok)
        self.assertTrue(result.reason.strip())
        self.assertNotIn(token, result.reason,
                         "git's own message may carry the credential; a reason gets logged")
        self.assertNotIn(token, " ".join(ran.call_args.args[1]))


if __name__ == "__main__":
    unittest.main()

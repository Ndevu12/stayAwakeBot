#!/usr/bin/env python3
"""#1327 — `saw fix` / `saw guard` adopt the shared concurrency seam (THREAD backend). These pin the
invariants that must survive concurrency: SUBMISSION-order determinism (`-j1` == `-jN`), fail-closed
isolation (one repo's failure never drops a peer and still flags needs-review), and NO cross-repo
token bleed (each repo acts with its own credential). Network/PR work is mocked; the sweep is real."""
from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.guard import sweep as guard_sweep
from stayawake.bots.security.guard.detect import GuardStatus
from stayawake.bots.security.targets import ScanOptions
from stayawake.utils.streaming import Streamer


def _commit_repo(name: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix=f"sweep-{name}-"))
    (d / "x.js").write_text("const x = 1;\n", encoding="utf-8")
    for cmd in (["init", "-q", str(d)],):
        subprocess.run(["git", *cmd], check=True, capture_output=True)
    for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"],
                ["config", "commit.gpgsign", "false"], ["add", "-A"], ["commit", "-qm", "init"]):
        subprocess.run(["git", "-C", str(d), *cmd], check=True, capture_output=True)
    return d


def _quiet_streamer() -> Streamer:
    return Streamer(enabled=False, out=io.StringIO())


class TestFixSweepDeterminism(unittest.TestCase):
    def setUp(self):
        self.repos = [_commit_repo(str(i)) for i in range(6)]
        self.paths = [str(r) for r in self.repos]
        self.addCleanup(lambda: [__import__("shutil").rmtree(r, ignore_errors=True)
                                 for r in self.repos])

    def _fix_local_outcomes(self, jobs):
        # Deterministic per-repo outcome keyed on the repo path, so ordering is observable.
        def prepare(repo, *a, **k):
            return f"{remediator._disp(repo)}: prepared"
        with mock.patch.object(remediator.pr_submit, "prepare_fix", side_effect=prepare):
            return remediator._fix_local({}, ScanOptions(), [], [], self.paths,
                                         _quiet_streamer(), publish=False, jobs=jobs)

    def test_j1_equals_jN_byte_for_byte(self):
        seq = self._fix_local_outcomes(jobs=1)
        par = self._fix_local_outcomes(jobs=4)
        self.assertEqual(len(seq), 6)
        self.assertEqual(seq, par, "the per-repo outcome list must be identical (submission order) "
                                   "whether run at -j1 or -j4")

    def test_every_repo_processed_exactly_once(self):
        calls = []
        with mock.patch.object(remediator.pr_submit, "prepare_fix",
                               side_effect=lambda repo, *a, **k: calls.append(Path(repo).name) or "ok"):
            remediator._fix_local({}, ScanOptions(), [], [], self.paths,
                                  _quiet_streamer(), publish=False, jobs=4)
        # By basename — discover_local_repos resolves /private/var on macOS. No drops, no dupes.
        self.assertEqual(sorted(calls), sorted(Path(p).name for p in self.paths))


class TestFixSweepFailClosed(unittest.TestCase):
    def test_one_repo_raising_is_isolated_and_flags_needs_review(self):
        repos = [_commit_repo(f"fc{i}") for i in range(4)]
        self.addCleanup(lambda: [__import__("shutil").rmtree(r, ignore_errors=True) for r in repos])
        paths = [str(r) for r in repos]
        bad_name = repos[1].name          # match by basename — discover resolves /private/var on macOS

        def prepare(repo, *a, **k):
            if Path(repo).name == bad_name:
                raise RuntimeError("kaboom")
            return f"{remediator._disp(repo)}: prepared"

        with mock.patch.object(remediator.pr_submit, "prepare_fix", side_effect=prepare):
            # _fix_local isolates the failure into a needs-review string...
            outcomes = remediator._fix_local({}, ScanOptions(), [], [], paths,
                                             _quiet_streamer(), publish=False, jobs=4)
        self.assertEqual(len(outcomes), 4, "a raising repo must not drop its peers")
        self.assertTrue(any(": error" in o for o in outcomes))
        # ...and fix() maps any needs-review outcome to a non-zero exit.
        with mock.patch.object(remediator.pr_submit, "prepare_fix", side_effect=prepare):
            rc = remediator.fix(None, paths=paths, no_stream=True, jobs=4)
        self.assertEqual(rc, 1)


class TestFixRemoteNoTokenBleed(unittest.TestCase):
    def test_each_repo_acts_with_its_own_installation_token(self):
        slugs = ["o/r0", "o/r1", "o/r2", "o/r3"]
        seen: dict[str, str] = {}

        @contextlib.contextmanager
        def fake_clone(slug, tok):
            yield Path(f"/tmp/clone-{slug.replace('/', '_')}")

        def fake_submit(clone, opts, sigs, allowlist, token, *, spin):
            # Record the (repo, token) pair the sweep handed this worker.
            seen[str(clone)] = token
            return f"{clone}: ok"

        with mock.patch.object(remediator, "_resolve_remote",
                               return_value=(slugs, "base", "github-app")), \
             mock.patch.object(remediator, "_preflight", return_value=None), \
             mock.patch.object(remediator.auth, "act_token",
                               side_effect=lambda base, src, slug: (f"tok-{slug}", None)), \
             mock.patch.object(remediator.resolution, "cloned_repo", side_effect=fake_clone), \
             mock.patch.object(remediator.pr_submit, "submit_fix_pr", side_effect=fake_submit):
            outcomes = remediator._fix_remote({}, ScanOptions(), [], [], _quiet_streamer(),
                                              slugs=slugs, jobs=4)
        self.assertEqual(len(outcomes), 4)
        # Every clone was submitted with the token minted for ITS slug — no cross-repo bleed.
        for slug in slugs:
            clone = f"/tmp/clone-{slug.replace('/', '_')}"
            self.assertEqual(seen[clone], f"tok-{slug}")


class TestGuardCheckDeterminism(unittest.TestCase):
    def setUp(self):
        self.repos = [_commit_repo(f"gd{i}") for i in range(5)]
        self.paths = [str(r) for r in self.repos]
        self.addCleanup(lambda: [__import__("shutil").rmtree(r, ignore_errors=True)
                                 for r in self.repos])

    def _run_check(self, jobs):
        calls = []

        def fake_check(**kw):
            calls.append(kw.get("repo"))
            return GuardStatus(present=True, error=None)

        buf = io.StringIO()
        with mock.patch.object(guard_sweep, "check", side_effect=fake_check), \
             mock.patch.object(guard_sweep, "latest_strix", return_value=None), \
             mock.patch.object(guard_sweep.auth, "resolve_token", return_value=(None, None)), \
             contextlib.redirect_stdout(buf):
            rc = guard_sweep.check_targets(paths=self.paths, config_path=None,
                                           no_stream=True, jobs=jobs)
        return rc, calls

    def test_check_exit_and_coverage_stable_across_jobs(self):
        rc1, calls1 = self._run_check(jobs=1)
        rc4, calls4 = self._run_check(jobs=4)
        self.assertEqual(rc1, rc4)
        self.assertEqual(len(calls1), 5)
        self.assertEqual(sorted(map(str, calls1)), sorted(map(str, calls4)))  # every repo, once


if __name__ == "__main__":
    unittest.main()

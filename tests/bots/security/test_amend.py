#!/usr/bin/env python3
"""`saw fix amend` force-updates branches that still carry the payload; it does not run on heuristic-only or `--pr`."""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr

from stayawake import cli
from stayawake.bots.security.models import CONFIRMED, Finding, ScanResult, Severity
from stayawake.bots.security.pr.amend import amend_repo
from stayawake.bots.security.remediator import _amend_line_needs
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.query import branches_carrying
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_evil_merge import EVIL_SIG, _git


def _sigs():
    by: dict[str, list] = {}
    for s in EVIL_SIG:
        by.setdefault(s["matcher"], []).append(s)
    return by


def _ok_push(branch, dest, lease):
    return PushResult(True)


class TestFixAmendCli(unittest.TestCase):
    @mock.patch("stayawake.bots.security.remediator.amend", return_value=0)
    def test_amend_routes_and_strips_the_word(self, m):
        rc = cli.main(["fix", "amend", "."])
        self.assertEqual(rc, 0)
        m.assert_called_once()
        self.assertEqual(m.call_args.kwargs["paths"], ["."])
        self.assertFalse(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.remediator.amend", return_value=0)
    def test_amend_remote_routes(self, m):
        rc = cli.main(["fix", "amend", "--remote"])
        self.assertEqual(rc, 0)
        self.assertTrue(m.call_args.kwargs["remote"])

    @mock.patch("stayawake.bots.security.remediator.amend")
    def test_amend_refuses_a_pull_request(self, m):
        with redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["fix", "amend", "--pr"])
        self.assertEqual(rc, 2)
        m.assert_not_called()
        self.assertIn("does not open a pull request", err.getvalue())

    @mock.patch("stayawake.bots.security.pr.amend.amend_repo")
    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_bare_fix_does_not_amend(self, mfix, mamend):
        rc = cli.main(["fix"])
        self.assertEqual(rc, 0)
        mfix.assert_called_once()
        mamend.assert_not_called()

    @mock.patch("stayawake.bots.security.pr.amend.amend_repo")
    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_fix_pr_does_not_amend(self, mfix, mamend):
        rc = cli.main(["fix", "--pr"])
        self.assertEqual(rc, 0)
        self.assertTrue(mfix.call_args.kwargs["pr"])
        mamend.assert_not_called()


class TestFixAmendRepo(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="amend-"))
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t.test")
        _git(self.d, "config", "user.name", "Tester")
        (self.d / "a.txt").write_text("base\n")
        _git(self.d, "add", ".")
        _git(self.d, "commit", "-qm", "init")
        self.base = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        _git(self.d, "checkout", "-qb", "feature")
        (self.d / "b.txt").write_text("feature\n")
        _git(self.d, "add", ".")
        _git(self.d, "commit", "-qm", "feature work")
        _git(self.d, "checkout", "-q", self.base)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _rev(self, ref="HEAD"):
        return subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", ref],
            capture_output=True, text=True, check=True).stdout.strip()

    def _show(self, spec):
        return subprocess.run(
            ["git", "-C", str(self.d), "show", spec],
            capture_output=True, text=True, check=True).stdout

    def _log_format(self, fmt, ref="HEAD"):
        return subprocess.run(
            ["git", "-C", str(self.d), "log", "-1", f"--format={fmt}", ref],
            capture_output=True, text=True, check=True).stdout.strip()

    def _log_subjects(self, ref="HEAD"):
        return subprocess.run(
            ["git", "-C", str(self.d), "log", "--format=%s", ref],
            capture_output=True, text=True, check=True).stdout

    def _parents(self, sha):
        out = subprocess.run(
            ["git", "-C", str(self.d), "rev-list", "--parents", "-n", "1", sha],
            capture_output=True, text=True, check=True).stdout.split()
        return out[1:]

    def _is_ancestor(self, anc, desc="HEAD"):
        r = subprocess.run(
            ["git", "-C", str(self.d), "merge-base", "--is-ancestor", anc, desc],
            capture_output=True, text=True)
        return r.returncode == 0

    def _loader_merge(self):
        (self.d / "x.js").write_text("var ok = 1;\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "commit", "-qm", "add x.js")
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "x.js").write_text("var ok = 1;\neval(String.fromCharCode(1, 2, 3));\n")
        _git(self.d, "add", "x.js")
        _git(self.d, "-c", "user.name=Injected", "-c", "user.email=inj@t.test",
             "commit", "-qm", "merge (smuggled loader)")

    def _amend(self, pusher=_ok_push, **kw):
        with mock.patch("stayawake.bots.security.pr.amend.gitutil.origin_slug",
                        return_value="acme/app"):
            return amend_repo(self.d, ScanOptions(), _sigs(), [], token="t",
                              pusher=pusher, **kw)

    def test_no_remote_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        line = amend_repo(self.d, ScanOptions(), _sigs(), [])
        self.assertIn("nothing was force-updated", line)
        self.assertEqual(before, self._rev())

    def test_force_updates_the_branch_that_carries_the_commit(self):
        self._loader_merge()
        merge = self._rev()
        calls = []

        def pusher(branch, dest, lease):
            calls.append((branch, dest, lease))
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertTrue(calls)
        self.assertEqual(calls[0][0], calls[0][1])
        self.assertIn("force-updated", line)
        self.assertNotIn("was not force-updated", line)
        self.assertNotEqual(self._rev(), merge)
        self.assertEqual(self._parents(self._rev()), self._parents(merge))
        self.assertEqual(self._log_format("%s"), "merge (smuggled loader)")
        self.assertEqual(self._log_format("%an"), "Injected")
        self.assertNotIn("security: remove payload", self._log_subjects())
        self.assertIn("fromCharCode", self._show(f"{merge}:x.js"))
        self.assertNotIn("fromCharCode", self._show("HEAD:x.js"))
        self.assertTrue((self.d / ".git" / "saw-amend" / merge[:12] / "capture.json").is_file())

    def test_replays_a_later_commit(self):
        self._loader_merge()
        merge = self._rev()
        (self.d / "later.txt").write_text("ok\n")
        _git(self.d, "add", "later.txt")
        _git(self.d, "commit", "-qm", "later work")
        line = self._amend()
        self.assertIn("force-updated", line)
        rewritten = self._rev("HEAD~1")
        self.assertEqual(self._parents(rewritten), self._parents(merge))
        self.assertEqual(self._log_format("%s", rewritten), "merge (smuggled loader)")
        self.assertEqual(self._log_format("%an", rewritten), "Injected")
        self.assertIn("later work", self._log_subjects())
        self.assertIn("merge (smuggled loader)", self._log_subjects())
        self.assertNotIn("security: remove payload", self._log_subjects())
        self.assertNotIn("fromCharCode", self._show("HEAD:x.js"))
        self.assertIn("fromCharCode", self._show(f"{merge}:x.js"))
        self.assertTrue((self.d / "later.txt").exists())
        self.assertNotEqual(self._rev(), merge)
        self.assertFalse(self._is_ancestor(merge))

    def test_force_updates_every_branch_that_carries_the_commit(self):
        self._loader_merge()
        merge = self._rev()
        _git(self.d, "branch", "also")
        calls = []

        def pusher(branch, dest, lease):
            calls.append(branch)
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertIn("force-updated", line)
        self.assertEqual(set(calls), {self.base, "also"})
        self.assertEqual(self._rev(), self._rev("also"))
        self.assertNotEqual(self._rev("also"), merge)

    def test_a_failed_push_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        line = self._amend(pusher=lambda *_a: PushResult(False, "denied"))
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)
        self.assertEqual(before, self._rev())
        self.assertIn("fromCharCode", self._show("HEAD:x.js"))
        self.assertIn("fromCharCode", self._show(f"{before}:x.js"))

    def test_a_failed_push_leaves_the_past_commit(self):
        self._loader_merge()
        merge = self._rev()
        (self.d / "later.txt").write_text("ok\n")
        _git(self.d, "add", "later.txt")
        _git(self.d, "commit", "-qm", "later work")
        tip = self._rev()
        line = self._amend(pusher=lambda *_a: PushResult(False, "denied"))
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)
        self.assertEqual(tip, self._rev())
        self.assertTrue((self.d / "later.txt").exists())
        self.assertTrue(self._is_ancestor(merge))
        self.assertIn("fromCharCode", self._show(f"{merge}:x.js"))
        self.assertIn("fromCharCode", self._show("HEAD:x.js"))

    def test_a_push_that_does_not_move_the_remote_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch("stayawake.bots.security.pr.amend._push_amended",
                        return_value=PushResult(True)), \
             mock.patch("stayawake.bots.security.pr.amend._remote_sha",
                        return_value=before):
            line = self._amend(pusher=None)
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)
        self.assertEqual(before, self._rev())

    def test_a_push_that_does_not_move_the_remote_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch("stayawake.bots.security.pr.amend._push_amended",
                        return_value=PushResult(True)), \
             mock.patch("stayawake.bots.security.pr.amend._remote_sha",
                        return_value=before):
            line = self._amend(pusher=None)
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)
        self.assertEqual(before, self._rev())

    def test_heuristic_only_is_not_replaced(self):
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected only in the merge\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "merge with new file")
        before = self._rev()
        line = self._amend()
        self.assertIn("no confirmed payload in past commits to replace", line)
        self.assertEqual(before, self._rev())

    def test_dirty_tree_is_refused(self):
        self._loader_merge()
        (self.d / "dirty.txt").write_text("nope\n")
        before = self._rev()
        line = self._amend()
        self.assertIn("working tree is not clean", line)
        self.assertEqual(before, self._rev())

    def _confirmed_finding(self, sha):
        return Finding(
            signature_id="evil-merge-loader", category="evil-merge",
            severity=Severity.CRITICAL, path=sha[:10], description="x",
            vector="evil-merge", commit_sha=sha, related_paths=("x.js",),
            confidence=CONFIRMED)

    def test_notes_are_not_carrying_branches(self):
        self._loader_merge()
        merge = self._rev()
        _git(self.d, "update-ref", "refs/remotes/origin/ghost", merge)
        _git(self.d, "update-ref", "refs/remotes/origin/notes/commits", merge)
        _git(self.d, "update-ref", "refs/notes/commits", merge)
        names = {n for n, _, _ in branches_carrying(self.d, merge)}
        self.assertIn("ghost", names)
        self.assertNotIn("notes/commits", names)

    def test_an_unfinished_scan_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        scan = ScanResult(target=str(self.d), source="local",
                          findings=[self._confirmed_finding(before)],
                          error="worker died")
        calls = []
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            line = self._amend(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn("scan did not finish", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])

    def test_two_confirmed_commits_are_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        other = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        scan = ScanResult(target=str(self.d), source="local",
                          findings=[self._confirmed_finding(before),
                                    self._confirmed_finding(other)])
        calls = []
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            line = self._amend(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn("2 confirmed past commits", line)
        self.assertIn("nothing was force-updated", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])

    def test_a_partial_push_still_needs_review(self):
        self._loader_merge()
        _git(self.d, "branch", "also")

        def pusher(branch, dest, lease):
            if branch == "also":
                return PushResult(False, "denied")
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertIn("was not force-updated", line)
        self.assertIn("force-updated '", line)
        self.assertTrue(_amend_line_needs(line))

    def test_mixed_amend_line_is_not_done(self):
        line = ("acme/app: force-updated 'also'; 'main' was not force-updated "
                "(commit abcdefabcdef)")
        self.assertTrue(_amend_line_needs(line))

    def test_capture_exists_before_refs_move(self):
        self._loader_merge()
        seen = []
        real = gitamend.apply_replacement

        def wrapped(repo, old, new, heads):
            cap = Path(repo) / ".git" / "saw-amend" / old[:12] / "capture.json"
            self.assertTrue(cap.is_file())
            seen.append(True)
            return real(repo, old, new, heads)

        with mock.patch("stayawake.bots.security.pr.amend.gitamend.apply_replacement",
                        wrapped):
            self._amend()
        self.assertTrue(seen)

    def test_empty_scan_error_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        scan = ScanResult(target=str(self.d), source="local",
                          findings=[self._confirmed_finding(before)],
                          error="")
        calls = []
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            line = self._amend(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn("scan did not finish", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])

    def test_whitespace_token_is_not_a_credential(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch("stayawake.bots.security.pr.amend.gitutil.origin_slug",
                        return_value="acme/app"):
            line = amend_repo(self.d, ScanOptions(), _sigs(), [], token=" ")
        self.assertIn("no credential", line)
        self.assertEqual(before, self._rev())

    def test_no_remote_does_not_rewrite_even_with_a_pusher(self):
        self._loader_merge()
        before = self._rev()
        calls = []
        line = amend_repo(self.d, ScanOptions(), _sigs(), [], token="t",
                          pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn("no remote", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])

    def test_path_is_not_a_commit_identity(self):
        self._loader_merge()
        before = self._rev()
        finding = self._confirmed_finding(before)
        finding.commit_sha = None
        finding.path = before[:10]
        scan = ScanResult(target=str(self.d), source="local", findings=[finding])
        calls = []
        with mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            line = self._amend(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn("no confirmed payload in past commits to replace", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])

    def test_force_push_names_a_heads_ref(self):
        self._loader_merge()
        seen = []

        def fake_run(repo, args, **kw):
            seen.append(list(args))
            class R:
                returncode = 1
                stdout = ""
                stderr = "denied"
            return R()

        with mock.patch("stayawake.bots.security.pr.amend._remote_sha", return_value=None), \
             mock.patch("stayawake.lib.git.write.push.run", fake_run):
            line = self._amend(pusher=None)
        self.assertIn("was not force-updated", line)
        specs = [a[-1] for a in seen if a and a[0] == "push"]
        self.assertTrue(specs)
        self.assertTrue(all(s.endswith("refs/heads/" + self.base) or ":refs/heads/" in s
                            for s in specs))


if __name__ == "__main__":
    unittest.main()

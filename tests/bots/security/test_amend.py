#!/usr/bin/env python3
"""`saw fix amend` force-updates branches that still carry the payload; it does not run on heuristic-only or `--pr`."""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack, contextmanager, redirect_stderr

from stayawake import cli
from stayawake.bots.security.models import CONFIRMED, Finding, ScanResult, Severity
from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr.amend import amend_outcome, amend_repo
from stayawake.bots.security.pr.outcome import (BranchResult, Cause, Reason, amended,
                                                      render_amend_line)
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.query import branches_carrying
from stayawake.lib.git.write import amend as gitamend
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_evil_merge import EVIL_SIG, _git


class _NoRemoteTags:
    """What `git ls-remote --tags` looks like for a remote carrying no tags."""
    returncode = 0
    stdout = ""
    stderr = ""


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

    @mock.patch("stayawake.bots.security.remediator.amend")
    def test_amend_refuses_a_named_branch(self, m):
        with redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["fix", "amend", "--branch", "develop"])
        self.assertEqual(rc, 2)
        m.assert_not_called()
        self.assertIn("does not take --branch", err.getvalue())

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

    @mock.patch("stayawake.bots.security.pr.amend.amend_repo")
    @mock.patch("stayawake.bots.security.remediator.fix", return_value=0)
    def test_fix_named_branch_does_not_amend(self, mfix, mamend):
        rc = cli.main(["fix", "--branch", "develop"])
        self.assertEqual(rc, 0)
        self.assertEqual(mfix.call_args.kwargs["branches"], ["develop"])
        mamend.assert_not_called()


class _AmendFixture(unittest.TestCase):
    """A repository carrying the payload in a past merge, and the remote answers the
    amend path must get before it may move anything."""

    def setUp(self):
        # The host's own git config decided these outcomes: this machine enables ssh signing
        # globally, so every replacement and every replayed commit was really signed — the suite
        # took ten times as long here than on a machine that does not sign, and "does it sign?"
        # was answered by the laptop rather than by the fixture. State goes to a temp dir too, so
        # no test writes a capture into the operator's own state directory.
        self._state = tempfile.mkdtemp(prefix="saw-teststate-")
        self.addCleanup(shutil.rmtree, self._state, True)
        isolated = mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": "/dev/null",
                                                "GIT_CONFIG_SYSTEM": "/dev/null",
                                                "XDG_STATE_HOME": self._state})
        isolated.start()
        self.addCleanup(isolated.stop)
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

    def _porcelain(self):
        return subprocess.run(
            ["git", "-C", str(self.d), "status", "--porcelain"],
            capture_output=True, text=True, check=True).stdout

    def _worktree(self, rel):
        return (self.d / rel).read_text()

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
        return render_amend_line(self._act(pusher=pusher, **kw))

    @contextmanager
    def _remote(self, *, permitted=True, protected=False):
        """The answers this path must get from GitHub before it may move anything: who may
        rewrite, whether the refs refreshed, and what each remote branch is at. Every amend goes
        through them, so the harness supplies them rather than letting them be skipped."""
        import stayawake.bots.security.pr.amend as amendmod
        at = "stayawake.bots.security.pr.amend."
        with ExitStack() as stack:
            for target, patch in (
                ("gitutil.origin_slug", dict(return_value="acme/app")),
                ("authority.may_rewrite", dict(return_value=mock.Mock(
                    permitted=permitted, conclusive=True,
                    reason="owner" if permitted else "unauthorized"))),
                ("authority.ref_protection", dict(return_value=mock.Mock(
                    protected=protected, reason="rule_read"))),
                ("authority.fork_count", dict(return_value=0)),
                ("gitutil.fetch_refs", dict(return_value=mock.Mock(ok=True, reason=""))),
                ("_read_remote_head",
                 dict(side_effect=lambda r, s, b, tk: (True, self._rev(b)))),
                # `_tags_at` asks the REMOTE for tags; unstubbed every gate test would wait out
                # the network timeout against a repository that does not exist.
                ("run", dict(return_value=_NoRemoteTags())),
            ):
                held = amendmod
                for part in target.split("."):
                    held = getattr(held, part)
                if isinstance(held, mock.Mock):
                    continue  # a test that supplies its own answer keeps it
                stack.enter_context(mock.patch(at + target, **patch))
            yield

    def _act(self, pusher=_ok_push, *, permitted=True, protected=False, **kw):
        with self._remote(permitted=permitted, protected=protected):
            return amend_outcome(self.d, "acme/app", ScanOptions(), _sigs(), [],
                                 "t", pusher=pusher, **kw)

    def _confirmed_finding(self, sha):
        return Finding(
            signature_id="evil-merge-loader", category="evil-merge",
            severity=Severity.CRITICAL, path=sha[:10], description="x",
            vector="evil-merge", commit_sha=sha, related_paths=("x.js",),
            confidence=CONFIRMED)


class TestFixAmendRepo(_AmendFixture):
    """Replacing the commit and moving the branches that reached it."""

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
        self.assertTrue(amendmod._capture_path("acme/app", merge[:12]).is_file())

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
        self.assertIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

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
        self.assertIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

    def test_a_push_that_does_not_move_the_remote_is_not_a_fix(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch("stayawake.bots.security.pr.amend._push_to",
                        return_value=PushResult(True)), \
             mock.patch("stayawake.bots.security.pr.amend._read_remote_head",
                        return_value=(True, before)):
            line = self._amend(pusher=None)
        self.assertIn("was not force-updated", line)
        self.assertNotIn("force-updated '", line)
        self.assertEqual(before, self._rev())
        self.assertIn("fromCharCode", self._show(f"{before}:x.js"))
        self.assertIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

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
        merge = self._rev()
        _git(self.d, "branch", "also")

        def pusher(branch, dest, lease):
            if branch == "also":
                return PushResult(False, "denied")
            return PushResult(True)

        outcome = self._act(pusher=pusher)
        line = render_amend_line(outcome)
        self.assertIn("was not force-updated", line)
        self.assertIn("force-updated '", line)
        self.assertTrue(outcome.needs_review)
        self.assertEqual(self._rev("also"), merge)
        self.assertNotEqual(self._rev(self.base), merge)
        self.assertIn("fromCharCode", self._show("also:x.js"))
        self.assertNotIn("fromCharCode", self._show(f"{self.base}:x.js"))
        self.assertNotIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

    def test_a_failed_current_branch_is_reset(self):
        self._loader_merge()
        merge = self._rev()
        _git(self.d, "branch", "also")
        _git(self.d, "checkout", "-q", "also")

        def pusher(branch, dest, lease):
            if branch == "also":
                return PushResult(False, "denied")
            return PushResult(True)

        line = self._amend(pusher=pusher)
        self.assertIn("was not force-updated", line)
        self.assertIn("force-updated '", line)
        self.assertEqual(self._rev("also"), merge)
        self.assertNotEqual(self._rev(self.base), merge)
        self.assertIn("fromCharCode", self._show("also:x.js"))
        self.assertNotIn("fromCharCode", self._show(f"{self.base}:x.js"))
        self.assertIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

    def test_a_mixed_result_is_not_done(self):
        """One branch moving does not settle the run: the outcome carries each branch, so a
        partial sweep needs review whatever its sentence happens to read like."""
        outcome = amended("acme/app", "abcdefabcdef", (
            BranchResult("also", True),
            BranchResult("main", False, Reason(Cause.PUSH_REFUSED, "denied")),
        ))
        self.assertTrue(outcome.needs_review)
        self.assertIn("was not force-updated", render_amend_line(outcome))

    def test_capture_exists_before_refs_move(self):
        self._loader_merge()
        seen = []
        real = gitamend.apply_replacement

        def wrapped(repo, old, new, heads, signing=None):
            cap = amendmod._capture_path("acme/app", old[:12])
            self.assertTrue(cap.is_file())
            seen.append(True)
            return real(repo, old, new, heads, signing)

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

    def test_unread_remote_is_not_a_force_update(self):
        self._loader_merge()
        before = self._rev()
        calls = []
        with mock.patch("stayawake.bots.security.pr.amend._read_remote_head",
                        return_value=(False, None)), \
             mock.patch("stayawake.bots.security.pr.amend._push_to",
                        side_effect=lambda *a, **k: calls.append(a) or PushResult(True)):
            line = self._amend(pusher=None)
        self.assertIn("could not be read", line)
        self.assertIn("nothing was force-updated", line)
        self.assertEqual(before, self._rev())
        self.assertEqual(calls, [])
        self.assertIn("fromCharCode", self._worktree("x.js"))
        self.assertEqual(self._porcelain(), "")

    def test_force_push_names_a_heads_ref(self):
        self._loader_merge()
        before = self._rev()
        seen = []

        def fake_run(repo, args, **kw):
            seen.append(list(args))
            class R:
                returncode = 1
                stdout = ""
                stderr = "denied"
            return R()

        with mock.patch("stayawake.bots.security.pr.amend._read_remote_head",
                        return_value=(True, before)), \
             mock.patch("stayawake.lib.git.write.push.run", fake_run):
            line = self._amend(pusher=None)
        self.assertIn("was not force-updated", line)
        specs = [a[-1] for a in seen if a and a[0] == "push"]
        self.assertTrue(specs)
        self.assertTrue(all(s.endswith("refs/heads/" + self.base) or ":refs/heads/" in s
                            for s in specs))
        self.assertTrue(any(any(x.startswith("--force-with-lease=refs/heads/") for x in a)
                            for a in seen if a and a[0] == "push"))
        self.assertTrue(all("--force" not in a for a in seen if a and a[0] == "push"))


class TestAmendGates(_AmendFixture):
    """Each gate the act passes through before a ref moves, and what it leaves behind."""

    AT = "stayawake.bots.security.pr.amend."

    def _causes(self, outcome):
        return [r.cause for r in outcome.reasons]

    def test_an_identity_that_may_not_rewrite_moves_nothing(self):
        self._loader_merge()
        before = self._rev()
        calls = []
        outcome = self._act(pusher=lambda *a: calls.append(a) or PushResult(True),
                            permitted=False)
        self.assertIn(Cause.NOT_PERMITTED_TO_REWRITE, self._causes(outcome))
        self.assertEqual(calls, [])
        self.assertEqual(before, self._rev())
        self.assertTrue(outcome.needs_review)

    def test_refs_that_did_not_refresh_stop_the_act(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch(self.AT + "gitutil.fetch_refs",
                        return_value=mock.Mock(ok=False, reason="network_error")):
            outcome = self._act()
        self.assertIn(Cause.REMOTE_REFS_UNREADABLE, self._causes(outcome))
        self.assertEqual(before, self._rev())

    def test_a_repository_that_signs_and_cannot_is_refused_before_anything_moves(self):
        self._loader_merge()
        before = self._rev()
        unavailable = mock.Mock(must_refuse=True, available=False, required=True,
                                reason="no secret key", config=())
        with mock.patch(self.AT + "sign.signing_status", return_value=unavailable):
            outcome = self._act()
        self.assertIn(Cause.SIGNING_UNAVAILABLE, self._causes(outcome))
        self.assertEqual(before, self._rev())
        self.assertIn("fromCharCode", self._worktree("x.js"))

    def test_a_protected_branch_is_published_beside_never_over(self):
        self._loader_merge()
        before = self._rev()
        pushes = []
        outcome = self._act(pusher=lambda *a: pushes.append(a) or PushResult(True),
                            protected=True)
        self.assertEqual([b.force_updated for b in outcome.branches], [False])
        self.assertEqual(self._causes(outcome)[:0], [])
        self.assertEqual(outcome.branches[0].reason.cause, Cause.BRANCH_PROTECTED)
        self.assertTrue(pushes and pushes[0][1].startswith("security/amend-"))
        self.assertNotEqual(pushes[0][0], pushes[0][1])
        self.assertTrue(outcome.needs_review)
        self.assertEqual(before, self._rev())

    def test_an_unreadable_protection_rule_is_not_permission(self):
        self._loader_merge()
        pushes = []
        outcome = self._act(pusher=lambda *a: pushes.append(a) or PushResult(True),
                            protected=None)
        self.assertEqual(outcome.branches[0].reason.cause, Cause.PROTECTION_UNKNOWN)
        self.assertTrue(pushes and pushes[0][1].startswith("security/amend-"))
        self.assertTrue(outcome.needs_review)

    def test_a_replacement_that_drops_more_than_the_payload_is_refused(self):
        self._loader_merge()
        before = self._rev()
        with mock.patch(self.AT + "gitamend.discarded_delta",
                        return_value=["README.md", "x.js"]):
            outcome = self._act()
        self.assertIn(Cause.REPLACEMENT_LOSES_MORE_THAN_THE_PAYLOAD, self._causes(outcome))
        self.assertIn("README.md", outcome.reasons[0].detail)
        self.assertEqual(before, self._rev())

    def test_nothing_moves_when_the_previous_objects_were_not_captured(self):
        self._loader_merge()
        before = self._rev()
        calls = []
        with mock.patch(self.AT + "capture_bundle",
                        return_value=mock.Mock(ok=False, reason="unwritable")):
            outcome = self._act(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn(Cause.CAPTURE_FAILED, self._causes(outcome))
        self.assertEqual(calls, [])
        self.assertEqual(before, self._rev())

    def test_a_replay_that_changed_unrelated_commits_puts_the_branches_back(self):
        self._loader_merge()
        before = self._rev()
        calls = []
        with mock.patch(self.AT + "gitamend.replay_is_faithful",
                        return_value=(False, ["deadbeef: message changed"])):
            outcome = self._act(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn(Cause.REPLAY_CHANGED_UNRELATED_COMMITS, self._causes(outcome))
        self.assertEqual(calls, [])
        self.assertEqual(before, self._rev())
        self.assertEqual(self._porcelain(), "")

    def test_a_branch_left_moved_is_reported_as_part_way(self):
        self._loader_merge()
        with mock.patch(self.AT + "gitamend.apply_replacement",
                        side_effect=gitamend.AmendUnwindFailed(
                            self.d, unrestored=["main"], moved={"main": "abc"})):
            outcome = self._act()
        self.assertIn(Cause.LEFT_PART_WAY, self._causes(outcome))
        self.assertIn("main", outcome.reasons[0].detail)
        self.assertTrue(outcome.needs_review)

    def test_the_lease_reaches_the_push(self):
        self._loader_merge()
        before = self._rev()
        seen = []
        self._act(pusher=lambda b, d, lease: seen.append(lease) or PushResult(True))
        self.assertEqual(seen, [before])

    def test_an_account_wide_amend_is_not_offered(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = cli.main(["fix", "amend", "--user", "acme"])
        self.assertEqual(code, 2)
        self.assertIn("--user", err.getvalue())


    def test_the_verb_reaches_the_act_through_its_real_call_site(self):
        """The gates above all call `amend_outcome` directly. This one goes through the sweep the
        CLI actually uses — the call site where a name that resolved to the module instead of the
        function made the whole verb inert while every test above stayed green."""
        from stayawake.bots.security import remediator
        from stayawake.utils.streaming import Streamer
        self._loader_merge()
        prog = Streamer(enabled=False, out=io.StringIO())
        with self._remote():
            outcomes = remediator._amend_local({}, ScanOptions(), _sigs(), [],
                                               [str(self.d)], prog, jobs=1)
        self.assertEqual(len(outcomes), 1)
        self.assertNotIn("error —", outcomes[0].summary)
        self.assertIn("force-updated", outcomes[0].summary)

    def test_a_named_path_that_does_not_exist_does_not_widen_the_sweep(self):
        from stayawake.bots.security import remediator
        from stayawake.utils.streaming import Streamer
        out = io.StringIO()
        outcomes = remediator._amend_local({}, ScanOptions(), _sigs(), [],
                                           [str(self.d / "no-such-repo")],
                                           Streamer(enabled=False, out=out), jobs=1)
        self.assertEqual(outcomes, [])
        self.assertIn("no such path", out.getvalue())

    def test_a_run_that_examined_nothing_is_not_success(self):
        from stayawake.bots.security import remediator
        err = io.StringIO()
        with redirect_stderr(err), \
             mock.patch.object(remediator, "_amend_local", return_value=[]), \
             mock.patch.object(remediator, "_resolve_config", return_value={"settings": {}}), \
             mock.patch.object(remediator, "load_signatures", return_value={}):
            self.assertEqual(remediator.amend(paths=["/nowhere"]), 2)

    def test_a_repository_nobody_forked_does_not_carry_a_standing_warning(self):
        self._loader_merge()
        with mock.patch(self.AT + "authority.fork_count", return_value=0):
            outcome = self._act()
        self.assertTrue(outcome.completed)
        self.assertFalse(outcome.needs_review)

    def test_forks_that_could_not_be_counted_still_need_a_person(self):
        self._loader_merge()
        with mock.patch(self.AT + "authority.fork_count", return_value=None):
            outcome = self._act()
        self.assertTrue(outcome.completed)
        self.assertTrue(outcome.needs_review)

    def test_a_clone_missing_remote_commits_is_never_force_updated(self):
        """The lease matching only says the remote is where we last read it. It does not say this
        clone contains what the remote has, and force-pushing a branch that is behind deletes
        commits that were never captured because they were never here."""
        self._loader_merge()
        before = self._rev()
        calls = []
        unseen = "f" * 40
        with mock.patch(self.AT + "_read_remote_head", return_value=(True, unseen)):
            outcome = self._act(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn(Cause.LOCAL_MISSING_REMOTE_COMMITS, self._causes(outcome))
        self.assertEqual(calls, [])
        self.assertEqual(before, self._rev())

    def test_a_decoy_ref_cannot_choose_the_lease(self):
        """`ls-remote <pattern>` tail-matches at `/`, so `refs/heads/a/refs/heads/main` answers a
        query for `refs/heads/main` and sorts first. Anyone who can push could otherwise pick the
        SHA used as the lease and as the post-push check."""
        self._loader_merge()
        real = self._rev()
        decoy = "1" * 40

        class R:
            returncode = 0
            stdout = (f"{decoy}\trefs/heads/a/refs/heads/{self.base}\n"
                      f"{real}\trefs/heads/{self.base}\n")
            stderr = ""

        with mock.patch(self.AT + "run", return_value=R()):
            known, sha = amendmod._read_remote_head(self.d, "acme/app", self.base, "t")
        self.assertTrue(known)
        self.assertEqual(sha, real)

    def test_a_branch_named_like_the_aside_ref_is_still_not_force_updated(self):
        """`_destination` decides; the transport must not re-decide from `dest != branch`. A
        branch already named `security/amend-<sha12>` makes those two names equal."""
        seen = []

        def pusher(branch, dest, lease):
            seen.append((branch, dest, lease))
            return PushResult(True)

        with mock.patch(self.AT + "publish_head",
                        side_effect=lambda *a, **k: seen.append(("publish",)) or PushResult(True)), \
             mock.patch(self.AT + "force_update_head",
                        side_effect=lambda *a, **k: seen.append(("force",)) or PushResult(True)):
            amendmod._push_to(self.d, "acme/app", "security/amend-abc123def456",
                              "security/amend-abc123def456", "t", "deadbeef", None, force=False)
        self.assertEqual(seen, [("publish",)])

    def test_a_tag_only_on_the_remote_still_needs_a_person(self):
        """The run's own refresh is `--no-tags`, so a tag pushed since the last fetch is invisible
        in this clone — and one `clone --branch <tag>` puts the payload back on disk."""
        self._loader_merge()
        old = self._rev()

        class R:
            returncode = 0
            stdout = f"{old}\trefs/tags/v1.0^{{}}\n"
            stderr = ""

        with mock.patch(self.AT + "run", return_value=R()), \
             mock.patch(self.AT + "authority.fork_count", return_value=0):
            outcome = self._act()
        self.assertIn(Cause.TAGS_AT_REPLACED_COMMIT, self._causes(outcome))
        self.assertIn("v1.0", outcome.reasons[1].detail)
        self.assertTrue(outcome.needs_review)

    def test_tags_that_could_not_be_listed_are_not_reported_as_none(self):
        self._loader_merge()

        class R:
            returncode = 128
            stdout = ""
            stderr = "could not read"

        with mock.patch(self.AT + "run", return_value=R()), \
             mock.patch(self.AT + "authority.fork_count", return_value=0):
            outcome = self._act()
        self.assertIn(Cause.TAGS_NOT_ESTABLISHED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)

    def test_a_repository_with_nothing_to_replace_is_not_work_for_a_person(self):
        """`saw fix amend ~/dev` over forty clean repositories used to report thirty-nine as
        needing review, because a refusal was graded on `not completed` rather than on why."""
        outcome = self._act()
        self.assertIn(Cause.NO_CONFIRMED_PAYLOAD, self._causes(outcome))
        self.assertFalse(outcome.needs_review)

    def test_a_repository_that_could_not_be_acted_on_is_still_work(self):
        self._loader_merge()
        outcome = self._act(permitted=False)
        self.assertTrue(outcome.needs_review)

    def test_a_glob_or_home_relative_target_is_not_treated_as_missing(self):
        from stayawake.bots.security import remediator
        from stayawake.utils.streaming import Streamer
        out = io.StringIO()
        remediator._amend_local({}, ScanOptions(), _sigs(), [],
                                [str(self.d.parent / "*")],
                                Streamer(enabled=False, out=out), jobs=1)
        self.assertNotIn("no such path", out.getvalue())

    def test_a_machine_with_no_git_identity_refuses_rather_than_inventing_one(self):
        """CI runners are the case: with nothing configured git either invents an identity from
        the host or cannot commit at all, and which one you get depends on the machine."""
        self._loader_merge()
        before = self._rev()
        calls = []
        _git(self.d, "config", "--unset", "user.email")
        outcome = self._act(pusher=lambda *a: calls.append(a) or PushResult(True))
        self.assertIn(Cause.NO_COMMITTER_IDENTITY, self._causes(outcome))
        self.assertEqual(calls, [])
        self.assertEqual(before, self._rev())
        self.assertTrue(outcome.needs_review)


if __name__ == "__main__":
    unittest.main()

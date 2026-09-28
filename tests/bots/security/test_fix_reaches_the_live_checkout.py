#!/usr/bin/env python3
"""A payload that exists only in the operator's checkout is still removed."""
from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout

from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.pr.fix_verdict import BaseState, Checkout, render_fix_verdict
from stayawake.bots.security.remediation import live
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox

LOADER = ("const _0x1a=['aHR0cHM6Ly9ldmlsLnRlc3Q='];\n"
          "(function(v){var f=String.fromCharCode;globalThis['v']=f(127);})(0);\n")
PAYLOAD = "public/fonts/text.woff"


class _CleanOrigin(GitSandbox):
    """A repository whose `origin/main` carries nothing at all."""

    def setUp(self):
        super().setUp()
        self.origin = self.owned(self.root / "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)],
                       check=True, capture_output=True)
        self.repo = self.new_repo("project")
        self.write(self.repo, "src/index.js", "export const greet = (n) => n;\n")
        self.commit(self.repo, "a clean starting point")
        self.git(self.repo, "remote", "add", "origin", str(self.origin))
        self.git(self.repo, "push", "-q", "origin", "main")
        self.git(self.repo, "fetch", "-q", "origin")

    def drop_payload(self):
        self.write(self.repo, PAYLOAD, LOADER)

    def run_fix(self) -> str:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            remediator.fix(None, paths=[str(self.repo)], no_stream=True)
        return out.getvalue() + err.getvalue()

    def assert_gone(self):
        self.assertFalse((self.repo / PAYLOAD).exists(),
                         f"{PAYLOAD} is still in the checkout")


class TestAnUntrackedPayload(_CleanOrigin):
    def test_it_is_removed_from_the_checkout(self):
        self.drop_payload()
        self.run_fix()
        self.assert_gone()

    def test_the_run_does_not_call_the_checkout_clean(self):
        self.drop_payload()
        self.assertNotIn("already clean", self.run_fix())


class TestAPayloadCommittedButNotPushed(_CleanOrigin):
    def setUp(self):
        super().setUp()
        self.drop_payload()
        self.commit(self.repo, "a local commit")

    def test_it_is_removed_from_the_checkout(self):
        self.run_fix()
        self.assert_gone()

    def test_the_run_does_not_call_the_checkout_clean(self):
        self.assertNotIn("already clean", self.run_fix())


class TestAPayloadOnAFeatureBranch(_CleanOrigin):
    def setUp(self):
        super().setUp()
        self.git(self.repo, "checkout", "-q", "-b", "feat/work")
        self.drop_payload()
        self.commit(self.repo, "work in progress")

    def test_it_is_removed_from_the_checkout(self):
        self.run_fix()
        self.assert_gone()

    def test_the_operator_stays_on_their_branch(self):
        self.run_fix()
        self.assertEqual("feat/work",
                         self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip())


class TestACleanCheckoutIsLeftAlone(_CleanOrigin):
    def test_nothing_of_theirs_is_removed(self):
        (self.repo / "notes.md").write_text("my own work\n")
        self.run_fix()
        self.assertTrue((self.repo / "src" / "index.js").exists())
        self.assertTrue((self.repo / "notes.md").exists())

    def test_the_run_says_it_is_clean(self):
        self.assertIn("clean", self.run_fix())


class TestACleanBaseDoesNotHideTheCheckoutsGrade(_CleanOrigin):
    """Check the grade on the path where no fix branch is prepared."""

    def _report(self, result):
        with mock.patch.object(fixmod.live, "clean", return_value=result), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(self.repo, ScanOptions(), load_signatures(), [])

    def test_a_checkout_it_could_not_finish_needs_review(self):
        self.drop_payload()
        report = self._report(live.LiveResult(unread=[PAYLOAD]))
        self.assertTrue(report.needs_review, render_fix_verdict(report))

    def test_a_checkout_it_finished_does_not(self):
        self.drop_payload()
        report = self._report(live.LiveResult(removed=[PAYLOAD]))
        self.assertFalse(report.needs_review, render_fix_verdict(report))

    def test_a_checkout_it_could_not_read_is_not_called_clean(self):
        self.drop_payload()
        locked = self.repo / "vault"
        locked.mkdir()
        (locked / "evil.js").write_text(LOADER)
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            report = fixmod.prepare_fix(self.repo, ScanOptions(), load_signatures(), [])
        self.assertNotIn("already clean", render_fix_verdict(report))
        self.assertTrue(report.needs_review, render_fix_verdict(report))


class TestACleanBaseKeepsItsLockfileOnTheBranch(_CleanOrigin):
    def setUp(self):
        super().setUp()
        self.write(self.repo, "package-lock.json", '{"lockfileVersion": 3, "packages": {"": {}}}\n')
        self.commit(self.repo, "a lockfile the base carries")
        self.git(self.repo, "push", "-q", "origin", "main")
        self.git(self.repo, "fetch", "-q", "origin")

    def test_the_prepared_branch_does_not_remove_it(self):
        self.drop_payload()
        self.run_fix()
        refs = self.git(self.repo, "for-each-ref", "--format=%(refname:short)",
                        "refs/heads/security/")
        for branch in refs.split():
            self.assertIn("package-lock.json",
                          self.git(self.repo, "ls-tree", "-r", "--name-only", branch))


class TestThePullRequestPathCarriesTheGrade(_CleanOrigin):
    def test_a_checkout_it_could_not_finish_needs_review(self):
        self.drop_payload()
        stopped = fixmod._Stopped(BaseState.NOTHING_TO_FIX, "'main' is clean", "main",
                                  fixmod._CheckoutSeen(Checkout.NOT_CLEAN))
        with mock.patch.object(fixmod, "_build_fix", return_value=(stopped, None)), \
             mock.patch.object(fixmod.gitutil, "origin_slug", return_value="o/r"):
            out = fixmod.submit_fix_pr(self.repo, ScanOptions(), load_signatures(), [],
                                       token="t")
        self.assertTrue(out.needs_review, render_fix_verdict(out))


class TestAnInfectedBaseLosesItsLockfileWhateverTheCheckout(GitSandbox):
    """Check the fix branch for an infected base while part of the checkout cannot be read."""

    def test_the_fix_branch_still_drops_the_lockfile(self):
        origin = self.owned(self.root / "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True,
                       capture_output=True)
        repo = self.new_repo("project")
        self.write(repo, "src/index.js", "export const greet = (n) => n;\n")
        self.write(repo, "package.json", '{"name":"p"}\n')
        self.write(repo, "package-lock.json",
                   '{"name":"p","lockfileVersion":3,"requires":true,"packages":{"":{"name":"p"}}}\n')
        self.write(repo, "public/fonts/text.woff", LOADER)
        self.commit(repo, "init")
        self.git(repo, "remote", "add", "origin", str(origin))
        self.git(repo, "push", "-q", "origin", "main")
        self.git(repo, "fetch", "-q", "origin")
        locked = repo / "private"
        locked.mkdir()
        (locked / "f.txt").write_text("x\n")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        with mock.patch.object(fixmod.installed, "lockfile_stays", return_value=False):
            fixmod.prepare_fix(repo, ScanOptions(), load_signatures(), [])
        branch = [b for b in self.git(repo, "for-each-ref", "--format=%(refname:short)",
                                      "refs/heads").split()
                  if b != "main" and not b.startswith("saw/uncommitted")]
        self.assertEqual(1, len(branch))
        self.assertNotIn("package-lock.json",
                         self.git(repo, "ls-tree", "-r", "--name-only", branch[0]).split())


if __name__ == "__main__":
    unittest.main()

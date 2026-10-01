#!/usr/bin/env python3
"""Bare `saw fix` names the files added in the same commit as a confirmed payload, removes none of
them, and does not call the repository done."""
from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout

from stayawake.bots.security.models import HEURISTIC, Finding, Severity
from stayawake.bots.security.pr import arrivals_for_fix
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.pr.fix_verdict import (Arrivals, BaseFix, BaseState, Checkout,
                                                    FixVerdict, Grade, render_fix_verdict)
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox

LOADER = 'var _0x=String.fromCharCode(118,97,114);eval(_0x+" x=1");\n'
PAYLOAD = "public/fonts/text.woff"
PADDING = {"public/fonts/inter-regular.woff": "wOFF\x00\x01\x00\x00genuine third-party font\n",
           ".vscode/extensions.json": '{"recommendations": []}\n'}


class _Project(GitSandbox):

    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        self.write(self.d, "src/index.js", "export const x = 1;\n")
        self.commit(self.d, "a clean start")

    def deliver(self):
        self.write(self.d, PAYLOAD, LOADER)
        for path, text in PADDING.items():
            self.write(self.d, path, text)
        return self.commit(self.d, "add build tooling")

    def verdict(self, repo=None):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(repo or self.d, ScanOptions(), load_signatures(), [])


class TestBareFixNamesWhatArrivedWithThePayload(_Project):

    def test_the_files_are_named_kept_and_the_run_needs_review(self):
        self.deliver()
        v = self.verdict()
        self.assertEqual(set(PADDING), set(v.arrivals.files))
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        for path in PADDING:
            self.assertTrue((self.d / path).exists(), path)
        self.assertFalse((self.d / PAYLOAD).exists())
        text = render_fix_verdict(v, detail=True)
        self.assertIn("saw fix amend", text)
        for path in PADDING:
            self.assertIn(path, text)

    def test_a_payload_added_alone_names_nothing(self):
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        v = self.verdict()
        self.assertEqual(Arrivals(), v.arrivals)
        self.assertIs(Grade.HISTORY_REMAINS, v.grade)

    def test_a_first_commit_carrying_the_payload_is_named_for_review(self):
        repo = self.new_repo("fresh", user__name="Tester")
        self.write(repo, "src/index.js", "export const x = 1;\n")
        self.write(repo, PAYLOAD, LOADER)
        self.commit(repo, "init")
        v = self.verdict(repo)
        self.assertEqual(1, len(v.arrivals.first_commits))
        self.assertEqual((), v.arrivals.files)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertTrue((repo / "src/index.js").exists())

    def test_a_clone_without_its_whole_history_is_not_called_a_first_commit(self):
        self.deliver()
        self.write(self.d, "later.txt", "x\n")
        self.commit(self.d, "later")
        clone = self.owned(self.root / "shallow")
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{self.d}", str(clone)],
                       check=True, capture_output=True, stdin=subprocess.DEVNULL)
        self.git(clone, "config", "user.name", "Tester")
        self.git(clone, "config", "user.email", "t@t.test")
        v = self.verdict(clone)
        self.assertEqual((), v.arrivals.first_commits)
        self.assertTrue(v.arrivals.unread)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)


class TestWhatIsNamed(_Project):

    def _named(self, findings):
        return arrivals_for_fix.arrivals_beside(self.d, [PAYLOAD], findings, load_signatures(), [],
                                       ScanOptions())

    def test_a_file_with_its_own_finding_is_not_named(self):
        self.deliver()
        own = Finding("suspect", "fake-font", Severity.HIGH, ".vscode/extensions.json", "unsure",
                      confidence=HEURISTIC)
        self.assertEqual(("public/fonts/inter-regular.woff",), self._named([own]).files)

    def test_a_merge_names_only_what_saw_fix_amend_does_not_take_on_its_own(self):
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "checkout", "-q", "-b", "feature")
        self.write(self.d, "src/feature.js", "export const f = 1;\n")
        self.commit(self.d, "feature work")
        self.git(self.d, "checkout", "-q", "main")
        self.git(self.d, "merge", "-q", "--no-commit", "--no-ff", "feature")
        self.write(self.d, PAYLOAD, LOADER)
        self.write(self.d, "public/fonts/inter-regular.woff", PADDING["public/fonts/inter-regular.woff"])
        self.write(self.d, "docs/notes.md", "# notes\n")
        self.commit(self.d, "Merge pull request #7 from feature")
        v = self.verdict()
        self.assertEqual(("docs/notes.md",), v.arrivals.files)


class TestTheArrivalsLine(unittest.TestCase):

    def _verdict(self, arrivals):
        return FixVerdict("o/r", BaseFix(BaseState.PREPARED, "o/r: prepared", "main"),
                          Checkout.CLEANED, arrivals=arrivals)

    def test_undecided_files_need_review_and_give_the_command(self):
        v = self._verdict(Arrivals(files=("pad.woff",)))
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertIn("run saw fix amend in this repository, on a terminal", render_fix_verdict(v))
        self.assertNotIn("pad.woff", render_fix_verdict(v))
        self.assertIn("pad.woff", render_fix_verdict(v, detail=True))

    def test_what_git_could_not_read_is_never_called_clean(self):
        v = self._verdict(Arrivals(unread=("every copy of x",)))
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertIn("not called clean", render_fix_verdict(v))

    def test_no_arrivals_leave_the_grade_alone(self):
        self.assertIs(Grade.DONE, self._verdict(Arrivals()).grade)


if __name__ == "__main__":
    unittest.main()

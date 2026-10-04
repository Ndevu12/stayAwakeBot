#!/usr/bin/env python3
"""Bare `saw fix` names the files added in the same commit as a confirmed payload, removes none of
them, and does not call the repository done."""
from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout

from stayawake.bots.security.models import HEURISTIC, Finding, Severity
from stayawake.bots.security.pr import arrival_record, arrivals_for_fix
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.pr.resolve import (KEEP, TAKE_OUT, ArrivedFile, DeliveryAnswer,
                                                DeliveryQuestion)
from stayawake.bots.security.pr.fix_verdict import (Arrivals, BaseFix, BaseState, Checkout,
                                                    FixVerdict, Grade, HistoryHold, Remedy,
                                                    render_fix_verdict)
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
        self.assertNotRegex(render_fix_verdict(v), r"\b(is|already) clean(ed)?\b")
        self.assertEqual(set(PADDING), set(v.arrivals.files))
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        for path in PADDING:
            self.assertTrue((self.d / path).exists(), path)
        self.assertFalse((self.d / PAYLOAD).exists())
        text = render_fix_verdict(v, detail=True)
        self.assertIn("run saw fix in this repository, on a terminal", text)
        for path in PADDING:
            self.assertIn(path, text)

    def test_files_an_earlier_amend_left_undecided_keep_a_clean_repository_in_review(self):
        self.git(self.d, "remote", "add", "origin", "https://github.com/acme/app.git")
        self.write(self.d, "public/fonts/inter-regular.woff", PADDING["public/fonts/inter-regular.woff"])
        self.commit(self.d, "fonts")
        left = DeliveryQuestion("1" * 40, "", "s", (PAYLOAD,),
                                (ArrivedFile("public/fonts/inter-regular.woff", "2" * 40),))
        arrival_record.write(arrival_record.state_dir("acme/app") / "0123456789ab", [left])
        v = self.verdict()
        self.assertIn("public/fonts/inter-regular.woff", v.arrivals.files)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertNotIn("clean", render_fix_verdict(v))

    def test_an_earlier_list_that_cannot_be_read_keeps_the_repository_in_review(self):
        self.git(self.d, "remote", "add", "origin", "https://github.com/acme/app.git")
        folder = arrival_record.state_dir("acme/app") / "0123456789ab"
        folder.mkdir(parents=True)
        (folder / arrival_record.RECORD_NAME).write_text("{not json")
        v = self.verdict()
        self.assertTrue(v.arrivals.unread_records)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertIn(arrival_record.RECORD_NAME, render_fix_verdict(v, detail=True))

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
        self.assertIn("run saw fix in this repository, on a terminal", render_fix_verdict(v))
        self.assertNotIn("pad.woff", render_fix_verdict(v))
        self.assertIn("pad.woff", render_fix_verdict(v, detail=True))

    def test_what_git_could_not_read_is_never_called_clean(self):
        v = self._verdict(Arrivals(unread=("every copy of x",)))
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertIn("git could not read what else was added with the malware", render_fix_verdict(v))

    def test_no_arrivals_leave_the_grade_alone(self):
        self.assertIs(Grade.DONE, self._verdict(Arrivals()).grade)



class TestFixAsksOnATerminal(_Project):
    """On a terminal, `saw fix` puts the files to the operator and keeps the answer."""

    def setUp(self):
        super().setUp()
        self.git(self.d, "remote", "add", "origin", "https://github.com/acme/app.git")

    def answering(self, action):
        asked: list[DeliveryQuestion] = []

        def resolve(question):
            if not isinstance(question, DeliveryQuestion):
                return None
            asked.append(question)
            chosen = tuple(f.path for f in question.files) if action == TAKE_OUT else ()
            return DeliveryAnswer(action, chosen)

        return resolve, asked

    def run_fix(self, resolver=None):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(self.d, ScanOptions(), load_signatures(), [],
                                      resolver=resolver)

    def restore_checkout(self):
        self.git(self.d, "checkout", "-q", "HEAD", "--", ".")

    def stored(self, ref, path):
        return subprocess.run(["git", "-C", str(self.d), "cat-file", "-e", f"{ref}:{path}"],
                              capture_output=True).returncode == 0

    def test_taking_out_removes_them_in_the_prepared_branch_and_names_where_they_stay(self):
        self.deliver()
        resolver, asked = self.answering(TAKE_OUT)
        v = self.run_fix(resolver)
        self.assertEqual(1, len(asked))
        for path in PADDING:
            self.assertFalse(self.stored(v.base_fix.branch, path), path)
            self.assertTrue(self.stored("HEAD", path), path)
        self.assertEqual((), v.arrivals.files)
        self.assertEqual(set(PADDING), {p for h in v.arrivals.taken_out_held for p in h.paths})
        self.assertIs(Grade.HISTORY_REMAINS, v.grade)
        text = render_fix_verdict(v)
        self.assertIn("files you chose to take out are still stored", text)
        self.assertNotRegex(text, r"\b(is|already) clean\b")

    def test_a_later_run_takes_them_out_again_without_asking(self):
        self.deliver()
        self.run_fix(self.answering(TAKE_OUT)[0])
        self.restore_checkout()
        resolver, asked = self.answering(KEEP)
        v = self.run_fix(resolver)
        self.assertEqual([], asked)
        for path in PADDING:
            self.assertFalse(self.stored(v.base_fix.branch, path), path)

    def test_kept_files_are_not_asked_or_named_again(self):
        self.deliver()
        self.run_fix(self.answering(KEEP)[0])
        self.restore_checkout()
        resolver, asked = self.answering(TAKE_OUT)
        v = self.run_fix(resolver)
        self.assertEqual([], asked)
        self.assertEqual((), v.arrivals.files)
        self.assertFalse(v.arrivals.undecided)
        for path in PADDING:
            self.assertTrue(self.stored(v.base_fix.branch, path), path)
        self.restore_checkout()
        self.assertEqual((), self.run_fix().arrivals.files)

    def test_a_take_out_saved_for_a_file_no_delivery_added_is_not_applied(self):
        sha = self.deliver()
        blob = self.git(self.d, "rev-parse", "HEAD:src/index.js").strip()
        arrival_record.add_decisions("acme/app", [arrival_record.Decision(
            "src/index.js", blob, (sha,), arrival_record.TAKE_OUT_DECISION)])
        v = self.run_fix()
        self.assertTrue(self.stored(v.base_fix.branch, "src/index.js"))
        self.assertNotIn(("src/index.js", blob), [(p, b) for p, b, _ids in v.arrivals.take_out])

    def test_a_take_out_leaves_the_bases_own_copy_and_does_not_report_it(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "dev")
        self.deliver()
        self.git(self.d, "checkout", "-q", base)
        own = ".vscode/extensions.json"
        self.write(self.d, own, PADDING[own])
        self.commit(self.d, "the project's own settings")
        self.git(self.d, "checkout", "-q", "dev")
        v = self.run_fix(self.answering(TAKE_OUT)[0])
        self.git(self.d, "checkout", "-q", base)
        held_on = {h.name: h.paths for h in v.arrivals.taken_out_held}
        self.assertTrue(not v.base_fix.branch or self.stored(v.base_fix.branch, own))
        self.assertNotIn(own, held_on.get(base, ()))

    def test_answers_that_cannot_be_kept_leave_the_run_in_review(self):
        self.git(self.d, "remote", "remove", "origin")
        self.deliver()
        v = self.run_fix(self.answering(KEEP)[0])
        self.assertTrue(v.arrivals.not_saved)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)
        self.assertIn("could not be saved", render_fix_verdict(v))

    def test_a_file_taken_out_but_still_stored_leaves_history_to_clear(self):
        hold = HistoryHold("head", "main", ("public/fonts/inter-regular.woff",), Remedy.FIX_PR)
        v = FixVerdict("acme/app", BaseFix(BaseState.PREPARED, "prepared", "main", "auto"),
                       Checkout.CLEANED, arrivals=Arrivals(taken_out_held=(hold,)))
        self.assertIs(Grade.HISTORY_REMAINS, v.grade)

    def test_earlier_answers_that_cannot_be_read_are_named(self):
        folder = arrival_record.state_dir("acme/app")
        folder.mkdir(parents=True, exist_ok=True)
        (folder / arrival_record.DECIDED_NAME).write_text("{not json")
        self.deliver()
        v = self.run_fix()
        self.assertIn(str(folder / arrival_record.DECIDED_NAME), v.arrivals.unread_records)
        self.assertIs(Grade.NEEDS_REVIEW, v.grade)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The grade a fix run reports is read from its verdict, never from its text."""
from __future__ import annotations

import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import pr, remediator
from stayawake.bots.security.models import Finding, ScanResult, Severity
from stayawake.bots.security.pr import fix as fixmod, held
from stayawake.bots.security.pr.fix_verdict import (
    BaseFix, BaseState, Checkout, CheckoutDetail, FixVerdict, Grade, History, HistoryHold,
    Remedy, checkout_of, render_fix_verdict)
from stayawake.bots.security.pr.render import _pr_body
from stayawake.bots.security.remediation import Change, live, preserve
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from stayawake.lib.git.write.commit import CommitResult
from stayawake.utils import exitcodes
from tests.bots.security.test_pr import _patch_git
from tests.support.gitrepo import GitSandbox

LOADER = 'var _0x=String.fromCharCode(118,97,114);eval(_0x+" x=1");\n'
PAYLOAD = "public/fonts/text.woff"

_SETTLED = (BaseState.NOTHING_TO_FIX, BaseState.SUSPICIOUS_ONLY, BaseState.PREPARED,
            BaseState.PR_OPENED)
_UNSETTLED = (BaseState.PARTIAL, BaseState.MANUAL, BaseState.ABORTED, BaseState.PR_FAILED)
_HOLD = HistoryHold("head", "main", (PAYLOAD,), Remedy.AMEND)


def _verdict(checkout=Checkout.CLEANED, state=BaseState.PREPARED, history=History(), **fix):
    base = BaseFix(state, "o/r: prepared", "main", fix.pop("branch", "security/auto-clean-main"),
                   **fix)
    return FixVerdict("o/r", base, checkout, history)


class TestTheGradeFunction(unittest.TestCase):
    def test_a_settled_fix_and_a_clean_checkout_are_done(self):
        for state in _SETTLED:
            for checkout in (Checkout.CLEAN, Checkout.CLEANED):
                with self.subTest(state=state, checkout=checkout):
                    self.assertIs(Grade.DONE, _verdict(checkout, state).grade)

    def test_a_checkout_not_clean_or_unread_needs_review(self):
        for checkout in (Checkout.NOT_CLEAN, Checkout.UNREAD):
            for state in _SETTLED:
                with self.subTest(state=state, checkout=checkout):
                    self.assertIs(Grade.NEEDS_REVIEW, _verdict(checkout, state).grade)

    def test_an_unsettled_base_fix_needs_review(self):
        for state in _UNSETTLED:
            with self.subTest(state=state):
                self.assertIs(Grade.NEEDS_REVIEW, _verdict(Checkout.CLEAN, state).grade)

    def test_a_base_fix_it_does_not_know_needs_review(self):
        self.assertIs(Grade.NEEDS_REVIEW, FixVerdict("o/r", None, Checkout.CLEAN).grade)

    def test_a_history_git_could_not_read_needs_review(self):
        self.assertIs(Grade.NEEDS_REVIEW,
                      _verdict(history=History(unread="could not read HEAD")).grade)

    def test_a_hold_is_history_remains(self):
        self.assertIs(Grade.HISTORY_REMAINS, _verdict(history=History(holds=(_HOLD,))).grade)

    def test_review_outranks_a_hold(self):
        for grade_source in (dict(checkout=Checkout.NOT_CLEAN),
                             dict(state=BaseState.ABORTED),
                             dict(history=History(holds=(_HOLD,), unread="x"))):
            kw = {"history": History(holds=(_HOLD,)), **grade_source}
            with self.subTest(**{k: str(v) for k, v in grade_source.items()}):
                self.assertIs(Grade.NEEDS_REVIEW, _verdict(**kw).grade)

    def test_needs_review_is_the_grade(self):
        self.assertTrue(_verdict(Checkout.UNREAD).needs_review)
        self.assertFalse(_verdict(history=History(holds=(_HOLD,))).needs_review)


def _report(not_removed=()):
    return SimpleNamespace(not_removed=list(not_removed), note=lambda: "")


class TestTheCheckoutState(unittest.TestCase):
    def _state(self, **kw):
        return checkout_of(live.CheckoutResult(**kw))[0]

    def test_nothing_confirmed_is_clean(self):
        self.assertIs(Checkout.CLEAN, self._state())

    def test_confirmed_and_all_gone_is_cleaned(self):
        self.assertIs(Checkout.CLEANED, self._state(
            confirmed=1, removed=live.LiveResult(removed=["a.js"]), cleared=["a.js"]))

    def test_each_thing_left_behind_is_not_clean(self):
        for kw in (dict(left_alone=["a.js"]),
                   dict(removed=live.LiveResult(refused=["a.js"])),
                   dict(staged=["a.js"]),
                   dict(kept=preserve.Preserved(reason="no", blocked=True)),
                   dict(report=_report(not_removed=[Path("node_modules/x")])),
                   dict(failure="could not remove the installed tree")):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertIs(Checkout.NOT_CLEAN, self._state(confirmed=1, **kw))

    def test_each_thing_it_could_not_read_is_unread(self):
        for kw in (dict(scan_error="not read in full"),
                   dict(removed=live.LiveResult(unread=["a.js"])),
                   dict(index_unread="the index could not be read")):
            with self.subTest(**{k: str(v) for k, v in kw.items()}):
                self.assertIs(Checkout.UNREAD, self._state(confirmed=1, **kw))

    def test_an_unread_path_outranks_one_left_behind(self):
        self.assertIs(Checkout.UNREAD, self._state(
            confirmed=1, left_alone=["b.js"], removed=live.LiveResult(unread=["a.js"])))

    def test_a_put_aside_that_had_nothing_to_do_is_not_a_block(self):
        self.assertIs(Checkout.CLEAN, self._state(
            kept=preserve.Preserved(reason="this repository has no commit to branch from")))

    def test_what_head_commits_is_not_the_checkouts_to_answer(self):
        self.assertFalse(hasattr(live.CheckoutResult(), "committed"))


def _lines(verdict, detail=False):
    return render_fix_verdict(verdict, detail).split("\n")[1:]


class TestTheWording(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(["    your checkout is clean"], _lines(_verdict(Checkout.CLEAN)))

    def test_cleaned(self):
        v = FixVerdict("o/r", BaseFix(BaseState.PREPARED, "s", "main"), Checkout.CLEANED,
                       checkout_detail=CheckoutDetail(removed=2))
        self.assertEqual(["    your checkout is cleaned — removed 2 file(s)"], _lines(v))

    def test_not_clean_counts_and_names_only_when_attended(self):
        v = FixVerdict("o/r", BaseFix(BaseState.PREPARED, "s", "main"), Checkout.NOT_CLEAN,
                       checkout_detail=CheckoutDetail(still_in=("a.js", "b.js")))
        self.assertEqual(["    your checkout is not clean — 2 confirmed file(s) are still in it"],
                         _lines(v))
        self.assertEqual(["    your checkout is not clean — 2 confirmed file(s) are still in it: "
                          "a.js, b.js"], _lines(v, detail=True))

    def test_unread(self):
        self.assertEqual(["    your checkout was not read in full, so it is not called clean"],
                         _lines(_verdict(Checkout.UNREAD)))

    def test_history_unread(self):
        self.assertIn("    git could not say what your history holds, so it is not called clean",
                      _lines(_verdict(history=History(unread="x"))))

    def _held(self, hold, **fix):
        return _lines(_verdict(history=History(holds=(hold,)), **fix))

    def test_cleaned_with_holds_leads_with_the_history(self):
        self.assertEqual("    your checkout is cleaned; your history still carries it:",
                         self._held(_HOLD)[0])

    def test_head_on_the_base_with_a_pull_request(self):
        hold = HistoryHold("head", "main", (PAYLOAD,), Remedy.FIX_PR)
        self.assertEqual("      the commit you are on is also on 'main' — pull request #12 "
                         "removes it from 'main'",
                         self._held(hold, state=BaseState.PR_OPENED, pull_request=12,
                                    published=True)[1])

    def test_head_on_the_base_without_a_pull_request(self):
        hold = HistoryHold("head", "main", (PAYLOAD,), Remedy.FIX_PR)
        self.assertEqual("      the commit you are on is also on 'main' — "
                         "'security/auto-clean-main' removes it from 'main' once merged; "
                         "saw fix --pr opens the pull request", self._held(hold)[1])

    def test_head_only_on_this_machine(self):
        self.assertEqual("      the commit you are on is only on this machine — saw fix amend "
                         "removes it from your commits", self._held(_HOLD)[1])

    def test_head_pushed_to_another_branch_is_not_called_local(self):
        hold = HistoryHold("head", "feat", (PAYLOAD,), Remedy.AMEND, on_remote=True)
        self.assertEqual("      the commit you are on is not on 'main' — saw fix amend removes "
                         "it from your commits", self._held(hold)[1])

    def test_another_branch(self):
        hold = HistoryHold("branch", "x", (PAYLOAD,), Remedy.AMEND)
        self.assertEqual("      branch 'x' carries it — saw fix amend removes it",
                         self._held(hold)[1])

    def test_a_stash_entry(self):
        hold = HistoryHold("stash", "stash@{0}", (PAYLOAD,), Remedy.NAMED_ONLY)
        self.assertEqual("      stash entry stash@{0} carries it", self._held(hold)[1])

    def test_never_calls_the_history_clean(self):
        for v in (_verdict(Checkout.CLEAN), _verdict(), _verdict(history=History(holds=(_HOLD,)))):
            self.assertNotIn("history is clean", render_fix_verdict(v))


class TestThePullRequestBody(unittest.TestCase):
    def test_it_names_the_base_and_not_the_machine(self):
        body = _pr_body("o/r", [Change("remove", PAYLOAD)], base="main")
        self.assertIn("This removes it from `main`. Earlier commits still store it; "
                      "`saw scan --history` lists them.", body)
        for machine in ("checkout", "this machine", "stash", "saw fix amend"):
            self.assertNotIn(machine, body)


class TestTheRunReadsTheGrade(unittest.TestCase):
    def _made(self, grade, acted=False):
        return remediator.FixOutcome("o/r: x", grade, acted)

    def test_each_board_tag(self):
        self.assertEqual("[review  ]", remediator.fix_tag(self._made(Grade.NEEDS_REVIEW)))
        self.assertEqual("[history ]", remediator.fix_tag(self._made(Grade.HISTORY_REMAINS)))
        self.assertEqual("[cleaned ]", remediator.fix_tag(self._made(Grade.DONE, acted=True)))
        self.assertEqual("[clean   ]", remediator.fix_tag(self._made(Grade.DONE)))

    def test_the_status_of_a_run(self):
        done, hist, rev = (self._made(g) for g in
                           (Grade.DONE, Grade.HISTORY_REMAINS, Grade.NEEDS_REVIEW))
        self.assertEqual(exitcodes.CLEAN, remediator.fix_status([done, done]))
        self.assertEqual(exitcodes.FINDINGS, remediator.fix_status([done, hist]))
        self.assertEqual(exitcodes.INCOMPLETE, remediator.fix_status([hist, rev, done]))

    def test_the_tally_counts_grades_not_words(self):
        outcomes = [remediator.FixOutcome("o/r: ABORTED PARTIAL : error", Grade.DONE),
                    self._made(Grade.HISTORY_REMAINS), self._made(Grade.NEEDS_REVIEW)]
        self.assertEqual("\nProcessed 3 repositories; 1 need review; 1 still carry it in their "
                         "history.", remediator.fix_tally(outcomes))

    def test_a_verdict_is_graded_where_it_is_made(self):
        verdict = _verdict(Checkout.UNREAD, BaseState.PR_OPENED)
        self.assertTrue(remediator._graded_fix(lambda: verdict, "o/r").needs_review)
        verdict = _verdict(history=History(holds=(_HOLD,)))
        self.assertIs(Grade.HISTORY_REMAINS, remediator._graded_fix(lambda: verdict, "o/r").grade)

    def test_text_where_a_verdict_belongs_needs_review(self):
        self.assertTrue(remediator._graded_fix(lambda: "o/r: fixed 2 file(s)", "o/r").needs_review)

    def test_an_exception_needs_review(self):
        def boom():
            raise RuntimeError("x")
        self.assertTrue(remediator._graded_fix(boom, "o/r").needs_review)


_LOADER_FINDING = Finding("code-loader", "code-loader", Severity.CRITICAL, "postcss.config.mjs",
                          "loader", confidence="confirmed")


class TestEveryAbortNeedsReview(unittest.TestCase):
    """Each path that stops before a fix is made grades NEEDS_REVIEW, with a clean checkout."""

    def _run(self, *, prepare=False, slug="owner/repo", suggested=False, **git):
        infected = ScanResult("owner/repo", "local", [_LOADER_FINDING])
        clean = ScanResult("owner/repo", "local", [])
        scans = [infected, clean, clean]
        sug = pr.remediation.Suggested("postcss.config.mjs", "loader", pr.remediation.NO_VCS,
                                       "review", "diff", "clean\n", 1)
        with _patch_git(origin_slug=lambda repo: slug, **git), \
             mock.patch.object(fixmod.live, "clean_checkout", return_value=live.CheckoutResult()), \
             mock.patch.object(fixmod, "scan_target",
                               side_effect=lambda *a, **k: scans.pop(0) if scans else clean), \
             mock.patch.object(pr.remediation, "plan", return_value=[]), \
             mock.patch.object(pr.remediation, "apply", return_value=[]), \
             mock.patch.object(pr.remediation, "remove_residual", return_value=[]), \
             mock.patch.object(pr.remediation, "classify_recovery",
                               return_value=sug if suggested else None), \
             mock.patch.object(pr.remediation, "apply_suggested", return_value=True):
            if prepare:
                return fixmod.prepare_fix(Path("/repo"), object(), {}, [])
            return fixmod.submit_fix_pr(Path("/repo"), object(), {}, [], token="t")

    def assert_aborted(self, verdict, text):
        self.assertIs(BaseState.ABORTED, verdict.base_fix.state)
        self.assertIs(Checkout.CLEAN, verdict.checkout)
        self.assertIn(text, verdict.base_fix.summary)
        self.assertIs(Grade.NEEDS_REVIEW, verdict.grade)

    def test_the_rollback_store_could_not_be_untracked(self):
        verdict = self._run(prepare=True, tracked_under=lambda repo, spec: ["x"])
        self.assert_aborted(verdict, "could not untrack")

    def test_the_computed_strip_could_not_be_staged(self):
        verdict = self._run(prepare=True, suggested=True, stage_all=lambda repo: False)
        self.assert_aborted(verdict, "could not stage the computed strip")

    def test_the_computed_strip_could_not_be_committed(self):
        verdict = self._run(prepare=True, suggested=True,
                            commit_fix=lambda repo, msg: CommitResult(committed=False,
                                                                      signed=False))
        self.assert_aborted(verdict, "could not commit the computed strip")

    def test_a_repository_with_no_github_origin(self):
        verdict = self._run(slug=None, tracked_under=lambda repo, spec: ["x"])
        self.assert_aborted(verdict, "could not untrack")


class _Repo(GitSandbox):
    def setUp(self):
        super().setUp()
        self.d = self.new_repo("project", user__name="Tester")
        self.write(self.d, "src/index.js", "export const x = 1;\n")
        self.commit(self.d, "a clean start")

    def origin(self):
        origin = self.owned(self.root / "origin.git")
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)],
                       check=True, capture_output=True)
        self.git(self.d, "remote", "add", "origin", str(origin))
        self.git(self.d, "push", "-q", "origin", "main")
        self.git(self.d, "fetch", "-q", "origin")

    def verdict(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return fixmod.prepare_fix(self.d, ScanOptions(), load_signatures(), [])


class TestWhatTheHistoryStillHolds(_Repo):
    def test_a_payload_never_committed_is_done(self):
        self.write(self.d, PAYLOAD, LOADER)
        v = self.verdict()
        self.assertEqual((Grade.DONE, Checkout.CLEANED, ()),
                         (v.grade, v.checkout, v.history.holds))
        self.assertIn("your checkout is cleaned — removed 1 file(s)", render_fix_verdict(v))

    def test_a_payload_on_the_base_is_removed_by_the_fix(self):
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        v = self.verdict()
        self.assertIs(Grade.HISTORY_REMAINS, v.grade)
        self.assertEqual([("head", "main", Remedy.FIX_PR)],
                         [(h.where, h.name, h.remedy) for h in v.history.holds])
        self.assertFalse((self.d / PAYLOAD).exists())

    def test_a_commit_only_here_is_amended(self):
        self.origin()
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        v = self.verdict()
        self.assertEqual([("head", Remedy.AMEND, False)],
                         [(h.where, h.remedy, h.on_remote) for h in v.history.holds])
        self.assertIn("is only on this machine", render_fix_verdict(v))

    def test_a_commit_pushed_to_another_branch_is_amended(self):
        self.origin()
        self.git(self.d, "checkout", "-q", "-b", "feat")
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        self.git(self.d, "push", "-q", "origin", "feat")
        v = self.verdict()
        self.assertEqual([("head", "feat", Remedy.AMEND, True)],
                         [(h.where, h.name, h.remedy, h.on_remote) for h in v.history.holds])
        self.assertIn("the commit you are on is not on 'main'", render_fix_verdict(v))

    def test_another_branch_that_carries_it(self):
        self.origin()
        self.git(self.d, "checkout", "-q", "-b", "other")
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        self.git(self.d, "checkout", "-q", "main")
        self.write(self.d, PAYLOAD, LOADER)
        v = self.verdict()
        self.assertEqual([("branch", "other", Remedy.AMEND)],
                         [(h.where, h.name, h.remedy) for h in v.history.holds])
        self.assertIn("branch 'other' carries it — saw fix amend removes it",
                      render_fix_verdict(v))

    def test_a_stash_entry_that_carries_it(self):
        self.origin()
        self.write(self.d, PAYLOAD, LOADER)
        self.git(self.d, "add", PAYLOAD)
        self.git(self.d, "stash", "push", "-q", "-m", "held")
        self.write(self.d, PAYLOAD, LOADER)
        v = self.verdict()
        self.assertEqual([("stash", "stash@{0}", Remedy.NAMED_ONLY)],
                         [(h.where, h.name, h.remedy) for h in v.history.holds])
        self.assertIs(Grade.HISTORY_REMAINS, v.grade)

    def test_git_that_cannot_answer_is_unread(self):
        self.write(self.d, PAYLOAD, LOADER)
        self.commit(self.d, "payload")
        with mock.patch.object(held.live, "entries", return_value=None):
            history = held.history_holds(self.d, [PAYLOAD], "main", load_signatures(), [],
                                         ScanOptions())
        self.assertTrue(history.unread)
        self.assertEqual((), history.holds)

    def test_no_cleared_path_asks_git_nothing(self):
        with mock.patch.object(held, "run") as git:
            self.assertEqual(History(), held.history_holds(self.d, [], "main", {}, [], None))
        git.assert_not_called()


class TestAPathSpelledTwoWaysIsOnePath(_Repo):
    """Check a path the filesystem spells in decomposed Unicode and git may store composed."""

    def test_the_history_hold_is_found(self):
        decomposed = "public/fonts/cafe\u0301.woff"
        self.write(self.d, decomposed, LOADER)
        self.commit(self.d, "payload")
        history = held.history_holds(self.d, [decomposed], "main", load_signatures(), [],
                                     ScanOptions())
        self.assertTrue(history.holds, "a payload the commit still stores was not found")


class TestTheCheckoutReachesTheGrade(_Repo):
    """What the run reports when the checkout could not be finished."""

    def setUp(self):
        super().setUp()
        self.write(self.d, PAYLOAD, LOADER)

    def _prepare(self, result):
        with mock.patch.object(fixmod.live, "clean", return_value=result):
            return self.verdict()

    def test_a_finished_checkout_needs_no_review(self):
        self.assertFalse(self._prepare(live.LiveResult(removed=[PAYLOAD])).needs_review)

    def test_a_checkout_it_could_not_read_needs_review(self):
        v = self._prepare(live.LiveResult(unread=[PAYLOAD]))
        self.assertIs(Checkout.UNREAD, v.checkout)
        self.assertTrue(v.needs_review)

    def test_an_automated_run_does_not_name_the_path(self):
        v = self._prepare(live.LiveResult(refused=[PAYLOAD]))
        with mock.patch.object(remediator.prompt, "attended", return_value=False):
            line = remediator._graded_fix(lambda: v, "o/r").summary
        self.assertNotIn("public/fonts", line)
        self.assertIn("your checkout is not clean — 1 confirmed file(s) are still in it", line)

    def test_a_person_at_a_terminal_is_told_the_path(self):
        v = self._prepare(live.LiveResult(refused=[PAYLOAD]))
        with mock.patch.object(remediator.prompt, "attended", return_value=True):
            line = remediator._graded_fix(lambda: v, "o/r").summary
        self.assertIn(PAYLOAD, line)


if __name__ == "__main__":
    unittest.main()

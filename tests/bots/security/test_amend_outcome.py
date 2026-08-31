#!/usr/bin/env python3
"""`saw fix amend`'s verdict comes from the run's structure, not from the sentence it printed.

The old path recovered it by looking for `"force-updated '"` in the line, so a reword moved the
exit code. These tests pin the direction of travel: the structure decides, the renderer only
speaks, and two conditions that leave the payload reachable after every branch has moved — a tag
still pointing at the replaced commit, and a fork — are verdicts rather than footnotes.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.pr import amend_outcome as ao
from stayawake.bots.security.pr.amend_outcome import (AmendOutcome, BranchResult, Cause, Reason,
                                                      amended, refused, render_amend_line)

_SHA = "abc123456789"

# Every reason `amend_repo` can refuse with today. Each is a different answer to the operator.
_REFUSALS_TODAY = (
    Cause.NOT_A_GIT_REPOSITORY,
    Cause.WORKING_TREE_NOT_CLEAN,
    Cause.NO_REMOTE,
    Cause.NO_CREDENTIAL,
    Cause.SCAN_DID_NOT_FINISH,
    Cause.NO_CONFIRMED_PAYLOAD,
    Cause.MANY_CONFIRMED_COMMITS,
    Cause.CONFIRMED_COMMIT_UNRESOLVED,
    Cause.COMMIT_ON_NO_BRANCH,
    Cause.REMOTE_BRANCH_UNREADABLE,
    Cause.COMMIT_SHAPE_NOT_MODELLED,
    Cause.MERGE_WOULD_NOT_RESOLVE,
    Cause.RECONSTRUCTION_UNAVAILABLE,
    Cause.REPLAY_FAILED,
    Cause.PUSH_REFUSED,
)


def _complete(*reasons: Reason) -> AmendOutcome:
    return amended("o/r", _SHA, [BranchResult("main", True), BranchResult("dev", True)], reasons)


class TestACompletedRun(unittest.TestCase):
    def test_every_branch_moved_so_the_act_completed(self):
        outcome = _complete()
        self.assertTrue(outcome.completed)
        self.assertFalse(outcome.needs_review)

    def test_the_line_names_the_branches_and_the_commit(self):
        line = render_amend_line(_complete())
        self.assertEqual(line.count("\n"), 0)
        self.assertIn("force-updated 'main', 'dev'", line)
        self.assertIn(_SHA, line)
        self.assertIn("o/r", line)

    def test_disclosing_what_no_one_can_act_on_is_not_a_review(self):
        """The objects of the replaced commit survive until git collects them. Every rewrite says
        so; nothing an operator does changes it, so it must not spend the run's verdict."""
        outcome = _complete(Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED))
        self.assertFalse(outcome.needs_review)
        self.assertIn("previous objects remain", render_amend_line(outcome))


class TestABranchLeftBehind(unittest.TestCase):
    def _partial(self) -> AmendOutcome:
        return amended("o/r", _SHA, [BranchResult("main", True), BranchResult("dev", False)])

    def test_a_branch_still_on_the_payload_is_not_a_completed_act(self):
        outcome = self._partial()
        self.assertFalse(outcome.completed)
        self.assertTrue(outcome.needs_review)

    def test_the_line_names_the_branch_that_did_not_move(self):
        line = render_amend_line(self._partial())
        self.assertIn("force-updated 'main'", line)
        self.assertIn("'dev' was not force-updated", line)
        self.assertIn("the remote was not fully updated", line)

    def test_a_run_that_moved_nothing_at_all_still_names_its_branch(self):
        outcome = amended("o/r", _SHA, [BranchResult("main", False)])
        self.assertTrue(outcome.needs_review)
        self.assertNotIn("force-updated 'main'", render_amend_line(outcome))


class TestWhatSurvivesACompletedAct(unittest.TestCase):
    """Both conditions leave the payload reachable when every branch has already moved. Neither is
    a footnote on a line that reads as done."""

    def test_a_tag_at_the_replaced_commit_needs_review(self):
        outcome = _complete(Reason(Cause.TAGS_AT_REPLACED_COMMIT, "v1.2.0"))
        self.assertTrue(outcome.completed)
        self.assertTrue(outcome.needs_review)

    def test_the_line_names_the_tag(self):
        line = render_amend_line(_complete(Reason(Cause.TAGS_AT_REPLACED_COMMIT, "v1.2.0")))
        self.assertIn("tags still point at it (v1.2.0)", line)

    def test_a_fork_needs_review(self):
        outcome = _complete(Reason(Cause.FORKS_EXIST, "3"))
        self.assertTrue(outcome.completed)
        self.assertTrue(outcome.needs_review)

    def test_the_line_says_forks_still_carry_it(self):
        self.assertIn("forks still carry it", render_amend_line(_complete(Reason(Cause.FORKS_EXIST))))

    def test_a_run_that_could_not_look_for_forks_is_not_a_run_that_found_none(self):
        outcome = _complete(Reason(Cause.FORKS_NOT_ESTABLISHED))
        self.assertTrue(outcome.needs_review)
        self.assertIn("could not check for forks", render_amend_line(outcome))

    def test_both_at_once_are_both_reported(self):
        line = render_amend_line(_complete(Reason(Cause.TAGS_AT_REPLACED_COMMIT, "v1"),
                                           Reason(Cause.FORKS_EXIST, "2")))
        self.assertIn("tags still point at it", line)
        self.assertIn("forks still carry it", line)
        self.assertEqual(line.count("\n"), 0)


class TestEveryRefusalIsItsOwnAnswer(unittest.TestCase):
    def test_each_refusal_needs_review_and_says_nothing_moved(self):
        for cause in _REFUSALS_TODAY:
            with self.subTest(cause=cause.value):
                outcome = refused("o/r", cause)
                self.assertFalse(outcome.completed)
                self.assertTrue(outcome.needs_review)
                self.assertEqual(outcome.branches, ())
                line = render_amend_line(outcome)
                self.assertIn("nothing was force-updated", line)
                self.assertEqual(line.count("\n"), 0)

    def test_no_two_refusals_read_the_same(self):
        lines = {render_amend_line(refused("o/r", c)) for c in _REFUSALS_TODAY}
        self.assertEqual(len(lines), len(_REFUSALS_TODAY))

    def test_an_unmodelled_shape_and_an_unresolvable_merge_are_different_answers(self):
        """One is a gap to report, the other a conflict to resolve by hand."""
        self.assertNotEqual(refused("o/r", Cause.COMMIT_SHAPE_NOT_MODELLED),
                            refused("o/r", Cause.MERGE_WOULD_NOT_RESOLVE))
        self.assertNotEqual(render_amend_line(refused("o/r", Cause.COMMIT_SHAPE_NOT_MODELLED)),
                            render_amend_line(refused("o/r", Cause.MERGE_WOULD_NOT_RESOLVE)))

    def test_the_refusal_carries_the_identifier_the_operator_needs(self):
        line = render_amend_line(refused("o/r", Cause.REMOTE_BRANCH_UNREADABLE, "release/2.x"))
        self.assertIn("a remote branch could not be read (release/2.x)", line)

    def test_every_cause_has_its_own_words(self):
        missing = [c.value for c in Cause if c not in ao._PHRASE]
        self.assertEqual(missing, [])
        self.assertEqual(len(set(ao._PHRASE.values())), len(list(Cause)))


class TestTheVerdictIsStructural(unittest.TestCase):
    def test_rewording_every_phrase_moves_no_verdict(self):
        outcomes = [_complete(), _complete(Reason(Cause.TAGS_AT_REPLACED_COMMIT, "v1")),
                    _complete(Reason(Cause.FORKS_EXIST, "2")),
                    _complete(Reason(Cause.PREVIOUS_OBJECTS_UNCOLLECTED)),
                    amended("o/r", _SHA, [BranchResult("main", False)]),
                    *[refused("o/r", c) for c in _REFUSALS_TODAY]]
        before = [(o.needs_review, render_amend_line(o)) for o in outcomes]
        reworded = {c: f"condition {i}" for i, c in enumerate(Cause)}
        with mock.patch.dict(ao._PHRASE, reworded, clear=True), \
                mock.patch.object(ao, "_NOTHING_MOVED", "no ref moved"), \
                mock.patch.object(ao, "_NOT_FULLY_UPDATED", "some refs stand"):
            after = [(o.needs_review, render_amend_line(o)) for o in outcomes]
        self.assertEqual([v for v, _ in before], [v for v, _ in after])
        self.assertNotEqual([line for _, line in before], [line for _, line in after])

    def test_a_verdict_survives_a_renderer_that_says_nothing_at_all(self):
        with mock.patch.object(ao, "render_amend_line", return_value=""):
            self.assertTrue(_complete(Reason(Cause.FORKS_EXIST)).needs_review)
            self.assertFalse(_complete().needs_review)

    def test_any_reason_not_declared_actionless_needs_review(self):
        """Fail-closed: a cause added later flags for review until someone decides it need not."""
        for cause in Cause:
            with self.subTest(cause=cause.value):
                outcome = _complete(Reason(cause))
                self.assertEqual(outcome.needs_review, cause not in ao._NEEDING_NO_ACTION)

    def test_only_the_uncollected_objects_are_declared_actionless(self):
        self.assertEqual(ao._NEEDING_NO_ACTION, frozenset({Cause.PREVIOUS_OBJECTS_UNCOLLECTED}))


class TestAnInconsistentOutcomeIsRefused(unittest.TestCase):
    def test_completed_cannot_be_claimed_over_a_branch_left_behind(self):
        with self.assertRaises(ValueError):
            AmendOutcome("o/r", completed=True, branches=(BranchResult("dev", False),))

    def test_completed_cannot_be_claimed_with_no_branch_at_all(self):
        with self.assertRaises(ValueError):
            AmendOutcome("o/r", completed=True)

    def test_an_amend_that_touched_no_branch_is_a_refusal(self):
        with self.assertRaises(ValueError):
            amended("o/r", _SHA, [])

    def test_the_caller_does_not_get_to_say_the_act_completed(self):
        self.assertFalse(amended("o/r", _SHA, [BranchResult("dev", False)]).completed)


class TestTheLineIsSafeToPrint(unittest.TestCase):
    def test_a_crafted_detail_cannot_break_the_line_or_forge_a_log_command(self):
        line = render_amend_line(refused("o/r", Cause.REMOTE_BRANCH_UNREADABLE,
                                         "a\nb ##[error]x"))
        self.assertEqual(line.count("\n"), 0)
        self.assertNotIn("##[", line)

    def test_a_crafted_repository_name_is_defanged(self):
        self.assertEqual(render_amend_line(refused("o\n/r", Cause.NO_REMOTE)).count("\n"), 0)


if __name__ == "__main__":
    unittest.main()

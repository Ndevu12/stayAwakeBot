#!/usr/bin/env python3
"""`saw fix amend` puts the files a delivery commit added beside a removed payload to the operator,
and removes them only on the operator's answer."""
from __future__ import annotations

import json
import os
from dataclasses import replace
import subprocess
import sys
import unittest
from unittest import mock

from stayawake.bots.security.models import CONFIRMED, HEURISTIC, Finding, ScanResult, Severity
from stayawake.bots.security.pr import amend as amendmod
from stayawake.bots.security.pr import arrival_record
from stayawake.bots.security.pr.amend import amend_outcome
from stayawake.bots.security.pr.outcome import Cause, render_amend_line
from stayawake.bots.security.pr.resolve import (KEEP, TAKE_OUT, UNANSWERED, ArrivedFile,
                                                DeliveryAnswer, DeliveryQuestion, Resolution)
from stayawake.bots.security.remediation.footprint import REMOVE_FILE
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions
from stayawake.lib.git.write.push import PushResult
from tests.bots.security.test_amend import _AmendFixture

PAYLOAD = "public/fonts/fa-solid-900.woff2"
PADDING = ("public/fonts/fa-regular-400.woff2", ".vscode/launch.json")


def _foreign(path=PAYLOAD):
    return Finding("fake-font", "fake-font", Severity.HIGH, path, "wholly foreign",
                   remediation=REMOVE_FILE, confidence=CONFIRMED)


def _answering(action, pick=None):
    """Build a resolver answering every delivery with `action`, choosing `pick` or every file.
    Returns it and the list of delivery questions it was asked."""
    asked: list[DeliveryQuestion] = []

    def resolve(question):
        if not isinstance(question, DeliveryQuestion):
            return Resolution(KEEP)
        asked.append(question)
        chosen = tuple(f.path for f in question.files if pick is None or f.path in pick)
        return DeliveryAnswer(action, chosen if action == TAKE_OUT else ())

    return resolve, asked


class _Delivery(_AmendFixture):
    """A repository where one ordinary commit delivers a payload with padding beside it."""

    def _deliver(self, payload=PAYLOAD, padding=PADDING, subject="add build tooling") -> str:
        self.write(self.d, payload, "wOF2\x00payload " + payload + "\n")
        for path in padding:
            self.write(self.d, path, "genuine " + path + "\n")
        sha = self.commit(self.d, subject)
        return sha

    def _later(self, name="later.txt"):
        self.write(self.d, name, "later work\n")
        self.commit(self.d, "later work")

    def _run(self, resolver=None, findings=None, pushed=True):
        found = [_foreign()] if findings is None else findings
        scan = ScanResult(target=str(self.d), source="local", findings=found)
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            return amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                 pusher=lambda *a: PushResult(pushed), resolver=resolver)

    def _in_history(self, path, blob=None):
        """Whether any commit a branch reaches holds `path`, at `blob` when given."""
        commits = self.git(self.d, "rev-list", "--branches").split()
        for commit in commits:
            found = self.git_may_fail(self.d, "rev-parse", f"{commit}:{path}")
            if found.returncode == 0 and (blob is None or found.stdout.strip() == blob):
                return True
        return False

    def _blob(self, path, ref="HEAD"):
        return self.git(self.d, "rev-parse", f"{ref}:{path}").strip()

    def _causes(self, outcome):
        return [r.cause for r in outcome.reasons]

    def _records(self):
        return sorted(arrival_record.state_dir("acme/app").glob(f"*/{arrival_record.RECORD_NAME}"))


class TestNobodyCanBeAsked(_Delivery):
    """Without a person to ask, nothing is removed on arrival and the run says it is not done."""

    def test_files_added_beside_the_payload_are_kept_and_named(self):
        self._deliver()
        self._later()
        outcome = self._run()
        self.assertTrue(outcome.completed)
        self.assertFalse(self._in_history(PAYLOAD))
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)
            self.assertNotIn(path, outcome.removed)
        self.assertIn(Cause.ARRIVALS_UNDECIDED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        line = render_amend_line(outcome)
        self.assertIn("saw fix amend", line)
        for path in PADDING:
            self.assertIn(path, line)

    def test_files_that_could_not_be_remembered_are_left_to_review_without_a_promise(self):
        self._deliver()
        self._later()
        with mock.patch.object(amendmod.arrival_record, "write", return_value=None):
            outcome = self._run()
        causes = self._causes(outcome)
        self.assertIn(Cause.ARRIVALS_NOT_RECORDED, causes)
        self.assertNotIn(Cause.ARRIVALS_UNDECIDED, causes)
        self.assertTrue(outcome.needs_review)
        self.assertNotIn("saw fix amend", render_amend_line(outcome))

    def test_a_file_with_its_own_finding_is_not_named_with_them(self):
        self._deliver()
        self._later()
        own = Finding("suspect", "fake-font", Severity.HIGH, PADDING[0], "unsure",
                      confidence=HEURISTIC)
        outcome = self._run(findings=[_foreign(), own])
        (undecided,) = [r for r in outcome.reasons if r.cause is Cause.ARRIVALS_UNDECIDED]
        self.assertEqual("1", undecided.detail)
        self.assertEqual(PADDING[1], undecided.subjects)

    def test_the_run_records_what_it_left_beside_its_capture(self):
        self._deliver()
        blobs = {p: self._blob(p) for p in PADDING}
        self._later()
        self._run()
        records = self._records()
        self.assertEqual(1, len(records))
        self.assertTrue((records[0].parent / "capture.bundle").is_file())
        stored = json.loads(records[0].read_text())
        files = {(f["path"], f["blob"]) for d in stored["deliveries"] for f in d["files"]}
        self.assertEqual(set(blobs.items()), files)

    def test_a_later_attended_run_asks_from_the_record_and_removes_what_is_taken_out(self):
        self._deliver()
        self._later()
        self._run()
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver, findings=[])
        self.assertEqual(1, len(asked))
        self.assertTrue(asked[0].recorded)
        self.assertEqual(set(PADDING), {f.path for f in asked[0].files})
        self.assertTrue(outcome.completed, self._causes(outcome))
        for path in PADDING:
            self.assertFalse(self._in_history(path), path)
            self.assertIn(path, outcome.removed)
        self.assertTrue((self.d / "later.txt").exists())
        self.assertEqual([], self._records())

    def test_a_take_out_whose_push_is_refused_stays_recorded(self):
        self._deliver()
        self._later()
        self._run()
        resolver, _asked = _answering(TAKE_OUT)
        self._run(resolver, findings=[], pushed=False)
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)
        recorded = {f.path for record in arrival_record.read_all("acme/app")[0]
                    for q in record.deliveries for f in q.files}
        self.assertEqual(set(PADDING), recorded)

    def test_a_copy_another_branch_added_itself_survives_a_take_out(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "fonts-elsewhere")
        self.write(self.d, PADDING[0], "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "the project's own font")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        resolver, _asked = _answering(TAKE_OUT)
        self._run(resolver)
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:{PADDING[0]}").returncode)
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"fonts-elsewhere:{PADDING[0]}").returncode)

    def test_a_take_out_from_an_older_record_leaves_another_branchs_own_copy(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "fonts-elsewhere")
        self.write(self.d, PADDING[0], "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "the project's own font")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        self._run()
        resolver, asked = _answering(TAKE_OUT)
        self._run(resolver, findings=[])
        self.assertTrue(asked and asked[0].recorded)
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:{PADDING[0]}").returncode)
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"fonts-elsewhere:{PADDING[0]}").returncode)
        self.assertEqual([], self._records())

    def test_a_take_out_leaves_an_infected_branchs_own_identical_copy(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "dev")
        self.write(self.d, PAYLOAD, "wOF2\x00payload " + PAYLOAD + "\n")
        self.commit(self.d, "branch hit by the worm")
        self.write(self.d, PADDING[1], "genuine " + PADDING[1] + "\n")
        self.commit(self.d, "the project's own copy")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        outcome = self._run(_answering(TAKE_OUT, pick={PADDING[1]})[0])
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:{PADDING[1]}").returncode)
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"dev:{PADDING[1]}").returncode)

    def test_a_take_out_git_cannot_place_removes_nothing_more_and_is_named(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "fonts-elsewhere")
        self.write(self.d, PADDING[0], "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "the project's own font")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        real = amendmod.gitutil.ancestry

        def failing_after_delivery(repo, ancestor, descendant):
            frame = sys._getframe(1)
            for _ in range(3):
                if frame is None:
                    break
                if frame.f_code.co_name == "_after_delivery":
                    return None
                frame = frame.f_back
            return real(repo, ancestor, descendant)

        with mock.patch.object(amendmod.gitutil, "ancestry", new=failing_after_delivery):
            outcome = self._run(_answering(TAKE_OUT, pick={PADDING[0]})[0])
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._causes(outcome))
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"fonts-elsewhere:{PADDING[0]}").returncode)

    def test_a_record_whose_commit_left_history_is_named_and_removes_nothing(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "fonts-elsewhere")
        self.write(self.d, PADDING[0], "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "the project's own font")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        self._run()
        added = self.git(self.d, "log", "--format=%H", "-1", "--", PADDING[0]).strip()
        with mock.patch.dict(os.environ, {"GIT_COMMITTER_DATE": "2001-01-01T00:00:00 +0000"}):
            self.git(self.d, "-c", "core.hooksPath=/dev/null", "rebase", "-q", "--force-rebase",
                     f"{added}^")
        self.assertNotEqual(0, self.git_may_fail(self.d, "merge-base", "--is-ancestor", added,
                                                 "HEAD").returncode)
        outcome = self._run(_answering(TAKE_OUT)[0], findings=[])
        self.assertFalse(outcome.completed)
        self.assertIn(Cause.ARRIVALS_DELIVERY_GONE, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"fonts-elsewhere:{PADDING[0]}").returncode)
        self.assertEqual(1, len(self._records()))

    def test_still_held_answers_yes_when_git_cannot_place_a_copy(self):
        sha = self._deliver()
        self._later()
        held = amendmod._held_since_delivery(self.d)
        blob = self.git(self.d, "rev-parse", f"{sha}:{PADDING[0]}").strip()
        with mock.patch.object(amendmod.gitutil, "ancestry", return_value=None):
            self.assertTrue(held((sha,), PADDING[0], blob))

    def test_keeping_a_recorded_file_is_final(self):
        self._deliver()
        self._later()
        self._run()
        resolver, _asked = _answering(KEEP)
        self._run(resolver, findings=[])
        outcome = self._run(findings=[])
        self.assertEqual([Cause.NO_CONFIRMED_PAYLOAD], self._causes(outcome))
        self.assertFalse(outcome.needs_review)
        self.assertEqual([], self._records())

    def test_a_later_run_with_nobody_to_ask_still_needs_review(self):
        self._deliver()
        self._later()
        self._run()
        outcome = self._run(findings=[])
        self.assertIn(Cause.NO_CONFIRMED_PAYLOAD, self._causes(outcome))
        self.assertIn(Cause.ARRIVALS_UNDECIDED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)

    def test_an_unreadable_record_is_named_kept_and_removes_nothing(self):
        self._deliver()
        self._later()
        self._run()
        record = self._records()[0]
        record.write_text("{not json")
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver, findings=[])
        self.assertEqual([], asked)
        self.assertIn(Cause.ARRIVALS_RECORD_UNREADABLE, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertEqual("{not json", record.read_text())
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)

    def test_a_recorded_file_no_branch_holds_is_not_asked_and_is_dropped(self):
        folder = arrival_record.state_dir("acme/app") / "0123456789ab"
        gone = DeliveryQuestion("1" * 40, "", "s", (PAYLOAD,),
                                (ArrivedFile("gone.txt", "2" * 40),))
        arrival_record.write(folder, [gone])
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver, findings=[])
        self.assertEqual([], asked)
        self.assertEqual([Cause.NO_CONFIRMED_PAYLOAD], self._causes(outcome))
        self.assertEqual([], self._records())


class TestTheOperatorDecides(_Delivery):
    """On a terminal the operator's answer decides what is removed."""

    def test_taking_out_every_file_removes_each_as_it_was_added(self):
        self._deliver()
        self._later()
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver)
        self.assertEqual(1, len(asked))
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(outcome.needs_review, self._causes(outcome))
        self.assertFalse(self._in_history(PAYLOAD))
        for path in PADDING:
            self.assertFalse(self._in_history(path), path)
            self.assertIn(path, outcome.removed)
        self.assertEqual([], self._records())

    def test_keeping_leaves_every_file_and_needs_no_review(self):
        self._deliver()
        self._later()
        resolver, _asked = _answering(KEEP)
        outcome = self._run(resolver)
        self.assertTrue(outcome.completed)
        self.assertIn(Cause.ARRIVALS_KEPT, self._causes(outcome))
        self.assertFalse(outcome.needs_review, self._causes(outcome))
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)
        self.assertEqual([], self._records())

    def test_choosing_some_removes_only_those(self):
        self._deliver()
        self._later()
        resolver, _asked = _answering(TAKE_OUT, pick={PADDING[1]})
        outcome = self._run(resolver)
        self.assertFalse(self._in_history(PADDING[1]))
        self.assertTrue(self._in_history(PADDING[0]))
        self.assertIn(Cause.ARRIVALS_KEPT, self._causes(outcome))

    def test_an_unanswered_question_removes_nothing_and_is_recorded(self):
        self._deliver()
        self._later()
        resolver, asked = _answering(UNANSWERED)
        outcome = self._run(resolver)
        self.assertEqual(1, len(asked))
        self.assertIn(Cause.ARRIVALS_UNDECIDED, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)
        self.assertEqual(1, len(self._records()))

    def test_a_resolver_that_fails_leaves_the_question_unanswered(self):
        self._deliver()
        self._later()

        def failing(question):
            if isinstance(question, DeliveryQuestion):
                raise RuntimeError("the prompt failed")
            return Resolution(KEEP)

        outcome = self._run(failing)
        self.assertIn(Cause.ARRIVALS_UNDECIDED, self._causes(outcome))
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)

    def _decide(self, delivery_sha, decision):
        blobs = {p: self.git(self.d, "rev-parse", f"{delivery_sha}:{p}").strip() for p in PADDING}
        arrival_record.add_decisions("acme/app", [
            arrival_record.Decision(p, b, (delivery_sha,), decision) for p, b in blobs.items()])

    def test_a_file_kept_in_an_earlier_run_is_not_asked_again(self):
        sha = self._deliver()
        self._later()
        self._decide(sha, arrival_record.KEEP_DECISION)
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver)
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertEqual([], asked)
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)

    def test_a_file_taken_out_in_an_earlier_run_is_removed_without_asking(self):
        sha = self._deliver()
        self._later()
        self._decide(sha, arrival_record.TAKE_OUT_DECISION)
        outcome = self._run()
        self.assertTrue(outcome.completed, self._causes(outcome))
        for path in PADDING:
            self.assertFalse(self._in_history(path), path)
        self.assertEqual([], arrival_record.read_decisions("acme/app")[0])

    def test_a_take_out_saved_for_a_file_no_delivery_added_removes_nothing(self):
        sha = self._deliver()
        self._later()
        blob = self.git(self.d, "rev-parse", "HEAD:later.txt").strip()
        arrival_record.add_decisions("acme/app", [arrival_record.Decision(
            "later.txt", blob, (sha,), arrival_record.TAKE_OUT_DECISION)])
        outcome = self._run()
        self.assertTrue(self._in_history("later.txt"))
        self.assertNotIn("later.txt", getattr(outcome, "removed", ()) or ())

    def test_the_answers_are_kept_for_later_runs(self):
        self._deliver()
        self._later()
        self._run(_answering(KEEP)[0])
        decided, read = arrival_record.read_decisions("acme/app")
        self.assertTrue(read)
        self.assertEqual({(p, arrival_record.KEEP_DECISION) for p in PADDING},
                         {(d.path, d.decision) for d in decided})

    def test_a_take_out_removes_the_same_files_the_worm_added_on_another_branch(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "dev")
        self._deliver(subject="add build tooling (dev)")
        self.git(self.d, "checkout", "-q", base)
        self._deliver()
        self._later()
        outcome = self._run(_answering(TAKE_OUT)[0])
        self.assertTrue(outcome.completed, self._causes(outcome))
        for ref in (base, "dev"):
            for path in PADDING:
                self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                         f"{ref}:{path}").returncode, (ref, path))

    def test_a_saved_take_out_naming_another_commit_reaches_no_other_copy(self):
        root = self.git(self.d, "rev-list", "--max-parents=0", "HEAD").strip().split()[0]
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "fonts-elsewhere")
        self.write(self.d, PADDING[0], "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "the project's own font")
        self.git(self.d, "checkout", "-q", base)
        sha = self._deliver()
        self._later()
        blob = self.git(self.d, "rev-parse", f"{sha}:{PADDING[0]}").strip()
        arrival_record.add_decisions("acme/app", [arrival_record.Decision(
            PADDING[0], blob, (sha, root), arrival_record.TAKE_OUT_DECISION)])
        self._run()
        self.assertEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                              f"fonts-elsewhere:{PADDING[0]}").returncode)
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:{PADDING[0]}").returncode)

    def test_a_saved_keep_naming_another_commit_hides_nothing(self):
        sha = self._deliver()
        self._later()
        blob = self.git(self.d, "rev-parse", f"{sha}:{PADDING[0]}").strip()
        arrival_record.add_decisions("acme/app", [arrival_record.Decision(
            PADDING[0], blob, ("e" * 40,), arrival_record.KEEP_DECISION)])
        resolver, asked = _answering(KEEP)
        self._run(resolver)
        self.assertIn(PADDING[0], [f.path for q in asked for f in q.files])

    def test_a_linked_store_of_answers_is_named_and_applies_nothing(self):
        sha = self._deliver()
        self._later()
        blob = self.git(self.d, "rev-parse", f"{sha}:{PADDING[0]}").strip()
        arrival_record.add_decisions("other/slug", [arrival_record.Decision(
            PADDING[0], blob, (sha,), arrival_record.TAKE_OUT_DECISION)])
        store = arrival_record.state_dir("acme/app") / arrival_record.DECIDED_NAME
        store.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(arrival_record.state_dir("other/slug") / arrival_record.DECIDED_NAME, store)
        outcome = self._run()
        self.assertIn(Cause.ARRIVALS_RECORD_UNREADABLE, self._causes(outcome))
        self.assertTrue(self._in_history(PADDING[0]))

    def test_answers_that_cannot_be_saved_are_named(self):
        store = arrival_record.state_dir("acme/app") / arrival_record.DECIDED_NAME
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text("{not json")
        self._deliver()
        self._later()
        outcome = self._run(_answering(KEEP)[0])
        self.assertIn(Cause.ARRIVALS_ANSWERS_NOT_SAVED, self._causes(outcome))
        self.assertIn(Cause.ARRIVALS_RECORD_UNREADABLE, self._causes(outcome))
        self.assertTrue(outcome.needs_review)

    def test_a_take_out_that_could_not_be_placed_is_not_reported_removed(self):
        self._deliver()
        self._later()
        with mock.patch.object(amendmod, "_commits_after", return_value=None):
            outcome = self._run(_answering(TAKE_OUT)[0])
        self.assertIn(Cause.REMOVAL_NOT_CONFIRMED, self._causes(outcome))
        for path in PADDING:
            self.assertNotIn(path, getattr(outcome, "removed", ()) or ())

    def test_an_answer_naming_a_file_not_offered_removes_nothing_else(self):
        self._deliver()
        self._later()
        outcome = self._run(lambda q: DeliveryAnswer(TAKE_OUT, ("a.txt", "later.txt"))
                            if isinstance(q, DeliveryQuestion) else Resolution(KEEP))
        self.assertTrue(self._in_history("a.txt"))
        self.assertTrue(self._in_history("later.txt"))
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)
        self.assertTrue(outcome.completed)

    def test_a_version_edited_after_it_arrived_stays(self):
        self._deliver()
        arrived = self._blob(PADDING[1])
        self.write(self.d, PADDING[1], '{"configurations": []}\n')
        self.commit(self.d, "the developer edits it")
        resolver, _asked = _answering(TAKE_OUT)
        self._run(resolver)
        self.assertFalse(self._in_history(PADDING[1], arrived))
        self.assertEqual('{"configurations": []}\n', self.git(self.d, "show", f"HEAD:{PADDING[1]}"))

    def test_a_genuine_copy_elsewhere_stays_and_the_run_completes(self):
        self.write(self.d, "vendor/fa-regular-400.woff2", "genuine " + PADDING[0] + "\n")
        self.commit(self.d, "vendor the icon set")
        self._deliver()
        self._later()
        resolver, _asked = _answering(TAKE_OUT)
        outcome = self._run(resolver)
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertNotIn(Cause.PAYLOAD_STILL_REACHABLE, self._causes(outcome))
        self.assertNotIn(Cause.PAYLOAD_REACHABLE_FROM_OTHER_REFS, self._causes(outcome))
        self.assertFalse(self._in_history(PADDING[0]))
        self.assertTrue(self._in_history("vendor/fa-regular-400.woff2"))
        self.assertFalse(self._in_history(PAYLOAD))


class TestWhatIsPutToTheOperator(_Delivery):
    """One question per delivery, holding only the files nothing else decides."""

    def test_the_question_names_the_commit_and_what_saw_removes_from_it(self):
        delivery = self._deliver()
        self._later()
        resolver, asked = _answering(KEEP)
        self._run(resolver)
        self.assertEqual(1, len(asked))
        question = asked[0]
        self.assertEqual(delivery, question.commit)
        self.assertEqual("add build tooling", question.subject)
        self.assertTrue(question.date)
        self.assertEqual((PAYLOAD,), question.removing)
        self.assertEqual(set(PADDING), {f.path for f in question.files})
        self.assertEqual({self._blob(p) for p in PADDING}, {f.blob for f in question.files})

    def test_the_question_says_how_many_project_files_name_each_file(self):
        self._deliver()
        self.write(self.d, "README.md", "debug with launch.json\n")
        self.commit(self.d, "readme")
        resolver, asked = _answering(KEEP)
        self._run(resolver)
        self.assertEqual({PADDING[0]: 0, PADDING[1]: 1}, dict(asked[0].named_by))

    def test_a_file_the_delivery_changed_does_not_count_as_naming_its_files(self):
        self.write(self.d, "NOTES.md", "notes\n")
        self.commit(self.d, "notes")
        self.write(self.d, "NOTES.md", "notes: debug with launch.json\n")
        self._deliver()
        self._later()
        resolver, asked = _answering(KEEP)
        self._run(resolver)
        self.assertIn("NOTES.md", asked[0].changed)
        self.assertEqual(0, dict(asked[0].named_by)[PADDING[1]])

    def test_a_file_with_its_own_finding_keeps_its_own_question(self):
        self._deliver()
        self._later()
        asked_files = []

        def resolve(question):
            if isinstance(question, DeliveryQuestion):
                asked_files.extend(f.path for f in question.files)
                return DeliveryAnswer(KEEP)
            asked_files.append(("own", question.path))
            return Resolution(KEEP)

        own = Finding("suspect", "fake-font", Severity.HIGH, PADDING[0], "unsure",
                      confidence=HEURISTIC)
        self._run(resolve, findings=[_foreign(), own])
        self.assertIn(("own", PADDING[0]), asked_files)
        self.assertNotIn(PADDING[0], asked_files)
        self.assertIn(PADDING[1], asked_files)

    def test_a_changed_file_is_named_and_never_removed(self):
        self.write(self.d, "a.txt", "base\nadded by the delivery\n")
        self._deliver()
        self._later()
        resolver, asked = _answering(TAKE_OUT)
        self._run(resolver)
        self.assertEqual(("a.txt",), asked[0].changed)
        self.assertNotIn("a.txt", {f.path for f in asked[0].files})
        self.assertEqual("base\nadded by the delivery\n", self.git(self.d, "show", "HEAD:a.txt"))

    def test_a_first_commit_carrying_the_payload_is_named_not_offered(self):
        self.git(self.d, "checkout", "-q", "--orphan", "other")
        self.git(self.d, "rm", "-rq", "--cached", ".")
        (self.d / "a.txt").unlink()
        self._deliver()
        resolver, asked = _answering(TAKE_OUT)
        outcome = self._run(resolver)
        self.assertEqual([], asked)
        self.assertIn(Cause.ARRIVALS_IN_FIRST_COMMIT, self._causes(outcome))
        self.assertTrue(outcome.needs_review)
        self.assertFalse(self._in_history(PAYLOAD))
        for path in PADDING:
            self.assertTrue(self._in_history(path), path)

    def test_at_most_ten_deliveries_are_asked_and_the_rest_are_named(self):
        payloads = [f"public/fonts/payload-{n}.woff2" for n in range(11)]
        for n, payload in enumerate(payloads):
            self._deliver(payload, (f"pad/{n}.txt",), subject=f"delivery {n}")
        resolver, asked = _answering(KEEP)
        outcome = self._run(resolver, findings=[_foreign(p) for p in payloads])
        self.assertEqual(10, len(asked))
        undecided = [r for r in outcome.reasons if r.cause is Cause.ARRIVALS_UNDECIDED]
        self.assertEqual(1, len(undecided))
        self.assertEqual("1", undecided[0].detail)
        self.assertTrue(outcome.needs_review)

    def test_the_same_file_added_by_two_deliveries_is_asked_once(self):
        root = self._rev()
        self._deliver()
        self.git(self.d, "checkout", "-q", "-b", "second", root)
        self._deliver(subject="the same bundle on another branch")
        self.git(self.d, "checkout", "-q", self.base)
        resolver, asked = _answering(KEEP)
        self._run(resolver)
        self.assertEqual(1, len(asked))

    def test_the_evil_merge_sweep_removes_what_the_merge_created_without_asking(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.targets import LocalRepoTarget
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/loader.js",
                   "global['_V']=function(x){return x};require('child_process').exec('id');\n")
        self.write(self.d, "vendor/helper.txt", "helper\n")
        self.write(self.d, "docs/notes.md", "# notes\n")
        self.commit(self.d, "Merge pull request #7 from feature")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        resolver, asked = _answering(KEEP)
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan):
            outcome = amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                    pusher=lambda *a: PushResult(True), resolver=resolver)
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertFalse(self._in_history("vendor/loader.js"))
        self.assertFalse(self._in_history("vendor/helper.txt"))
        self.assertEqual(1, len(asked))
        self.assertEqual(["docs/notes.md"], [f.path for f in asked[0].files])
        self.assertTrue(self._in_history("docs/notes.md"))


    def test_a_merge_that_could_not_be_rewritten_is_asked_about_once_its_payload_is_taken_out(self):
        from types import SimpleNamespace
        from stayawake.bots.security.pr.resolve import REMOVE, Resolution
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.targets import LocalRepoTarget
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/loader.js",
                   "global['_V']=function(x){return x};require('child_process').exec('id');\n")
        self.write(self.d, "docs/notes.md", "# notes\n")
        self.commit(self.d, "Merge pull request #7 from feature")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        asked: list[DeliveryQuestion] = []

        def resolve(question):
            if isinstance(question, DeliveryQuestion):
                asked.append(question)
                return DeliveryAnswer(KEEP, ())
            return Resolution(REMOVE)

        refused = SimpleNamespace(ok=False, kind="replacement", refusal="refused")
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan), \
                mock.patch("stayawake.bots.security.pr.amend.replacement_tree",
                           return_value=refused):
            amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                          pusher=lambda *a: PushResult(True), resolver=resolve)
        self.assertFalse(self._in_history("vendor/loader.js"))
        self.assertEqual(["docs/notes.md"], [f.path for q in asked for f in q.files])

    def test_removing_a_genuine_file_of_a_merge_that_could_not_be_rewritten_takes_it_out(self):
        from types import SimpleNamespace
        from stayawake.bots.security.pr.resolve import REMOVE, Resolution
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.targets import LocalRepoTarget
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.write(self.d, "docs/guide.md", "# guide\n")
        self.commit(self.d, "add docs")
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/loader.js",
                   "global['_V']=function(x){return x};require('child_process').exec('id');\n")
        self.write(self.d, "vendor/helper.txt", "helper\n")
        self.commit(self.d, "Merge pull request #7 from feature")
        scan = scan_target(LocalRepoTarget(self.d, str(self.d), ScanOptions()), load_signatures())
        refused = SimpleNamespace(ok=False, kind="replacement", refusal="refused")
        with self._remote(), \
                mock.patch("stayawake.bots.security.pr.amend.scan_target", return_value=scan), \
                mock.patch("stayawake.bots.security.pr.amend.replacement_tree",
                           return_value=refused), \
                mock.patch("stayawake.bots.security.pr.amend.gitamend.replacement_commit",
                           side_effect=AssertionError("a handled merge is not replaced")):
            outcome = amend_outcome(self.d, "acme/app", ScanOptions(), load_signatures(), [], "t",
                                    pusher=lambda *a: PushResult(True),
                                    resolver=lambda q: Resolution(REMOVE))
        self.assertTrue(outcome.completed, self._causes(outcome))
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:vendor/helper.txt").returncode)
        self.assertNotEqual(0, self.git_may_fail(self.d, "cat-file", "-e",
                                                 f"{base}:vendor/loader.js").returncode)

    def test_a_genuine_file_of_a_merge_is_taken_out_only_from_that_merge_and_after(self):
        base = self.git(self.d, "rev-parse", "--abbrev-ref", "HEAD").strip()
        self.git(self.d, "checkout", "-q", "-b", "own-helper")
        self.write(self.d, "vendor/helper.txt", "helper\n")
        own = self.commit(self.d, "the project's own helper")
        self.git(self.d, "checkout", "-q", base)
        self.git(self.d, "merge", "--no-commit", "--no-ff", "feature")
        self.write(self.d, "vendor/helper.txt", "helper\n")
        merge = self.commit(self.d, "Merge pull request #7 from feature")
        self._later()
        taken, holders = {}, {}
        outcome, scheduled = amendmod._register_merge_file_removal(
            self.d, merge, "vendor/helper.txt", lambda tree, path: None, set(), set(), taken,
            set(), holders)
        self.assertEqual(("", True), (outcome, scheduled))
        self.assertIn(merge, holders["vendor/helper.txt"])
        self.assertNotIn(own, holders["vendor/helper.txt"])

class TestTheRecord(unittest.TestCase):
    """The record saw keeps between runs reads back what it wrote and nothing else."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        self.folder = Path(tempfile.mkdtemp(prefix="saw-arrival-record-"))
        self.addCleanup(__import__("shutil").rmtree, self.folder, True)
        patched = mock.patch.dict("os.environ", {"XDG_STATE_HOME": str(self.folder)})
        patched.start()
        self.addCleanup(patched.stop)

    def _question(self, *paths, commit="a" * 40):
        return DeliveryQuestion(commit, "2026-01-01", "subject", ("p.js",),
                                tuple(ArrivedFile(p, "b" * 40) for p in paths))

    def test_what_is_written_reads_back(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [self._question("x.txt", "y.txt")])
        records, unreadable = arrival_record.read_all("acme/app")
        self.assertEqual([], unreadable)
        (read,) = records[0].deliveries
        self.assertTrue(read.recorded)
        self.assertEqual(["x.txt", "y.txt"], [f.path for f in read.files])

    def test_a_second_write_adds_and_removes_nothing(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [self._question("x.txt")])
        arrival_record.write(where, [self._question("y.txt"),
                                     self._question("z.txt", commit="c" * 40)])
        (record,), _ = arrival_record.read_all("acme/app")
        files = {f.path for q in record.deliveries for f in q.files}
        self.assertEqual({"x.txt", "y.txt", "z.txt"}, files)

    def test_a_record_not_in_its_own_form_is_unreadable_and_left_alone(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [self._question("x.txt")])
        target = where / arrival_record.RECORD_NAME
        stored = json.loads(target.read_text())
        stored["deliveries"][0]["files"][0]["blob"] = "not an object id"
        target.write_text(json.dumps(stored))
        records, unreadable = arrival_record.read_all("acme/app")
        self.assertEqual([], records)
        self.assertEqual([str(target)], unreadable)
        self.assertIsNone(arrival_record.write(where, [self._question("y.txt")]))
        self.assertIn("not an object id", target.read_text())

    def test_the_ids_a_delivery_commit_has_had_are_kept(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [replace(self._question("x.txt"), known_as=("b" * 40,))])
        (record,), _ = arrival_record.read_all("acme/app")
        self.assertEqual(("b" * 40,), record.deliveries[0].known_as)

    def test_a_record_without_later_ids_reads(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [self._question("x.txt")])
        stored = where / arrival_record.RECORD_NAME
        data = json.loads(stored.read_text())
        for delivery in data["deliveries"]:
            delivery.pop("known_as", None)
        stored.write_text(json.dumps(data))
        (record,), unreadable = arrival_record.read_all("acme/app")
        self.assertEqual([], unreadable)
        self.assertEqual((), record.deliveries[0].known_as)

    def test_a_record_left_with_nothing_to_ask_is_removed(self):
        where = arrival_record.state_dir("acme/app") / "run"
        arrival_record.write(where, [self._question("x.txt")])
        (record,), _ = arrival_record.read_all("acme/app")
        self.assertTrue(arrival_record.keep_only(record, [self._question()]))
        self.assertFalse((where / arrival_record.RECORD_NAME).exists())


if __name__ == "__main__":
    unittest.main()

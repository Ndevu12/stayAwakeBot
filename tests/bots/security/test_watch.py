#!/usr/bin/env python3
"""One unattended pass.

Nobody is present. That changes two things from `saw harden`: what may be ended, and whether a
password may be asked for. Both are pinned here."""
from __future__ import annotations

import subprocess
import types
import unittest
from unittest import mock

from stayawake.bots.security import liveledger, schedule, watch, watchstate, watchstatus
from stayawake.bots.security.watchevents import SENTENCE_FOR
from stayawake.bots.security.harden.live import Ending
from stayawake.bots.security.livecode import LiveCode, fingerprint
from stayawake.utils import elevate, exitcodes
from stayawake.utils.procsnap import Process, Snapshot


def _held(pid, code, confirmed):
    return LiveCode(Process(pid=pid, argv=("node", "-e", code)), code, "reason", confirmed)


def _never(*args, **kwargs):
    """Fail the test rather than reach this machine's own service manager."""
    raise AssertionError(f"a test reached the real service manager: {args[0] if args else kwargs}")


_NO_MANAGER = mock.patch.object(
    schedule, "subprocess",
    types.SimpleNamespace(run=_never, SubprocessError=subprocess.SubprocessError))

_ITEM_BEFORE = False


def setUpModule():
    """Cut this module off from the machine's own service manager and login item."""
    global _ITEM_BEFORE
    _ITEM_BEFORE = schedule.item_path().exists()
    _NO_MANAGER.start()


def tearDownModule():
    """Nothing here may place a login item, or register a job, on the machine running the suite.

    Two canaries because they see different things. A registration is not a file, so the filesystem
    check below is blind to it; a `**kwargs` spread is not visible to the static guard either.
    """
    _NO_MANAGER.stop()
    if schedule.item_path().exists() and not _ITEM_BEFORE:
        where = schedule.item_path()
        where.unlink(missing_ok=True)
        raise AssertionError(f"a test in this module placed {where.name} on this machine")


class _Recorder:
    """Stands in for the ender and keeps what it was handed."""

    def __init__(self, ending=None):
        self.ending = ending or Ending(matched=1, ended=1, quiet=True)
        self.find = None
        self.elevated = None

    def __call__(self, *, find, elevated):
        self.find, self.elevated = find, elevated
        return self.ending


_READABLE = Snapshot(processes=[Process(pid=1, argv=("launchd",))])


def _looks(first, *later):
    """A finder that sees `first` before the stop and each of `later` after it (the last repeats)."""
    answers = [list(first)] + [list(x) for x in later or ([],)]
    return lambda: answers.pop(0) if len(answers) > 1 else list(answers[0])


def _run(seen, ender=None, before=None, after=()):
    saved = {}
    code, text = watch.watch_once(
        find=_looks(seen, list(after)), stop=ender, load=lambda: before or liveledger.Ledger(),
        save=lambda ledger: saved.setdefault("ledger", ledger) or True, look=lambda: _READABLE)
    return code, text, saved.get("ledger"), ender


class TestARecordThatCouldNotBeKeptIsSaid(unittest.TestCase):
    def test_an_unwritable_or_changed_record_is_said_and_the_pass_is_incomplete(self):
        cases = ((lambda ledger: False, liveledger.Ledger(status=liveledger.LOADED)),
                 (lambda ledger: True, liveledger.Ledger(status=liveledger.EDITED)),
                 (lambda ledger: True, liveledger.Ledger(status=liveledger.CORRUPT)))
        for save, before in cases:
            with self.subTest(status=before.status):
                code, kinds = watch.examine(find=lambda: [], stop=None, load=lambda b=before: b,
                                            save=save, look=lambda: _READABLE)
                self.assertIn(watch.NOT_REMEMBERED, kinds)
                self.assertEqual(code, exitcodes.INCOMPLETE)

    def test_a_kept_record_says_nothing_about_it(self):
        code, kinds = watch.examine(find=lambda: [], stop=None, load=liveledger.Ledger,
                                    save=lambda ledger: True, look=lambda: _READABLE)
        self.assertEqual((code, kinds), (exitcodes.CLEAN, (watch.QUIET,)))


class TestOnlyWhatEndedIsRecordedAsEnded(unittest.TestCase):
    def test_ending_one_of_two_marks_only_that_one(self):
        first, second = _held(1, "one", True), _held(2, "two", True)
        saved = {}
        watch.examine(find=_looks([first, second], [second]),
                      stop=_Recorder(Ending(matched=2, ended=1, survived=[2], quiet=True)),
                      load=liveledger.Ledger, look=lambda: _READABLE,
                      save=lambda ledger: saved.setdefault("ledger", ledger) or True)
        entries = saved["ledger"].entries
        self.assertEqual(entries[fingerprint("one")].ended, 1)
        self.assertEqual(entries[fingerprint("two")].ended, 0,
                         "code still running after the stop was recorded as ended")


class TestCodeRestartedInANewProcessCameBack(unittest.TestCase):
    def test_a_respawn_is_ended_now_and_said_to_have_come_back_on_the_next_pass(self):
        original, respawn = _held(10, "bad", True), _held(11, "bad", True)
        first = {}
        watch.examine(find=_looks([original], [respawn]), stop=_Recorder(), look=lambda: _READABLE,
                      load=liveledger.Ledger,
                      save=lambda ledger: first.setdefault("ledger", ledger) or True)
        self.assertEqual(first["ledger"].entries[fingerprint("bad")].ended, 1,
                         "a process that ended was not counted because its code restarted")
        _code, kinds = watch.examine(find=_looks([respawn], []), stop=_Recorder(),
                                     look=lambda: _READABLE, load=lambda: first["ledger"],
                                     save=lambda ledger: True)
        self.assertIn(watch.RETURNED, kinds)

    def test_the_same_process_still_running_after_the_stop_could_not_be_stopped(self):
        held = _held(10, "bad", True)
        code, text, _l, _e = _run([held], _Recorder(), after=[held])
        self.assertIn(SENTENCE_FOR[watch.LEFT], text)
        self.assertEqual(code, exitcodes.INCOMPLETE)

    def test_a_second_look_that_cannot_be_read_claims_nothing_ended(self):
        saved = {}
        looks = iter([_READABLE, Snapshot(processes=[])])
        watch.examine(find=None, stop=_Recorder(), look=lambda: next(looks),
                      load=liveledger.Ledger,
                      save=lambda ledger: saved.setdefault("ledger", ledger) or True)
        self.assertEqual(watch.what_the_stop_did([_held(1, "x", True)], None), watch.StopOutcome())
        for unreadable in (Snapshot(processes=[]), Snapshot(supported=False)):
            with self.subTest(unreadable=unreadable):
                self.assertIsNone(watch._look_again(None, lambda s=unreadable: s),
                                  "an unreadable second look was read as nothing running")


class TestTheLedgerNeverKeepsThePassFromEndingCode(unittest.TestCase):
    def test_a_ledger_that_cannot_be_read_still_lets_the_pass_end_identified_code(self):
        def boom():
            raise RecursionError("deep")
        ender = _Recorder()
        code, kinds = watch.examine(find=lambda: [_held(7, "bad", True)], stop=ender, load=boom,
                                    save=lambda ledger: True, look=lambda: _READABLE)
        self.assertIsNotNone(ender.find, "the pass stopped nothing because of its ledger")
        self.assertIn(watch.NOT_REMEMBERED, kinds)


class TestAPassThatCouldNotLookIsNeverQuiet(unittest.TestCase):
    def test_a_process_table_it_cannot_read_is_not_a_quiet_machine(self):
        for snap in (Snapshot(supported=False), Snapshot(processes=[])):
            code, text = watch.watch_once(find=lambda: [], stop=None, load=liveledger.Ledger,
                                          save=lambda ledger: True, look=lambda s=snap: s)
            self.assertEqual(code, exitcodes.INCOMPLETE)
            self.assertNotIn(SENTENCE_FOR[watch.QUIET], text)
            self.assertIn("could not be examined", text)

    def test_a_pass_that_failed_is_reported(self):
        said = []

        def boom():
            raise RuntimeError("x")
        watch.keep_going(once=boom, sleep=lambda n: None, passes=1, report=said.append)
        self.assertEqual(said, [SENTENCE_FOR[watch.PASS_FAILED]])


class TestItNeverAsksForAPassword(unittest.TestCase):
    """A prompt nobody can answer is a scheduled run that hangs, and a password asked for where
    nobody is watching is a password asked of whoever is."""

    def test_the_ender_is_given_something_that_refuses_privilege(self):
        ender = _Recorder()
        _run([_held(1, "bad", True)], ender)
        self.assertIs(ender.elevated, watch._never_asks)

    def test_and_that_something_ends_nothing_and_says_it_could_not_ask(self):
        outcome, ended = watch._never_asks([1, 2], signatures={})
        self.assertEqual(outcome, elevate.CANNOT_ASK)
        self.assertEqual(ended, [])


class TestItEndsOnlyWhatWasIdentified(unittest.TestCase):
    def test_the_ender_is_given_a_view_that_drops_the_merely_suspected(self):
        ender = _Recorder()
        seen = [_held(1, "identified", True), _held(2, "shape-only", False)]
        _run(seen, ender, after=seen)
        self.assertEqual([lc.process.pid for lc in ender.find()], [1])

    def test_nothing_identified_means_the_ender_is_never_called(self):
        ender = _Recorder()
        code, text, _led, _ = _run([_held(2, "shape-only", False)], ender)
        self.assertIsNone(ender.find, "the ender must not run when nothing was identified")
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertIn("cannot identify", text)


class TestItRemembersWhatItSaw(unittest.TestCase):
    def test_the_merely_suspected_reaches_the_record_even_though_it_was_left_alone(self):
        _c, _t, ledger, _e = _run([_held(2, "shape-only", False)])
        self.assertIn(fingerprint("shape-only"), ledger.entries)

    def test_something_stopped_before_is_named_as_having_come_back(self):
        code = "bad"
        before = liveledger.record(liveledger.Ledger(), [_held(1, code, True)],
                                   ended_keys={fingerprint(code)})
        _c, text, _l, _e = _run([_held(1, code, True)], _Recorder(), before=before)
        self.assertIn("running again", text)

    def test_something_seen_before_but_never_stopped_has_not_come_back(self):
        code = "bad"
        before = liveledger.record(liveledger.Ledger(), [_held(1, code, True)])
        _c, text, _l, _e = _run([_held(1, code, True)], _Recorder(), before=before)
        self.assertNotIn("running again", text)

    def test_something_new_is_not(self):
        _c, text, _l, _e = _run([_held(1, "fresh", True)], _Recorder())
        self.assertNotIn("running again", text)


class TestWhatItCouldNotFinishIsNotSilence(unittest.TestCase):
    def test_an_unfinished_ending_is_incomplete_and_names_the_verb_that_can_finish(self):
        ender = _Recorder(Ending(matched=2, ended=1, survived=[9], quiet=True))
        code, text, _l, _e = _run([_held(1, "bad", True)], ender)
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertIn("saw harden", text)

    def test_a_stop_that_ended_nothing_is_not_reported_as_stopped(self):
        ender = _Recorder(Ending(matched=1, ended=0, survived=[9], quiet=True))
        code, text, _l, _e = _run([_held(1, "bad", True)], ender)
        self.assertNotIn(SENTENCE_FOR[watch.ENDED], text)
        self.assertIn(SENTENCE_FOR[watch.LEFT], text)
        self.assertEqual(code, exitcodes.INCOMPLETE)

    def test_a_finished_ending_reports_findings_not_clean(self):
        # It ended them, but this machine WAS running identified code; a gate must not read that as
        # a clean pass.
        code, _t, _l, _e = _run([_held(1, "bad", True)], _Recorder())
        self.assertEqual(code, exitcodes.FINDINGS)


class TestItKeepsGoing(unittest.TestCase):
    """The pass is only protection while it keeps happening."""

    def test_it_makes_a_pass_sleeps_and_makes_another(self):
        slept = []
        watch.keep_going(once=lambda: (exitcodes.CLEAN, (watch.QUIET,)), sleep=slept.append, passes=3)
        self.assertEqual(slept, [watch.BETWEEN_PASSES, watch.BETWEEN_PASSES])

    def test_one_bad_pass_does_not_end_the_watch(self):
        # A machine stops being watched exactly when something goes wrong on it.
        made = []

        def boom():
            made.append(1)
            raise RuntimeError("a pass went wrong")

        code = watch.keep_going(once=boom, sleep=lambda n: None, passes=3)
        self.assertEqual(len(made), 3, "the watch stopped at the first bad pass")
        self.assertEqual(code, exitcodes.INCOMPLETE)

    def test_a_quiet_pass_says_nothing(self):
        said = []
        watch.keep_going(once=lambda: (exitcodes.CLEAN, (watch.QUIET,)), sleep=lambda n: None,
                         passes=2, report=said.append)
        self.assertEqual(said, [], "a watch that speaks every pass is one nobody reads")

    def test_a_pass_that_found_something_does_say_it(self):
        said = []
        watch.keep_going(once=lambda: (exitcodes.FINDINGS, (watch.ENDED,)),
                         sleep=lambda n: None, passes=1, report=said.append)
        self.assertEqual(said, [SENTENCE_FOR[watch.ENDED]])


class TestItSchedulesItselfRatherThanBeingScheduled(unittest.TestCase):
    """The verb that runs on a schedule owns its schedule. Asking a machine to keep a kill
    primitive running is its own decision, not a side effect of hardening one."""

    def test_asking_once_says_so_and_asking_twice_does_not(self):
        first = watch.schedule_it(settle=lambda: schedule.Scheduling(state=schedule.PLACED))
        again = watch.schedule_it(settle=lambda: schedule.Scheduling(state=schedule.IN_PLACE))
        self.assertEqual(first[0], exitcodes.CLEAN)
        self.assertNotEqual(first[1], again[1])
        self.assertIn("already", again[1])

    def test_it_does_not_claim_to_be_running_when_it_starts_at_the_next_login(self):
        # A service manager that would not answer leaves the item in place but not yet running.
        # Saying "from now on" there is a claim about this machine that is not true yet.
        now = watch.schedule_it(settle=lambda: schedule.Scheduling(state=schedule.PLACED, active=True))
        later = watch.schedule_it(settle=lambda: schedule.Scheduling(state=schedule.PLACED, active=False))
        self.assertIn("from now on", now[1])
        self.assertIn("next login", later[1])

    def test_one_changed_underneath_you_reads_differently_from_a_first_time(self):
        put_back = watch.schedule_it(settle=lambda: schedule.Scheduling(state=schedule.REPLACED))
        self.assertIn("put back", put_back[1])

    def test_a_platform_that_cannot_says_so_rather_than_claiming_it_did(self):
        code, text = watch.schedule_it(
            settle=lambda: schedule.Scheduling(problem="not implemented on this platform"))
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertIn("could not", text)

    def test_taking_it_back_removes_saws_own_and_leaves_anything_else(self):
        gone = watch.unschedule_it(remove=lambda: schedule.REMOVED)
        never = watch.unschedule_it(remove=lambda: schedule.NOTHING_TO_REMOVE)
        theirs = watch.unschedule_it(remove=lambda: schedule.ALTERED)
        self.assertEqual(gone[0], exitcodes.CLEAN)
        self.assertEqual(never[0], exitcodes.CLEAN)
        self.assertEqual(theirs[0], exitcodes.INCOMPLETE)
        self.assertIn("left alone", theirs[1])


class TestHardenSetsItUpToo(unittest.TestCase):
    """`saw watch` owns the arrangement; hardening a machine also puts it in place, the way it puts
    the scan-on-clone hooks in place."""

    def test_hardening_a_machine_also_asks_it_to_keep_checking_itself(self):
        import inspect
        from stayawake.bots.security import harden
        self.assertIn("schedule_pass", inspect.signature(harden.run).parameters)
        self.assertIn("schedule_pass", harden.TOUCHES_THIS_MACHINE)

    def test_and_taking_the_controls_back_takes_that_back_too(self):
        import inspect
        from stayawake.bots.security import harden
        self.assertIn("unschedule", inspect.signature(harden.take_back).parameters)


class TestTheCommandSurfaceIsTwoThings(unittest.TestCase):
    """Start checking, and stop. The pass the scheduled item runs is saw's own business and is not
    offered as a choice."""

    def _parse(self, *args):
        import argparse
        from stayawake.cli.commands import watch as cli
        parser = argparse.ArgumentParser()
        cli.register(parser.add_subparsers())
        return parser.parse_args(["watch", *args])

    def test_bare_starts_it_and_stop_stops_it(self):
        from stayawake.cli.commands import watch as cli
        self.assertIs(self._parse().func, cli.run)
        self.assertIs(self._parse("stop").func, cli.run_stop)

    def test_the_scheduled_pass_is_reachable_but_not_offered(self):
        from stayawake.cli.commands import watch as cli
        import argparse
        self.assertIs(self._parse("run").func, cli.run_internal)
        parser = argparse.ArgumentParser()
        cli.register(parser.add_subparsers())
        self.assertNotIn("run", parser.format_help())

    def test_the_scheduled_item_calls_exactly_that(self):
        # If the item and the command surface drift, the machine schedules something that no longer
        # exists and stops checking itself silently.
        saw = ["/usr/local/bin/python", "-E", "-P", "-m", "stayawake"]
        for platform, expected in (("darwin", "<string>watch</string>\n\t\t<string>run</string>"),
                                   ("linux", "ExecStart=" + " ".join(saw) + " watch run")):
            with self.subTest(platform=platform), \
                    mock.patch.object(schedule.sys, "platform", platform):
                self.assertIn(expected, schedule.content(saw))


if __name__ == "__main__":
    unittest.main()


class TestItSaysWhetherThisMachineIsCheckingItself(unittest.TestCase):
    """`saw watch status`. Whether the job is loaded is asked of the service manager, because one
    unprivileged command stops it without touching a byte."""

    def _status(self, state, running=True, supported=True, record=None, now=1000.0,
                since=995.0):
        return watchstatus.status_of(supported=lambda: supported, verdict=lambda: state,
                               running=lambda: running, record=lambda: dict(record or {}),
                               clock=lambda: now, placed_since=lambda: since,
                               acknowledged=lambda: None)

    def test_held_with_no_pass_since_it_was_placed_long_ago_is_not_clean(self):
        code, text = self._status(schedule.PRISTINE, since=0.0, now=10_000.0)
        self.assertEqual((code, text), (exitcodes.FINDINGS, watchstatus._STALLED))

    def test_held_but_not_checking_recently_is_not_clean(self):
        code, text = self._status(schedule.PRISTINE, record={"last_good": 0.0}, now=10_000.0)
        self.assertEqual((code, text), (exitcodes.FINDINGS, watchstatus._STALLED))

    def test_code_that_came_back_is_said_until_it_is_dealt_with(self):
        _, text = self._status(schedule.PRISTINE, record={"last_good": 990.0,
                                                          "unacknowledged": 5.0})
        self.assertIn("saw harden", text)

    def test_it_shows_what_a_notification_pointed_to(self):
        record = {"last_good": 990.0, "since": {"ended": 1}}
        code, text = self._status(schedule.PRISTINE, record=record)
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertIn("Code running here was stopped once.", text)
        code, text = self._status(schedule.PRISTINE,
                                  record={"last_good": 990.0, "not_stopped": 900.0})
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertIn(watchstate.LINE_FOR[watchstate.NOT_STOPPED], text)

    def test_in_place_and_running_is_the_only_clean_answer(self):
        self.assertEqual(self._status(schedule.PRISTINE, running=True),
                         (exitcodes.CLEAN, watchstatus._CHECKING))

    def test_in_place_but_not_loaded_says_from_the_next_login(self):
        code, text = self._status(schedule.PRISTINE, running=False)
        self.assertNotEqual(code, exitcodes.CLEAN)
        self.assertIn("next login", text)

    def test_nothing_there_says_it_is_not_checking(self):
        code, text = self._status(schedule.ABSENT)
        self.assertEqual((code, text), (exitcodes.FINDINGS, watchstatus._NOT_CHECKING))

    def test_changed_underneath_you_is_not_reported_as_absent(self):
        for state in (schedule.ALTERED, schedule.UNREADABLE):
            with self.subTest(state=state):
                code, text = self._status(state)
                self.assertEqual((code, text), (exitcodes.FINDINGS, watchstatus._WAS_CHANGED))

    def test_a_platform_without_one_says_it_could_not_tell(self):
        self.assertEqual(self._status(schedule.PRISTINE, supported=False),
                         (exitcodes.INCOMPLETE, watchstatus._CANNOT_TELL))

    def test_a_verdict_that_raises_does_not_take_the_command_down(self):
        def boom():
            raise OSError("x")
        code, text = watchstatus.status_of(supported=lambda: True, verdict=boom, running=lambda: True,
                                     record=dict, placed_since=lambda: None,
                                     acknowledged=lambda: None)
        self.assertEqual((code, text), (exitcodes.INCOMPLETE, watchstatus._CANNOT_TELL))

    def test_it_names_no_location(self):
        for state in (schedule.PRISTINE, schedule.ABSENT, schedule.ALTERED):
            with self.subTest(state=state):
                self.assertNotIn("/", self._status(state, running=False)[1].replace("`", ""))

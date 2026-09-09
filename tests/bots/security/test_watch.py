#!/usr/bin/env python3
"""One unattended pass.

Nobody is present. That changes two things from `saw harden`: what may be ended, and whether a
password may be asked for. Both are pinned here."""
from __future__ import annotations

import unittest

from stayawake.bots.security import liveledger, watch
from stayawake.bots.security.harden.live import Ending
from stayawake.bots.security.livecode import LiveCode, fingerprint
from stayawake.utils import elevate, exitcodes
from stayawake.utils.procsnap import Process


def _held(pid, code, confirmed):
    return LiveCode(Process(pid=pid, argv=("node", "-e", code)), code, "reason", confirmed)


class _Recorder:
    """Stands in for the ender and keeps what it was handed."""

    def __init__(self, ending=None):
        self.ending = ending or Ending(matched=1, ended=1, quiet=True)
        self.find = None
        self.elevated = None

    def __call__(self, *, find, elevated):
        self.find, self.elevated = find, elevated
        return self.ending


def _run(seen, ender=None, before=None):
    saved = {}
    code, text = watch.watch_once(
        find=lambda: list(seen), stop=ender, load=lambda: before or liveledger.Ledger(),
        save=lambda ledger: saved.setdefault("ledger", ledger) or True)
    return code, text, saved.get("ledger"), ender


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
        _run(seen, ender)
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

    def test_something_seen_before_is_named_as_having_come_back(self):
        code = "bad"
        before = liveledger.record(liveledger.Ledger(), [_held(1, code, True)])
        _c, text, _l, _e = _run([_held(1, code, True)], _Recorder(), before=before)
        self.assertIn("running again", text)

    def test_something_new_is_not(self):
        _c, text, _l, _e = _run([_held(1, "fresh", True)], _Recorder())
        self.assertNotIn("running again", text)


class TestWhatItCouldNotFinishIsNotSilence(unittest.TestCase):
    def test_an_unfinished_ending_is_incomplete_and_names_the_verb_that_can_finish(self):
        ender = _Recorder(Ending(matched=2, ended=1, survived=[9], quiet=True))
        code, text, _l, _e = _run([_held(1, "bad", True)], ender)
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertIn("saw harden", text)

    def test_a_finished_ending_reports_findings_not_clean(self):
        # It ended them, but this machine WAS running identified code; a gate must not read that as
        # a clean pass.
        code, _t, _l, _e = _run([_held(1, "bad", True)], _Recorder())
        self.assertEqual(code, exitcodes.FINDINGS)


if __name__ == "__main__":
    unittest.main()

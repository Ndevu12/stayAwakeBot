#!/usr/bin/env python3
"""The document `saw watch status --json` prints: the schedule, the open matters and what happened
since the last report, with no paths and no process numbers, the same facts the sentences carry."""
from __future__ import annotations

import unittest

from stayawake.bots.security import schedule, watchstatus, watchstate
from stayawake.bots.security.watchstatus import (
    CHANGED, COULD_NOT_TELL, FROM_NEXT_LOGIN, IN_PLACE, NOT_IN_PLACE)
from stayawake.bots.security.watchevents import ENDED

_RAISE = object()
_ALTERED = object()          # a schedule state that is neither pristine nor absent


def _doc(*, supported=True, state=schedule.PRISTINE, running=True, record=None,
         now=10_000.0, placed_since=9_990.0):
    def verdict():
        if state is _RAISE:
            raise RuntimeError("cannot read")
        return state
    return watchstatus.status_document(
        supported=lambda: supported, verdict=verdict, running=lambda: running,
        record=lambda: dict(record or {}), clock=lambda: now,
        placed_since=lambda: placed_since, acknowledged=lambda: None)


class TestSchedule(unittest.TestCase):
    def test_each_state_maps_to_one_schedule_word(self):
        cases = [
            (dict(state=schedule.PRISTINE, running=True), IN_PLACE, 0),
            (dict(state=schedule.PRISTINE, running=False), FROM_NEXT_LOGIN, None),
            (dict(state=schedule.ABSENT), NOT_IN_PLACE, None),
            (dict(state=_ALTERED), CHANGED, None),
            (dict(supported=False), COULD_NOT_TELL, None),
            (dict(state=_RAISE), COULD_NOT_TELL, None),
        ]
        for kwargs, word, exact_code in cases:
            with self.subTest(**kwargs):
                code, body = _doc(**kwargs)
                self.assertEqual(body["schedule"], word)
                if exact_code is not None:
                    self.assertEqual(code, exact_code)


class TestDocument(unittest.TestCase):
    def test_schema_version_is_first_and_one(self):
        _, body = _doc()
        self.assertEqual(next(iter(body)), "schema_version")
        self.assertEqual(body["schema_version"], 1)

    def test_a_clean_in_place_watcher_has_no_matters_and_no_since(self):
        code, body = _doc()
        self.assertEqual(body["matters"], [])
        self.assertNotIn("since", body)
        self.assertEqual(code, 0)

    def test_an_open_matter_carries_its_kind_line_and_urgency(self):
        code, body = _doc(record={"unacknowledged": 1.0})
        self.assertEqual(body["matters"],
                         [{"kind": watchstate.CAME_BACK,
                           "line": watchstate.LINE_FOR[watchstate.CAME_BACK], "urgent": True}])
        self.assertNotEqual(code, 0, "code that came back is a finding")

    def test_a_stalled_watcher_reports_not_checking_as_a_matter(self):
        _, body = _doc(record={"last_good": 0.0})
        kinds = [m["kind"] for m in body["matters"]]
        self.assertIn(watchstate.NOT_CHECKING, kinds)

    def test_since_is_present_only_when_something_happened(self):
        _, body = _doc(record={"last_good": 9_990.0, "since": {ENDED: 1}})
        self.assertEqual(body["since"]["heading"], "Since saw started watching:")
        self.assertEqual(body["since"]["lines"], ["Code running here was stopped once."])

    def test_the_document_names_no_path_and_no_process_number(self):
        _, body = _doc(record={"unacknowledged": 1.0, "not_stopped": 2.0, "undelivered": 3.0,
                               "last_good": 0.0, "since": {ENDED: 4}})
        strings = [m["line"] for m in body["matters"]]
        strings += body.get("since", {}).get("lines", []) + [body.get("since", {}).get("heading", "")]
        for text in strings:
            self.assertNotIn("/", text, f"a path leaked into the document: {text!r}")
            self.assertFalse(any(part.isdigit() and len(part) >= 3 for part in text.split()),
                             f"a process number leaked into the document: {text!r}")


if __name__ == "__main__":
    unittest.main()

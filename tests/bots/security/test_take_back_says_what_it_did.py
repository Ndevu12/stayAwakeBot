#!/usr/bin/env python3
"""`saw harden --take-back` states what it took back and what is left, in plain words."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import approvals as agentapprovals
from stayawake.bots.security.harden import denial
from stayawake.bots.security.harden import settings as editorsettings

_NEEDS_POSIX_NONROOT = (os.name == "posix"
                        and not (hasattr(os, "geteuid") and os.geteuid() == 0))
_STATE_NAMES = (denial.ENFORCING, denial.SELF_ENFORCING, denial.NEEDS_ROOT, denial.REMOVED,
                denial.NOTHING_TO_REMOVE, denial.LOCKED_OVER_CONTENT,
                denial.LEFT_OPEN_OVER_CONTENT, denial.HELD_BY_ANOTHER,
                denial.NOT_WHERE_IT_WAS_NAMED, denial.OCCUPIED, denial.NOT_HERE_YET)


def _take_back(outcomes, *, unscheduled="nothing-to-remove", editors=None, agents=None):
    """Take back over locations whose removal answers `outcomes`, touching nothing real."""
    by_path = {o.path: o for o in outcomes}
    return harden.take_back(supported=lambda: True, folders=lambda: list(by_path),
                            remove=lambda p: by_path[p], unschedule=lambda: unscheduled,
                            restore_editors=lambda: editors or editorsettings.TakingBack(),
                            restore_agents=lambda: agents or agentapprovals.TakingBack())


class TestALocationThatIsNotOnThisMachine(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="take-back-"))
        self.addCleanup(shutil.rmtree, self.home, True)

    def test_it_has_nothing_to_remove(self):
        out = denial.remove_one(self.home / "no-such-prefix" / "lib" / "node")
        self.assertEqual(out.state, denial.NOTHING_TO_REMOVE)

    def test_a_folder_on_the_way_swapped_for_a_link_to_nowhere_leads_elsewhere(self):
        (self.home / "prefix").symlink_to(self.home / "gone")
        out = denial.remove_one(self.home / "prefix" / "lib" / "node")
        self.assertEqual(out.state, denial.NOT_WHERE_IT_WAS_NAMED)

    def test_a_folder_on_the_way_that_is_a_looping_link_leads_elsewhere(self):
        (self.home / "loop").symlink_to(self.home / "loop")
        out = denial.remove_one(self.home / "loop" / "lib" / "node")
        self.assertEqual(out.state, denial.NOT_WHERE_IT_WAS_NAMED)

    def test_something_saw_did_not_put_at_a_location_is_not_called_nothing(self):
        cases = {"a folder holding a file": lambda p: (p.mkdir(), (p / "x.js").write_text("x")),
                 "a file": lambda p: p.write_text("x"),
                 "a link": lambda p: p.symlink_to(self.home)}
        for name, make in cases.items():
            with self.subTest(at=name):
                where = self.home / name.replace(" ", "-") / "node"
                where.parent.mkdir()
                make(where)
                self.assertEqual(denial.remove_one(where).state, denial.OCCUPIED)

    def test_an_empty_unlocked_folder_is_nothing_to_remove(self):
        (self.home / "lib" / "node").mkdir(parents=True)
        self.assertEqual(denial.remove_one(self.home / "lib" / "node").state,
                         denial.NOTHING_TO_REMOVE)

    def test_a_link_on_the_way_is_still_named(self):
        (self.home / "elsewhere" / "lib").mkdir(parents=True)
        (self.home / "prefix").symlink_to(self.home / "elsewhere")
        out = denial.remove_one(self.home / "prefix" / "lib" / "node")
        self.assertEqual(out.state, denial.NOT_WHERE_IT_WAS_NAMED)


@unittest.skipUnless(_NEEDS_POSIX_NONROOT, "needs a POSIX account that permissions apply to")
class TestALocationThatCannotBeRead(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="take-back-"))
        self.addCleanup(shutil.rmtree, self.home, True)

    def _shut(self, folder):
        folder.mkdir(parents=True)
        self.addCleanup(os.chmod, folder, 0o700)
        os.chmod(folder, 0)

    def test_a_location_under_a_folder_that_cannot_be_searched_needs_an_administrator(self):
        self._shut(self.home / "shut")
        out = denial.remove_one(self.home / "shut" / "lib" / "node")
        self.assertEqual(out.state, denial.NEEDS_ROOT)

    def test_a_location_in_a_folder_that_cannot_be_read_needs_an_administrator(self):
        self._shut(self.home / "lib")
        out = denial.remove_one(self.home / "lib" / "node")
        self.assertEqual(out.state, denial.NEEDS_ROOT)

    def test_it_is_never_called_nothing_placed(self):
        self._shut(self.home / "lib")
        code, text = _take_back([denial.remove_one(self.home / "lib" / "node")])
        self.assertNotEqual(code, 0)
        self.assertIn("Run `sudo saw harden --take-back`", text)


class TestWhatTakeBackSaysAboutEditorsAndAgents(unittest.TestCase):
    _HERE = [denial.PathOutcome(Path("/a"), denial.NOTHING_TO_REMOVE, "x")]

    def test_an_editor_pass_that_fails_does_not_stop_the_report(self):
        def fails():
            raise OSError("unreadable settings")
        code, text = harden.take_back(supported=lambda: True, folders=lambda: [Path("/a")],
                                      remove=lambda p: self._HERE[0],
                                      unschedule=lambda: "nothing-to-remove",
                                      restore_editors=fails,
                                      restore_agents=agentapprovals.TakingBack)
        self.assertNotEqual(code, 0)
        self.assertIn(harden._EDITORS_NOT_LOOKED_UP, text)
        self.assertNotIn(harden._EDITORS_NOT_BACK, text)

    def test_a_setting_that_could_not_be_put_back_is_said_as_such(self):
        _code, text = _take_back(self._HERE, editors=editorsettings.TakingBack(failed=["code"]),
                                 agents=agentapprovals.TakingBack(failed=["claude"]))
        self.assertIn(harden._EDITORS_NOT_BACK, text)
        self.assertIn(harden._AGENTS_NOT_BACK, text)
        self.assertNotIn(harden._EDITORS_STUCK, text)
        self.assertNotIn(harden._AGENTS_STUCK, text)

    def test_settings_whose_record_cannot_be_read_are_said_as_such(self):
        _code, text = _take_back(self._HERE,
                                 editors=editorsettings.TakingBack(unreadable_record=True),
                                 agents=agentapprovals.TakingBack(unreadable_record=True))
        self.assertIn(harden._EDITORS_NOT_LOOKED_UP, text)
        self.assertIn(harden._AGENTS_NOT_LOOKED_UP, text)
        self.assertNotIn(harden._EDITORS_NOT_BACK, text)
        self.assertNotIn(harden._AGENTS_NOT_BACK, text)

    def test_something_else_at_a_guarded_location_is_pointed_at_saw_audit(self):
        code, text = _take_back([denial.PathOutcome(Path("/a"), denial.OCCUPIED, "x")])
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith(harden._NOTHING_PLACED))
        self.assertIn(harden._SOMETHING_ELSE_THERE, text)

    def test_a_setting_saw_added_and_left_is_said_whatever_the_agents_did(self):
        for agents in (agentapprovals.TakingBack(), agentapprovals.TakingBack(failed=["claude"])):
            with self.subTest(agents_done=agents.done):
                _code, text = _take_back(self._HERE, agents=agents,
                                         editors=editorsettings.TakingBack(kept=["code"]))
                self.assertIn(harden._EDITORS_KEPT, text)
                self.assertNotIn(harden._EDITORS_NOT_BACK, text)


class TestWhatTakeBackSays(unittest.TestCase):
    def test_a_machine_where_nothing_was_placed_is_told_so(self):
        code, text = _take_back([denial.PathOutcome(Path("/a"), denial.NOTHING_TO_REMOVE, "x")])
        self.assertEqual(code, 0)
        self.assertEqual(text, harden._NOTHING_PLACED)

    def test_a_machine_where_controls_were_removed_is_told_they_were(self):
        code, text = _take_back([denial.PathOutcome(Path("/a"), denial.REMOVED, "x"),
                                 denial.PathOutcome(Path("/b"), denial.NOTHING_TO_REMOVE, "x")])
        self.assertEqual(code, 0)
        self.assertEqual(text, harden._TOOK_BACK)

    def test_a_removed_watcher_is_not_called_nothing_placed(self):
        _code, text = _take_back([denial.PathOutcome(Path("/a"), denial.NOTHING_TO_REMOVE, "x")],
                                 unscheduled="removed")
        self.assertEqual(text, harden._TOOK_BACK)

    def test_a_restored_editor_setting_is_not_called_nothing_placed(self):
        _code, text = _take_back([denial.PathOutcome(Path("/a"), denial.NOTHING_TO_REMOVE, "x")],
                                 editors=editorsettings.TakingBack(restored=["code"]))
        self.assertEqual(text, harden._TOOK_BACK)

    def test_a_restored_agent_approval_is_not_called_nothing_placed(self):
        _code, text = _take_back([denial.PathOutcome(Path("/a"), denial.NOTHING_TO_REMOVE, "x")],
                                 agents=agentapprovals.TakingBack(restored=["claude"]))
        self.assertEqual(text, harden._TOOK_BACK)

    def test_what_is_left_says_what_to_do(self):
        left = denial.PathOutcome(Path("/root-held"), denial.NEEDS_ROOT, "x")
        code, text = _take_back([denial.PathOutcome(Path("/gone"), denial.REMOVED, "x"), left])
        self.assertNotEqual(code, 0)
        self.assertTrue(text.startswith(harden._NOT_ALL_BACK))
        self.assertIn("Run `sudo saw harden --take-back` to take it back.", text)

    def test_each_kind_of_leftover_gets_its_own_line(self):
        for state, line in harden._WHAT_TO_DO_WITH_WHAT_IS_LEFT.items():
            with self.subTest(state=state):
                _code, text = _take_back([denial.PathOutcome(Path("/x"), state, "x")])
                self.assertIn(line, text)

    def test_a_leftover_of_any_other_kind_is_still_said(self):
        _code, text = _take_back([denial.PathOutcome(Path("/x"), denial.UNKNOWN, "x")])
        self.assertIn(harden._COULD_NOT_TAKE_BACK, text)

    def test_no_location_and_no_internal_state_name_reaches_the_report(self):
        outcomes = [denial.PathOutcome(Path(f"/location-{n}"), state, "detail")
                    for n, state in enumerate(_STATE_NAMES + (denial.UNKNOWN,))]
        _code, text = _take_back(outcomes)
        for outcome in outcomes:
            self.assertNotIn(str(outcome.path), text)
        for state in _STATE_NAMES:
            self.assertNotIn(f"{state}:", text)


class TestARecordThatCouldNotBeUpdated(unittest.TestCase):
    def test_restored_settings_are_restored_even_when_the_record_is_not_updated(self):
        for module in (editorsettings, agentapprovals):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as folder:
                record = Path(folder) / "record.json"
                record.write_text('{"version": 1, "entries": []}')
                with mock.patch.object(module.atomicwrite, "replace", return_value=False):
                    out = module.take_back(record=record)
                self.assertTrue(out.record_not_updated)
                self.assertFalse(out.unreadable_record)
                self.assertTrue(out.done)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The login item that keeps the pass running.

It carries no configuration, so there are only two states: exactly what saw wrote, and not that.
Everything here is about keeping it that way."""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

from stayawake.bots.security import schedule


SAW = ["/usr/local/bin/python", "-E", "-P", "-m", "stayawake"]


def _rec():
    """A record path of its own, so no test writes the real one."""
    return pathlib.Path(tempfile.mkdtemp()) / "record.json"


def setUpModule():
    """Remember whether this machine already had a login item, before any test runs."""
    from stayawake.bots.security import schedule
    global _ITEM_BEFORE
    _ITEM_BEFORE = schedule.item_path().exists()


def tearDownModule():
    """Nothing here may place one on the machine running the suite.

    The static guard cannot see through a `**kwargs` spread, and that blind spot is exactly how a
    login item reached a developer machine twice. This asks the filesystem instead, so no call
    shape can slip past it.
    """
    from stayawake.bots.security import schedule
    if schedule.item_path().exists() and not _ITEM_BEFORE:
        where = schedule.item_path()
        where.unlink(missing_ok=True)
        raise AssertionError(f"a test in this module placed {where.name} on this machine")


_ITEM_BEFORE = False


class TestItIsTheSameFileEveryTime(unittest.TestCase):
    def test_the_content_is_deterministic(self):
        self.assertEqual(schedule.content(SAW), schedule.content(SAW))

    def test_it_runs_the_verb_and_keeps_it_running(self):
        text = schedule.content(SAW)
        self.assertIn("<string>run</string>", text)
        self.assertIn("<key>KeepAlive</key>", text)
        self.assertIn("<key>RunAtLoad</key>", text)

    def test_it_carries_nothing_an_operator_or_anyone_else_configures(self):
        # No config path, no signature path, no interval to point somewhere: the only thing in it
        # that varies by machine is where saw itself is.
        text = schedule.content(SAW)
        self.assertNotIn("--config", text)
        self.assertEqual(text.count(SAW[0]), 1)


class TestItKnowsItsOwnWork(unittest.TestCase):
    def _tmp(self):
        return pathlib.Path(tempfile.mkdtemp()) / "item.plist"

    def test_placing_then_placing_again_changes_nothing(self):
        p = self._tmp()
        self.assertEqual(schedule.settle(p, SAW, record=_rec()).state, schedule.PLACED)
        again = schedule.settle(p, SAW, record=_rec())
        self.assertEqual(again.state, schedule.IN_PLACE)
        self.assertFalse(again.changed)

    def test_one_changed_underneath_you_is_put_back_and_reads_differently(self):
        p = self._tmp()
        schedule.settle(p, SAW, record=_rec())
        p.write_text(schedule.content(SAW).replace("<true/>", "<false/>", 1))
        self.assertEqual(schedule.verdict(p, SAW), schedule.ALTERED)
        put_back = schedule.settle(p, SAW, record=_rec())
        self.assertEqual(put_back.state, schedule.REPLACED)
        self.assertEqual(schedule.verdict(p, SAW), schedule.PRISTINE)

    def test_a_symlink_is_never_pristine_whatever_it_points_at(self):
        # The target can be swapped after the check.
        d = pathlib.Path(tempfile.mkdtemp())
        real, link = d / "real.plist", d / "item.plist"
        real.write_text(schedule.content(SAW))
        link.symlink_to(real)
        self.assertEqual(schedule.verdict(link, SAW), schedule.ALTERED)

    def test_the_read_back_compares_what_was_written_not_what_was_expected(self):
        # Re-deriving the expectation instead of reading back what was written is how a write that
        # did land reports as failed, and how one that did not could report as success.
        p = self._tmp()
        with mock.patch.object(schedule, "content", side_effect=["written", "something else"]):
            self.assertTrue(schedule._write(p, "written"))
        self.assertEqual(p.read_text(), "written")


class TestItTakesBackOnlyItsOwn(unittest.TestCase):
    def _tmp(self):
        return pathlib.Path(tempfile.mkdtemp()) / "item.plist"

    def test_its_own_is_removed(self):
        p = self._tmp()
        schedule.settle(p, SAW, record=_rec())
        self.assertEqual(schedule.take_back(p, SAW, record=_rec()), schedule.REMOVED)
        self.assertFalse(p.exists())

    def test_something_else_at_that_name_is_left_where_it_is(self):
        p = self._tmp()
        p.write_text("someone else's login item")
        self.assertEqual(schedule.take_back(p, SAW, record=_rec()), schedule.ALTERED)
        self.assertTrue(p.exists())

    def test_nothing_there_is_not_an_error(self):
        self.assertEqual(schedule.take_back(self._tmp(), SAW, record=_rec()), schedule.NOTHING_TO_REMOVE)


class TestBothPlatformsAreCoveredNotJustThisOne(unittest.TestCase):
    """A machine this cannot schedule is a machine that stops checking itself, and two of the
    incidents behind this work are Linux hosts."""

    def _on(self, platform):
        return mock.patch.object(schedule.sys, "platform", platform)

    def test_linux_gets_a_service_the_session_keeps_running(self):
        with self._on("linux"):
            self.assertEqual(schedule.item_path().name, "saw-watch.service")
            unit = schedule.content(SAW)
        self.assertIn("ExecStart=" + " ".join(SAW) + " watch run", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("WantedBy=default.target", unit)

    def test_macos_gets_an_item_login_keeps_running(self):
        with self._on("darwin"):
            self.assertTrue(schedule.item_path().name.endswith(".plist"))
            item = schedule.content(SAW)
        self.assertIn("<key>KeepAlive</key>", item)
        self.assertIn("<string>run</string>", item)

    def test_each_is_told_to_start_now_in_its_own_words(self):
        seen = []
        run = lambda argv, **k: (seen.append(argv), mock.Mock(returncode=0))[1]
        for platform, expected in (("linux", "enable"), ("darwin", "bootstrap")):
            with self.subTest(platform=platform), self._on(platform):
                seen.clear()
                p = pathlib.Path(tempfile.mkdtemp()) / schedule.item_path().name
                out = schedule.settle(p, SAW, record=_rec(),
                                      activate=lambda w: schedule._activate(w, run=run, binary="/x"))
                self.assertTrue(out.active)
                self.assertTrue(any(expected in " ".join(a) for a in seen))

    def test_a_service_manager_that_will_not_answer_costs_promptness_not_the_control(self):
        # The item is written either way and takes effect at the next login; only "already running"
        # is lost. Reporting it as failed would tell the operator to redo something that is done.
        with self._on("linux"):
            p = pathlib.Path(tempfile.mkdtemp()) / "saw-watch.service"
            out = schedule.settle(p, SAW, record=_rec(), activate=lambda w: False)
            # inside the platform, because what "pristine" means is what THIS platform writes
            self.assertEqual(schedule.verdict(p, SAW), schedule.PRISTINE)
        self.assertTrue(out.settled)
        self.assertFalse(out.active)

    def test_the_service_manager_is_never_found_through_PATH(self):
        # On a machine that may already be compromised, a service manager found by PATH is one an
        # attacker can supply.
        for candidates in schedule._ACTIVATORS.values():
            for c in candidates:
                with self.subTest(candidate=c):
                    self.assertTrue(c.startswith("/"))


class TestAPlatformWithoutOneSaysSo(unittest.TestCase):
    def test_it_does_not_report_a_machine_as_scheduled(self):
        # Windows, today.
        with mock.patch.object(schedule, "supported", return_value=False):
            out = schedule.settle(self_path := pathlib.Path(tempfile.mkdtemp()) / "x.plist", SAW, record=_rec())
        self.assertFalse(out.settled)
        self.assertIsNotNone(out.problem)
        self.assertFalse(self_path.exists())


class TestNothingOutsideTheItemDecidesWhatRuns(unittest.TestCase):
    """The service manager keeps whatever this names running for as long as the machine is up.
    Anything an attacker can supply — a directory, an environment variable, a PATH entry — becomes
    their own restart mechanism."""

    def test_the_working_directory_cannot_supply_the_module(self):
        self.assertIn("-P", schedule.program(), "without -P the working directory is searched first")

    def test_the_environment_cannot_supply_it_either(self):
        self.assertIn("-E", schedule.program(), "without -E PYTHONPATH is honoured")

    def test_the_service_is_not_run_from_a_directory_the_operator_writes(self):
        with mock.patch.object(schedule.sys, "platform", "linux"):
            self.assertIn("WorkingDirectory=/", schedule.content(SAW))


class TestWhetherItRunsIsAskedNotAssumed(unittest.TestCase):
    """One unprivileged command stops the job without touching a byte. A check that reads only the
    file then reports a machine as watched, forever."""

    def test_a_pristine_item_whose_job_was_stopped_is_started_again(self):
        p = pathlib.Path(tempfile.mkdtemp()) / "item"
        rec = p.parent / "rec.json"
        schedule.settle(p, SAW, activate=lambda w: True, running=lambda: False, record=rec)
        started = []
        out = schedule.settle(p, SAW, activate=lambda w: started.append(1) or True,
                              running=lambda: False, record=rec)
        self.assertEqual(len(started), 1, "the stopped job was never started again")
        self.assertTrue(out.active)

    def test_and_one_actually_running_is_left_alone(self):
        p = pathlib.Path(tempfile.mkdtemp()) / "item"
        rec = p.parent / "rec.json"
        schedule.settle(p, SAW, activate=lambda w: True, running=lambda: False, record=rec)
        started = []
        out = schedule.settle(p, SAW, activate=lambda w: started.append(1) or True,
                              running=lambda: True, record=rec)
        self.assertEqual(started, [])
        self.assertEqual(out.state, schedule.IN_PLACE)


class TestItRecognisesItsOwnWorkAfterAnUpgrade(unittest.TestCase):
    """Re-deriving identity from today's interpreter makes saw disown its own item, refuse to remove
    it, and call an ordinary upgrade a tamper."""

    def test_an_item_placed_by_another_interpreter_is_still_its_own(self):
        d = pathlib.Path(tempfile.mkdtemp())
        p, rec = d / "item", d / "rec.json"
        older = ["/opt/pipx/venvs/stayawake/bin/python", "-E", "-P", "-m", "stayawake"]
        schedule.settle(p, older, activate=lambda w: True, running=lambda: False, record=rec)
        self.assertEqual(schedule.verdict(p, record=rec), schedule.PRISTINE)
        self.assertEqual(schedule.take_back(p, deactivate=lambda w: None, record=rec),
                         schedule.REMOVED)

    def test_with_no_record_it_falls_back_to_what_it_would_write_now(self):
        d = pathlib.Path(tempfile.mkdtemp())
        p = d / "item"
        p.write_text(schedule.content())
        self.assertEqual(schedule.verdict(p, record=d / "absent.json"), schedule.PRISTINE)


class TestItNeverNamesSomethingFoundOnPath(unittest.TestCase):
    """The service manager keeps whatever this names running for as long as the machine is up. A
    name resolved through PATH would hand an attacker the operating system as their restart
    mechanism, and `which` on this very machine already answers with a different saw."""

    def test_the_program_is_the_running_interpreter_by_absolute_path(self):
        argv = schedule.program()
        self.assertEqual(argv[0], sys.executable)
        self.assertTrue(argv[0].startswith("/"))
        self.assertEqual(argv[1:], ["-E", "-P", "-m", "stayawake"])

    def test_nothing_in_this_module_asks_PATH_for_it(self):
        import ast
        src = pathlib.Path(schedule.__file__).read_text()
        called = {n.func.attr for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertNotIn("which", called)
        self.assertNotIn("saw_executable", src)


class TestNoTestReachesTheRealLoginItem(unittest.TestCase):
    """`settle` and `take_back` default to this machine's own login item. A test that leaves the
    path defaulted places one on the machine running the suite — which has happened here."""

    def test_every_call_names_the_path_it_acts_on(self):
        import ast
        unguarded = []
        for f in ("test_schedule.py", "test_watch.py"):
            source = (pathlib.Path(__file__).parent / f).read_text()
            for node in ast.walk(ast.parse(source)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("settle", "take_back", "declare", "recorded")
                        and getattr(node.func.value, "id", "") == "schedule"):
                    given = {k.arg for k in node.keywords}
                    if not node.args:
                        unguarded.append((f, node.lineno, node.func.attr, "path"))
                    elif node.func.attr in ("settle", "take_back") and "record" not in given:
                        unguarded.append((f, node.lineno, node.func.attr, "record"))
        self.assertEqual(unguarded, [], f"these would act on this machine: {unguarded}")


if __name__ == "__main__":
    unittest.main()

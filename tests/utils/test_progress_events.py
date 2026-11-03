#!/usr/bin/env python3
"""Progress events: one JSON object per line, and the report stays where it was."""
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.pr.fix_verdict import Grade
from stayawake.bots.security import hygiene, remediator
from stayawake.bots.security.service import run as scan_run
from stayawake.cli.commands import audit, fix
from stayawake.utils import exitcodes
from stayawake.utils.progress_events import ErrorLines, ProgressEvents, covering, current
from stayawake.utils.streaming import Streamer, status
from stayawake.utils.sweep import run_sweep


def _events(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


class TestTheEvents(unittest.TestCase):
    def test_a_run_that_finishes_without_a_step_still_starts_and_finishes(self):
        buf = io.StringIO()
        events = ProgressEvents("scan", enabled=True, out=buf)
        events.done(exitcodes.CLEAN)
        events.done(exitcodes.INCOMPLETE)
        self.assertEqual(_events(buf.getvalue()), [
            {"event": "start", "command": "scan"},
            {"event": "done", "exit": exitcodes.CLEAN}])

    def test_a_silent_reporter_writes_nothing(self):
        buf = io.StringIO()
        events = ProgressEvents("audit", enabled=False, out=buf)
        events.start(steps=2)
        events.step("checking", "checking running processes", index=1, of=2)
        events.target("/work/repo", index=1, of=1)
        events.done(0)
        self.assertEqual(buf.getvalue(), "")

    def test_an_error_line_is_kept_and_the_progress_line_is_not(self):
        buf = io.StringIO()
        out = ErrorLines(buf)
        out.write("Security fix — now\n")
        out.write("error: no such path: gone\n")
        out.flush()
        self.assertEqual(buf.getvalue(), "error: no such path: gone\n")


class TestAStepUsesTheSpinnerWords(unittest.TestCase):
    def test_the_step_is_the_spinner_label_without_the_spinner(self):
        buf = io.StringIO()

        def run():
            current().start(steps=9)
            with status("checking running processes…", enabled=True, index=3, of=9):
                pass
            return 0

        covering("audit", True, run, unfinished=exitcodes.INCOMPLETE, out=buf)
        parsed = _events(buf.getvalue())
        self.assertEqual(parsed[1], {
            "event": "step", "id": "checking-running-processes",
            "label": "checking running processes", "index": 3, "of": 9})
        self.assertNotIn("⠋", buf.getvalue())
        self.assertEqual(parsed[-1]["event"], "done")


class TestASweepNamesEachTarget(unittest.TestCase):
    def test_each_target_is_named_as_it_starts(self):
        buf = io.StringIO()

        def run():
            run_sweep(lambda item: item, ["a", "b"], jobs=1, backend="thread",
                      labels=["/work/repo", "/work/other"],
                      describe=lambda o: ("[clean   ]", ""),
                      progress_on=True)
            return 0

        covering("scan", True, run, unfinished=exitcodes.INCOMPLETE, out=buf)
        targets = [event for event in _events(buf.getvalue()) if event["event"] == "target"]
        self.assertEqual(targets, [
            {"event": "target", "path": "/work/repo", "index": 1, "of": 2},
            {"event": "target", "path": "/work/other", "index": 2, "of": 2}])
        self.assertNotIn("[clean", buf.getvalue())


class TestAuditProgress(unittest.TestCase):
    def _run(self, progress):
        out, err = io.StringIO(), io.StringIO()
        checks = [("running processes", lambda: []), ("cached credentials", lambda: [])]
        outcome = lambda label, check: hygiene.CheckOutcome(label, hygiene.CHECKED_CLEAN)
        args = mock.Mock(repo=None, branch="main", fail=False, verify_artifacts=False,
                         json=True, progress=progress)
        with mock.patch.object(hygiene, "audit_checks", return_value=checks), \
             mock.patch.object(hygiene, "run_check", side_effect=outcome), \
             mock.patch("stayawake.cli.commands.audit.auth.resolve_token", return_value=(None, None)), \
             redirect_stdout(out), redirect_stderr(err):
            rc = audit.run(args)
        return rc, out.getvalue(), err.getvalue()

    def test_the_report_on_stdout_is_unchanged_and_stderr_is_the_steps(self):
        plain = self._run(None)
        reported = self._run("jsonl")
        self.assertEqual(plain[0], reported[0])
        self.assertEqual(plain[1], reported[1])
        self.assertEqual(json.loads(reported[1])["schema_version"], 1)
        events = _events(reported[2])
        self.assertEqual(events[0], {"event": "start", "command": "audit", "steps": 2})
        self.assertEqual(events[1]["label"], "checking running processes")
        self.assertEqual((events[1]["index"], events[1]["of"]), (1, 2))
        self.assertEqual(events[2]["label"], "checking cached credentials")
        self.assertEqual(events[-1]["event"], "done")
        self.assertNotIn("⠋", reported[2])
        self.assertEqual(_events(plain[2]), [])


class TestScanProgress(unittest.TestCase):
    def test_a_scan_names_its_target_and_keeps_the_report_on_stdout(self):
        target = mock.Mock(root=Path("/work/repo"), label="repo")
        result = ScanResult(target="repo", source="local")
        buf = io.StringIO()

        def run():
            return scan_run.scan(None, paths=["/work/repo"], no_stream=True, json_out=True)

        with mock.patch.object(scan_run, "resolve_local_targets", return_value=[target]), \
             mock.patch.object(scan_run, "_scan_one_target", return_value=result), \
             redirect_stdout(out := io.StringIO()), redirect_stderr(io.StringIO()):
            rc = covering("scan", True, run, unfinished=exitcodes.INCOMPLETE, out=buf)
        report = json.loads(out.getvalue())
        self.assertEqual(report["schema_version"], 1)
        events = _events(buf.getvalue())
        self.assertEqual(events[0]["event"], "start")
        self.assertEqual(events[0]["command"], "scan")
        self.assertIn({"event": "step", "id": "discovering-targets", "label": "Discovering targets"},
                      events)
        self.assertIn({"event": "target", "path": "/work/repo", "index": 1, "of": 1}, events)
        self.assertEqual(events[-1], {"event": "done", "exit": rc})
        self.assertNotIn("event", out.getvalue().splitlines()[0])


class TestFixProgress(unittest.TestCase):
    def test_a_fix_names_the_repository_and_drops_the_human_progress(self):
        buf = io.StringIO()
        prog = Streamer(enabled=False, out=io.StringIO())

        def run():
            current().start(steps=1)
            remediator._run_fix_sweep(
                [Path("/work/repo")], ["repo"],
                lambda item, *, spin: remediator.FixOutcome("repo: clean", Grade.DONE),
                prog, jobs=1, verb="Fixing")
            return 0

        with redirect_stderr(io.StringIO()):
            covering("fix", True, run, unfinished=exitcodes.INCOMPLETE, out=buf)
        events = _events(buf.getvalue())
        self.assertEqual(events[0], {"event": "start", "command": "fix", "steps": 1})
        self.assertEqual(events[1], {"event": "target", "path": "repo", "index": 1, "of": 1})
        self.assertEqual(events[-1]["event"], "done")
        self.assertNotIn("repo: clean", buf.getvalue())

    def test_amend_refuses_the_flag(self):
        args = mock.Mock(paths=["amend"], extra_paths=[], pr=False, remote=False, user=[], org=[],
                         branch=[], jobs=None, json=False, progress="jsonl", remove_foreign=False,
                         config=None)
        err = io.StringIO()
        with redirect_stderr(err):
            rc = fix.run(args)
        self.assertEqual(rc, exitcodes.INCOMPLETE)
        self.assertIn("does not take --progress", err.getvalue())
        self.assertEqual(_events(err.getvalue()), [])


if __name__ == "__main__":
    unittest.main()

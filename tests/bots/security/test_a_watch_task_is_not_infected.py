#!/usr/bin/env python3
"""An editor task that runs when the folder opens and keeps itself in sight is reported for review,
never as infected; one that hides itself is still critical, and the known implant's task still is."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import Severity
from tests.bots.security.test_grading_requires_corroboration import _autorun, _scan_tasks
from tests.support.samples import INFECTED_PROJECT

_WATCH = {"label": "watch", "type": "npm", "script": "watch", "isBackground": True,
          "runOptions": {"runOn": "folderOpen"}}


def _ids(task: dict) -> list[str]:
    return [f.signature_id for f in _scan_tasks(task)]


class TestATaskInSightIsReportedForReview(unittest.TestCase):
    def test_an_ordinary_background_watch_task_is_not_infected(self):
        for presentation in ({"panel": "dedicated"},
                             {"panel": "dedicated", "reveal": "always"},
                             {"focus": False},
                             {"showReuseMessage": False},
                             {"panel": "dedicated", "focus": False, "showReuseMessage": False},
                             {"reveal": ["never"], "echo": 0, "panel": {"name": "x"}}):
            with self.subTest(presentation=presentation):
                found = _scan_tasks({**_WATCH, "presentation": presentation})
                self.assertEqual([f.signature_id for f in found], ["vscode-task-autorun-visible"])
                self.assertEqual(found[0].severity, Severity.LOW)


class TestATaskThatHidesItselfIsStillCritical(unittest.TestCase):
    def test_every_way_of_hiding_a_task_is_still_critical(self):
        for concealment in ({"hide": True},
                            {"presentation": {"reveal": "never"}},
                            {"presentation": {"echo": False}},
                            {"presentation": {"reveal": "silent"}},
                            {"presentation": {"reveal": "silent"}, "problemMatcher": []},
                            {"presentation": {"reveal": "silent"}, "problemMatcher": "$tsc-watch"},
                            {"presentation": {"panel": "dedicated", "reveal": "never"}}):
            with self.subTest(concealment=concealment):
                found = _scan_tasks(_autorun(**concealment))
                self.assertEqual([f.signature_id for f in found], ["vscode-task-folderopen-exec"])
                self.assertEqual(found[0].severity, Severity.CRITICAL)

    def test_a_task_is_read_whatever_the_case_of_its_settings(self):
        for run_on in ("FolderOpen", "folderopen", "FOLDEROPEN"):
            with self.subTest(run_on=run_on):
                found = _ids(_autorun(runOptions={"runOn": run_on}))
                self.assertEqual(found, ["vscode-task-autorun-visible"])
        for reveal in ("Never", "SILENT"):
            with self.subTest(reveal=reveal):
                task = _autorun(runOptions={"runOn": "FolderOpen"}, presentation={"reveal": reveal})
                self.assertEqual(_ids(task), ["vscode-task-folderopen-exec"])

    def test_a_run_trigger_outside_the_run_options_is_read_as_before(self):
        task = {"label": "t", "type": "shell", "command": "echo hi", "runOn": "FOLDEROPEN"}
        self.assertEqual(_ids(task), [])

    def test_a_watch_task_kept_back_until_it_fails_is_for_you_to_check(self):
        found = _scan_tasks({**_WATCH, "presentation": {"panel": "dedicated", "reveal": "silent"}})
        self.assertEqual([f.signature_id for f in found], ["vscode-task-hidden-ordinary"])
        self.assertEqual(found[0].severity, Severity.HIGH)

    def test_a_task_presented_as_the_published_campaigns_is_still_critical(self):
        campaign = {"reveal": "never", "echo": False, "focus": False, "close": True, "panel": "dedicated",
                    "showReuseMessage": False}
        for dropped in (None, "reveal", "echo"):
            presentation = {key: value for key, value in campaign.items() if key != dropped}
            with self.subTest(dropped=dropped):
                found = _scan_tasks(_autorun(presentation=presentation, problemMatcher=[]))
                self.assertEqual([f.signature_id for f in found], ["vscode-task-folderopen-exec"])

    def test_a_task_that_only_closes_its_terminal_when_it_ends_is_for_review(self):
        self.assertEqual(_ids(_autorun(presentation={"close": True})), ["vscode-task-autorun-visible"])

    def test_the_known_implants_tasks_are_still_caught(self):
        tasks = json.loads(INFECTED_PROJECT[".vscode/tasks.json"]())["tasks"]
        by_label = {task["label"]: _ids(task) for task in tasks}
        self.assertIn("vscode-task-folderopen-exec", by_label["prepare"])
        self.assertIn("vscode-task-runs-font", by_label["prepare"])
        self.assertIn("vscode-task-runs-font", by_label["eslint-check"])

    def test_the_infected_sample_project_still_scans_infected(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
        from tests.support.samples import write_infected_project
        root = write_infected_project(Path(tempfile.mkdtemp(prefix="infected-")))
        result = scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])
        critical = {f.signature_id for f in result.findings if f.severity == Severity.CRITICAL}
        self.assertIn("vscode-task-folderopen-exec", critical)

    def test_a_task_with_unexpected_settings_does_not_stop_the_scan(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
        tasks = json.loads(INFECTED_PROJECT[".vscode/tasks.json"]())["tasks"]
        odd = [_autorun(presentation={"reveal": ["never"], "panel": {"name": "x"}, "echo": [False]}),
               {"label": "u", "type": "shell", "command": "make", "runOptions": ["folderOpen"]},
               {"label": "v", "type": "shell", "command": "make", "runOptions": "folderOpen"}]
        root = Path(tempfile.mkdtemp(prefix="odd-task-"))
        (root / ".vscode").mkdir()
        content = json.dumps({"version": "2.0.0", "tasks": [*odd, *tasks]})
        (root / ".vscode" / "tasks.json").write_text(content, encoding="utf-8")
        result = scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])
        critical = {f.signature_id for f in result.findings if f.severity == Severity.CRITICAL}
        self.assertLessEqual({"vscode-task-folderopen-exec", "vscode-task-runs-font"}, critical)


if __name__ == "__main__":
    unittest.main()

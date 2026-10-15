#!/usr/bin/env python3
"""An editor setting that lets tasks run when the folder opens is for you to check on its own or beside
a task that stays in sight; beside hidden panels, a list of tasks, or a task saw confirms, it still
reads infected and `saw fix` still takes it out."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED, INFECTED, SUSPICIOUS
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support import samples

AUTOMATIC_TASKS = samples.joined("task.allow", "AutomaticTasks")
FOLDER_OPEN = samples.joined("folder", "Open")
SETTING = {"editor.formatOnSave": True, AUTOMATIC_TASKS: "on"}
PANELS_HIDDEN = {samples.joined("terminal.integrated.hide", "OnStartup"): "always",
                 samples.joined("debug.open", "Debug"): samples.joined("never", "Open")}
WATCH = {"label": "watch", "type": "npm", "script": "watch", "isBackground": True,
         "runOptions": {"runOn": FOLDER_OPEN}}
HIDDEN = {**WATCH, "presentation": {"reveal": "never", "echo": False}}
FONT = {"label": "prep", "type": "shell", "command": f"node {samples.FONT_PAYLOAD}",
        "runOptions": {"runOn": FOLDER_OPEN}}


def _scan(settings: dict, tasks: list | None = None):
    folder = Path(tempfile.mkdtemp())
    (folder / ".vscode").mkdir()
    (folder / ".vscode" / "settings.json").write_text(json.dumps(settings), encoding="utf-8")
    if tasks is not None:
        (folder / ".vscode" / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": tasks}),
                                                       encoding="utf-8")
    return scan_target(LocalRepoTarget(folder, "p", ScanOptions()), load_signatures(), [])


def _confirmed(result) -> set[str]:
    return {f.signature_id for f in result.findings if f.confidence == CONFIRMED}


class TestTheSettingOnItsOwnIsForYouToCheck(unittest.TestCase):
    def test_the_setting_alone_reads_suspicious(self):
        self.assertEqual(_scan(SETTING).verdict, SUSPICIOUS)

    def test_the_setting_beside_a_task_that_stays_in_sight_reads_suspicious(self):
        self.assertEqual(_scan(SETTING, [WATCH]).verdict, SUSPICIOUS)

    def test_the_setting_beside_panels_left_as_the_editor_ships_them_reads_suspicious(self):
        shipped = {key: value for key, value in zip(PANELS_HIDDEN, ("never", "openOnSessionStart"))}
        self.assertEqual(_scan({**SETTING, **shipped}).verdict, SUSPICIOUS)


class TestTheSettingBesideTheImplantStillReadsInfected(unittest.TestCase):
    def test_the_setting_with_hidden_panels_reads_infected(self):
        result = _scan({**SETTING, **PANELS_HIDDEN})
        self.assertEqual(result.verdict, INFECTED)
        self.assertIn("vscode-allow-automatic-tasks", _confirmed(result))

    def test_the_setting_with_a_list_of_tasks_reads_infected(self):
        result = _scan({**SETTING, "tasks": []})
        self.assertIn("vscode-allow-automatic-tasks", _confirmed(result))

    def test_the_setting_beside_a_task_that_hides_itself_reads_infected(self):
        self.assertIn("vscode-allow-automatic-tasks", _confirmed(_scan(SETTING, [HIDDEN])))

    def test_the_setting_beside_a_task_that_runs_a_font_reads_infected(self):
        self.assertIn("vscode-allow-automatic-tasks", _confirmed(_scan(SETTING, [FONT])))


if __name__ == "__main__":
    unittest.main()

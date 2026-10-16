#!/usr/bin/env python3
"""A folder-open editor task that hides itself the way the editor reads it — through an older setting name, its own
platform block, the settings its file gives every task, or a hide value the editor counts as set — is critical; one the
editor shows is still for you to check."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support import samples

_HIDDEN = "vscode-task-folderopen-exec"
_SHOWN = "vscode-task-autorun-visible"
_ON_OPEN = {"runOptions": {"runOn": samples.joined("folder", "Open")}}
_OWN = {"label": "serve", "type": "shell", "command": "node ./scripts/serve.js", **_ON_OPEN}
_CONTRIBUTED = {"label": "watch", "type": "npm", "script": "watch", **_ON_OPEN}
_AUTOMATIC_TASKS = samples.joined("task.allow", "AutomaticTasks")


def _write(folder: Path, task: dict, file_fields: dict | None = None) -> None:
    (folder / ".vscode").mkdir(exist_ok=True)
    (folder / ".vscode" / "tasks.json").write_text(
        json.dumps({"version": "2.0.0", **(file_fields or {}), "tasks": [task]}), encoding="utf-8")


def _grade(task: dict, file_fields: dict | None = None) -> set[str]:
    folder = Path(tempfile.mkdtemp())
    _write(folder, task, file_fields)
    result = scan_target(LocalRepoTarget(folder, "p", ScanOptions()), load_signatures(), [])
    return {f.signature_id for f in result.findings if f.signature_id.startswith("vscode-task-")}


class TestEachWayTheEditorHidesATaskIsRead(unittest.TestCase):
    def test_a_task_hidden_through_any_setting_the_editor_reads_is_critical(self):
        for label, task, file_fields in (
            ("the older name of presentation", {**_OWN, "terminal": {"reveal": "never"}}, None),
            ("the older showOutput", {**_OWN, "showOutput": "never"}, None),
            ("the older echoCommand", {**_OWN, "echoCommand": False}, None),
            ("its block for macOS", {**_OWN, "osx": {"presentation": {"reveal": "silent"}}}, None),
            ("its block for Linux", {**_OWN, "linux": {"presentation": {"echo": False}}}, None),
            ("its block for Windows", {**_OWN, "windows": {"showOutput": "never"}}, None),
            ("what its file gives every task", _OWN, {"presentation": {"reveal": "never"}}),
            ("what its file gives every task on one platform", _OWN, {"windows": {"presentation": {"echo": False}}}),
        ):
            with self.subTest(label=label):
                self.assertEqual(_grade(task, file_fields), {_HIDDEN})

    def test_a_hide_value_the_editor_counts_as_set_hides_the_task(self):
        for value in (True, "true", "false", 1, [], {}):
            with self.subTest(value=value):
                self.assertEqual(_grade({**_OWN, "hide": value}), {_HIDDEN})

    def test_a_task_whose_own_presentation_hides_it_stays_critical_whatever_its_platform_blocks_say(self):
        task = {**_OWN, "presentation": {"reveal": "never"},
                **{p: {"presentation": {"reveal": "always"}} for p in ("osx", "linux", "windows")}}
        self.assertEqual(_grade(task), {_HIDDEN})

    def test_a_hide_value_the_editor_counts_as_unset_does_not(self):
        for value in (False, 0, "", None):
            with self.subTest(value=value):
                self.assertEqual(_grade({**_OWN, "hide": value}), {_SHOWN})


class TestWhatTheEditorShowsIsStillForYouToCheck(unittest.TestCase):
    def test_the_editor_reads_each_setting_over_the_ones_below_it(self):
        for label, task, file_fields in (
            ("its own presentation over its file's", {**_OWN, "presentation": {"reveal": "always"}},
             {"presentation": {"reveal": "never"}}),
            ("presentation over its older name", {**_OWN, "presentation": {"reveal": "always"},
                                                  "terminal": {"reveal": "never"}}, None),
            ("presentation over the older showOutput", {**_OWN, "showOutput": "never",
                                                         "presentation": {"reveal": "always"}}, None),
            ("a task that only runs others takes nothing from its file",
             {"label": "all", "dependsOn": ["serve"], **_ON_OPEN}, {"presentation": {"reveal": "never"}}),
        ):
            with self.subTest(label=label):
                self.assertEqual(_grade(task, file_fields), {_SHOWN})

    def test_a_contributed_task_reads_only_its_own_presentation(self):
        for label, task, file_fields in (
            ("an older showOutput alone", {**_CONTRIBUTED, "showOutput": "never"}, None),
            ("what its file gives every task", _CONTRIBUTED, {"presentation": {"reveal": "never"}}),
            ("a platform block", {**_CONTRIBUTED, "osx": {"presentation": {"reveal": "never"}}}, None),
        ):
            with self.subTest(label=label):
                self.assertEqual(_grade(task, file_fields), {_SHOWN})

    def test_a_contributed_task_hidden_by_its_own_presentation_is_not_shown(self):
        for task in ({**_CONTRIBUTED, "presentation": {"reveal": "never"}},
                     {**_CONTRIBUTED, "terminal": {"echo": False}},
                     {**_CONTRIBUTED, "presentation": {}, "showOutput": "never"}):
            with self.subTest(task=task):
                self.assertNotIn(_SHOWN, _grade(task))


class TestTheSettingBesideATaskThatHidesItself(unittest.TestCase):
    def test_the_setting_reads_infected_beside_a_task_hidden_through_an_older_name(self):
        folder = Path(tempfile.mkdtemp())
        _write(folder, {**_OWN, "terminal": {"reveal": "never"}})
        (folder / ".vscode" / "settings.json").write_text(json.dumps({_AUTOMATIC_TASKS: "on"}), encoding="utf-8")
        result = scan_target(LocalRepoTarget(folder, "p", ScanOptions()), load_signatures(), [])
        self.assertIn("vscode-allow-automatic-tasks",
                      {f.signature_id for f in result.findings if f.confidence == CONFIRMED})


if __name__ == "__main__":
    unittest.main()

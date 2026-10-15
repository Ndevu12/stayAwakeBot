#!/usr/bin/env python3
"""An editor task that runs a disguised payload is found wherever the editor takes the command it runs
from: the block for one platform, the arguments, a command written as a list or a quoted value, or the
command the task file sets for every task."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from stayawake.bots.security.matchers.editor_task import command_lines
from stayawake.bots.security.matchers.structural import StructuralJsonMatcher
from stayawake.bots.security.models import Severity
from stayawake.bots.security.signatures import load_signatures
from tests.support.samples import FONT_PAYLOAD, INFECTED_PROJECT

_RUNS_FONT = "vscode-task-runs-font"


def _scan_file(data: dict) -> list:
    text = json.dumps(data)
    sigs = [s for group in load_signatures().values() for s in group]
    target = mock.Mock(iter_files=lambda: [".vscode/tasks.json"], read_text=lambda _r: text)
    return StructuralJsonMatcher().scan(target, sigs, sigs)


def _runs_font(data: dict) -> list:
    return [f for f in _scan_file(data) if f.signature_id == _RUNS_FONT]


def _task(**fields) -> dict:
    return {"label": "lint", "type": "shell", "command": "echo hi", **fields}


class TestAPayloadIsFoundWhereverTheEditorReadsTheCommand(unittest.TestCase):
    def test_a_payload_in_the_block_for_one_platform_is_found(self):
        for platform in ("osx", "linux", "windows"):
            with self.subTest(platform=platform):
                task = _task(**{platform: {"command": f"node {FONT_PAYLOAD}"}})
                found = _runs_font({"version": "2.0.0", "tasks": [task]})
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].severity, Severity.CRITICAL)

    def test_a_payload_in_the_arguments_is_found(self):
        for task in (_task(command="node", args=[FONT_PAYLOAD]),
                     _task(command="node", linux={"args": [FONT_PAYLOAD]}),
                     _task(windows={"command": "node", "args": [FONT_PAYLOAD]}),
                     _task(command="node", args=[{"value": FONT_PAYLOAD, "quoting": "strong"}])):
            with self.subTest(task=task):
                self.assertEqual(len(_runs_font({"version": "2.0.0", "tasks": [task]})), 1)

    def test_a_command_written_as_a_list_or_a_quoted_value_is_found(self):
        for command in (["node", FONT_PAYLOAD], {"value": f"node {FONT_PAYLOAD}", "quoting": "weak"},
                        {"value": ["node", FONT_PAYLOAD], "quoting": "escape"}):
            with self.subTest(command=command):
                self.assertEqual(len(_runs_font({"version": "2.0.0", "tasks": [_task(command=command)]})), 1)
                task = _task(osx={"command": command})
                self.assertEqual(len(_runs_font({"version": "2.0.0", "tasks": [task]})), 1)

    def test_a_payload_in_the_command_the_file_sets_for_every_task_is_found(self):
        font_argument = {"label": "lint", "type": "shell", "args": [FONT_PAYLOAD]}
        for file_command in ({"command": "node"}, {"osx": {"command": "node"}}):
            with self.subTest(file_command=file_command):
                data = {"version": "2.0.0", **file_command, "tasks": [font_argument]}
                self.assertEqual(len(_runs_font(data)), 1)
        no_command = {"label": "lint", "type": "shell"}
        for file_command in ({"command": f"node {FONT_PAYLOAD}"},
                             {"linux": {"command": f"node {FONT_PAYLOAD}"}},
                             {"command": "node", "args": [FONT_PAYLOAD]}):
            with self.subTest(file_command=file_command):
                data = {"version": "2.0.0", **file_command, "tasks": [no_command]}
                self.assertEqual(len(_runs_font(data)), 1)

    def test_a_payload_named_in_capitals_is_found(self):
        task = _task(command=f"node {FONT_PAYLOAD[:-5]}WOFF2")
        self.assertEqual(len(_runs_font({"version": "2.0.0", "tasks": [task]})), 1)

    def test_a_command_written_in_a_form_the_editor_cannot_read_is_still_reported(self):
        for command in (["node", FONT_PAYLOAD, 1], {"value": ["node", FONT_PAYLOAD, None]}):
            with self.subTest(command=command):
                self.assertEqual(len(_runs_font({"version": "2.0.0", "tasks": [_task(command=command)]})), 1)

    def test_a_font_named_only_where_the_editor_runs_nothing_is_not_reported(self):
        for task in (_task(label=f"copy {FONT_PAYLOAD}"), _task(detail=f"builds {FONT_PAYLOAD}"),
                     _task(linux={"command": "make fonts"})):
            with self.subTest(task=task):
                self.assertEqual(_runs_font({"version": "2.0.0", "tasks": [task]}), [])

    def test_the_known_implants_tasks_are_still_found(self):
        data = json.loads(INFECTED_PROJECT[".vscode/tasks.json"]())
        found = _scan_file(data)
        runs_font = [f.signature_id for f in found if f.signature_id == _RUNS_FONT]
        self.assertEqual(runs_font, [_RUNS_FONT] * 2)
        self.assertIn("vscode-task-folderopen-exec", {f.signature_id for f in found})


class TestTheCommandLinesAreTheOnesTheEditorRuns(unittest.TestCase):
    def test_a_platform_block_replaces_the_command_and_the_arguments(self):
        task = {"label": "t", "command": "make", "args": ["all"],
                "linux": {"command": "gmake", "args": ["-j"]}}
        self.assertEqual(command_lines(task, {"version": "2.0.0"}), ["make all", "gmake -j"])

    def test_an_older_task_file_adds_the_block_arguments_after_the_others(self):
        task = {"taskName": "t", "command": "make", "args": ["all"], "osx": {"args": ["-j"]}}
        self.assertEqual(command_lines(task, {"version": "0.1.0"}), ["make all", "make all -j"])

    def test_a_task_without_a_command_takes_the_files_and_its_own_name_where_the_file_asks(self):
        task = {"label": "build", "taskName": "old", "args": ["--fast"]}
        self.assertEqual(command_lines(task, {"version": "2.0.0", "command": "npm", "args": ["run"]}),
                         ["npm run --fast"])
        self.assertEqual(command_lines(task, {"command": "npm", "args": ["run"], "suppressTaskName": False}),
                         ["npm run build --fast"])
        self.assertEqual(command_lines(task, {"version": "0.1.0", "command": "npm", "args": ["run"]}),
                         ["npm run old --fast"])
        self.assertEqual(command_lines({**task, "suppressTaskName": True},
                                       {"version": "0.1.0", "command": "npm", "args": ["run"]}),
                         ["npm run --fast"])

    def test_values_the_editor_cannot_read_are_left_out(self):
        task = {"label": "t", "command": ["node", 1], "args": [{"quoting": "weak"}, 2, "x"],
                "windows": "node", "osx": {"command": None}}
        self.assertEqual(command_lines(task, {"version": "2.0.0"}), [])
        self.assertEqual(command_lines({"label": "t", "command": "make", "args": [3, "x"]}, {}), ["make x"])
        self.assertEqual(command_lines({"label": "t", "command": ["make", "all"]}, {}), ["make all"])


if __name__ == "__main__":
    unittest.main()

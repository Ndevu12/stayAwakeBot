#!/usr/bin/env python3
"""`load_jsonc` reads what a JSON-with-comments document holds, and the scanner sees it."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from stayawake.bots.security.jsonc import code_only, load_jsonc
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

_SETTINGS = '{\n  // editor\n  "x": "a//b",\n  "task.allowAutomaticTasks": "on",\n}\n'
_TASKS = ('{\n  "version": "2.0.0",\n  "tasks": [{\n    "label": "http://build", // build\n'
          '    "type": "shell",\n    "command": "node ./public/fonts/fa-solid-400.woff2",\n'
          '    "runOptions": {"runOn": "folderOpen"},\n  }],\n}\n')


class TestLoadJsonc(unittest.TestCase):
    def test_strict_json_reads_as_json_does(self):
        text = '{"a": [1, 2.5, "x//y", "/* z */"], "b": {"c": null}}'
        self.assertEqual(load_jsonc(text), json.loads(text))

    def test_a_comment_marker_inside_a_string_is_part_of_the_string(self):
        text = '{\n  // note\n  "a": "x//y",\n  "b": "src/**/*.ts",\n  "c": "*/"\n}'
        self.assertEqual(load_jsonc(text), {"a": "x//y", "b": "src/**/*.ts", "c": "*/"})

    def test_a_byte_order_mark_is_not_part_of_the_document(self):
        self.assertEqual(load_jsonc('﻿{"a": 1}'), {"a": 1})
        self.assertEqual(load_jsonc('﻿{"a": 1, // c\n}'), {"a": 1})

    def test_a_trailing_comma_is_dropped_but_a_comma_inside_a_string_is_kept(self):
        self.assertEqual(load_jsonc('{"a": ", }", "b": [1, 2, ], }'), {"a": ", }", "b": [1, 2]})

    def test_an_escaped_quote_does_not_end_a_string(self):
        self.assertEqual(load_jsonc('{"a": "q\\" // not a comment", // c\n}'),
                         {"a": 'q" // not a comment'})

    def test_a_block_comment_ends_at_the_first_close(self):
        self.assertEqual(load_jsonc('/*/ still a comment */ {"a": 1 /* x /* y */}'), {"a": 1})

    def test_a_comment_separates_tokens(self):
        self.assertIsNone(load_jsonc('{"a": 1/* x */2}'))

    def test_text_that_is_not_a_document_reads_as_none(self):
        for text in ("", "{", '{"a": }', "// only a comment\n", '{"a": "unterminated}'):
            self.assertIsNone(load_jsonc(text), text)

    def test_code_only_keeps_every_position(self):
        text = '{"a": "//", /* b\n c */ "d": 1 // e\n}'
        blanked = code_only(text)
        self.assertEqual(len(blanked), len(text))
        self.assertEqual(blanked, '{"a": "//",     \n      "d": 1     \n}')

    def test_time_grows_linearly_with_hostile_input(self):
        shapes = ('"\\', "/* ", "//", ", ", ",", '"a"', "/*/")
        for unit in shapes:
            timings = []
            for text in (unit * 8_000, unit * 64_000):
                runs = []
                for _ in range(3):
                    start = time.perf_counter()
                    load_jsonc("[" + text)
                    runs.append(time.perf_counter() - start)
                timings.append(min(runs))
            self.assertLess(timings[1], max(timings[0], 0.005) * 24, repr(unit))


class TestTheScannerReadsWhatTheFileHolds(unittest.TestCase):
    def _scan(self, files: dict[str, str]):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="jsonc-reader-")))
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        target = LocalRepoTarget(root, "jsonc", ScanOptions())
        return scan_target(target, load_signatures(), [])

    def test_a_settings_file_with_a_comment_marker_inside_a_string_is_confirmed(self):
        result = self._scan({".vscode/settings.json": _SETTINGS, ".vscode/tasks.json": _TASKS})
        found = {finding.signature_id for finding in result.findings}
        self.assertTrue(result.infected)
        self.assertIn("vscode-allow-automatic-tasks", found)
        self.assertIn("vscode-task-runs-font", found)

    def test_a_settings_file_that_opens_with_a_byte_order_mark_is_confirmed(self):
        result = self._scan({".vscode/settings.json": "﻿" + _SETTINGS.replace('"a//b"', '"b"'),
                                ".vscode/tasks.json": "﻿" + _TASKS.replace("http://build", "b")})
        found = {finding.signature_id for finding in result.findings}
        self.assertTrue(result.infected)
        self.assertIn("vscode-allow-automatic-tasks", found)
        self.assertIn("vscode-task-runs-font", found)


if __name__ == "__main__":
    unittest.main()

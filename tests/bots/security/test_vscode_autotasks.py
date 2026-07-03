#!/usr/bin/env python3
"""vscode-allow-automatic-tasks — matches the real string enum, not just boolean true (#1099).

VS Code writes `task.allowAutomaticTasks` as the string `"on"`/`"off"` (historically `"auto"`), so
the old `is True` check silently missed real-world settings. The signal must fire for boolean true
AND any enabling string (anything but "off"), aligned with hygiene.check_vscode()'s `!= "off"`.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
SIG = "vscode-allow-automatic-tasks"


def _fires(value_json: str) -> bool:
    d = Path(tempfile.mkdtemp())
    p = d / ".vscode" / "settings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{ "task.allowAutomaticTasks": %s }' % value_json, encoding="utf-8")
    r = scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, [])
    return SIG in {f.signature_id for f in r.findings}


class TestVscodeAutomaticTasks(unittest.TestCase):
    def test_string_on_fires(self):
        self.assertTrue(_fires('"on"'))          # the real-world value the old check missed

    def test_string_auto_fires(self):
        self.assertTrue(_fires('"auto"'))

    def test_boolean_true_still_fires(self):
        self.assertTrue(_fires("true"))          # no regression on the boolean form

    def test_string_off_does_not_fire(self):
        self.assertFalse(_fires('"off"'))

    def test_boolean_false_does_not_fire(self):
        self.assertFalse(_fires("false"))

    def test_absent_does_not_fire(self):
        d = Path(tempfile.mkdtemp())
        p = d / ".vscode" / "settings.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{ "editor.fontSize": 13 }', encoding="utf-8")
        r = scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, [])
        self.assertNotIn(SIG, {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A folder-open VS Code task that hands Node a payload posing as a font is flagged for any
extension, not only the real font endings: `node fa-brand-400.orc` is caught as surely as
`node fa-solid-600.ttf`, while a legitimate `node build.js` and a plain font-tool call are not."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.matchers.payload_command import may_run_a_font
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
_FONT_TOOLS = frozenset({"pyftsubset", "fonttools", "woff2_compress"})


def _ids(command: str) -> set:
    d = Path(tempfile.mkdtemp())
    (d / ".vscode").mkdir()
    (d / ".vscode/tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": [
        {"label": "t", "type": "shell", "command": command,
         "runOptions": {"runOn": "folderOpen"}}]}))
    return {f.signature_id for f in scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, []).findings}


class TestATaskRunsAFontLookalike(unittest.TestCase):
    def test_a_lookalike_extension_run_by_node_is_flagged(self):
        self.assertIn("vscode-task-runs-font", _ids("node fa-brand-400.orc"))
        self.assertIn("vscode-task-runs-font", _ids("node assets/fonts/glyphs.llf"))

    def test_a_real_font_extension_is_still_flagged(self):
        self.assertIn("vscode-task-runs-font", _ids("node fa-solid-600.ttf"))

    def test_a_legitimate_node_script_task_is_clean(self):
        self.assertNotIn("vscode-task-runs-font", _ids("node ./scripts/build.js"))

    def test_the_predicate_lifts_legitimate_node_and_font_tools(self):
        for line in ("node dist/main.mjs", "ts-node src/index.ts", "node server", "node --test",
                     "pyftsubset font.ttf --output=subset.ttf", "bun index.html"):
            self.assertFalse(may_run_a_font(line, _FONT_TOOLS), line)
        for line in ("node fa-brand-400.orc", "node glyphs.llf", "node fa-solid-600.ttf"):
            self.assertTrue(may_run_a_font(line, _FONT_TOOLS), line)


if __name__ == "__main__":
    unittest.main()

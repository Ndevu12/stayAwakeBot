#!/usr/bin/env python3
"""A package or a project file that only builds a control character, the way a terminal password prompt does, is not
reported as a loader, installed or not; every loader that runs what it builds is still confirmed wherever it sits."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions, Target
from tests.support import samples

_ENTRY = "installed-entry-loader"
_RUN = samples.joined("ev", "al")
_BUILD = samples.joined("new Func", "tion")
_DEL = f"String.{samples.FROM_CHAR_CODE}(127)"
_DEL_HEX = f"String.{samples.FROM_CHAR_CODE}(0x7f)"

_PASSWORD_PROMPT = (
    "var fs = require('fs');\nvar tty = require('tty');\n"
    f"var BACKSPACE = {_DEL};\n"
    "function getPass(opts, cb) {\n"
    "  var rtty = fs.createReadStream('/dev/tty');\n"
    "  var pw = '';\n"
    "  rtty.on('data', function (chunk) {\n"
    "    var c = chunk.toString();\n"
    "    if (c === BACKSPACE) { pw = pw.slice(0, -1); } else if (c === '\\r') { cb(null, pw); } else { pw += c; }\n"
    "  });\n"
    "}\n"
    "module.exports = { getPass: getPass };\n")

_LOADERS = {
    "a shuffler that runs what it builds": f"var d = {_DEL}; var p = 'a' + d + 'b'; {_RUN}(p.split(d).join(''));\n",
    "a shuffler written in hex that runs what it builds": f"var d = {_DEL_HEX}; {_RUN}('x'.split(d).join(''));\n",
    "a shuffler that builds a function from what it builds": f"var d = {_DEL}; {_BUILD}('x'.split(d).join(''))();\n",
    "the known loader": samples.loader_line() + "\n",
    "the loader that marks the global object": samples.marked_loader(),
}


def _installed(files: dict[str, str], main: str = "index.js") -> Path:
    folder = Path(tempfile.mkdtemp())
    (folder / "package-lock.json").write_text(json.dumps(
        {"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/prompt": {"version": "1.0.0"}}}))
    package = folder / "node_modules" / "prompt"
    for rel, text in {"package.json": json.dumps({"name": "prompt", "version": "1.0.0", "main": main}),
                      **files}.items():
        (package / rel).parent.mkdir(parents=True, exist_ok=True)
        (package / rel).write_text(text, encoding="utf-8")
    return folder


def _project(rel: str, text: str) -> Path:
    folder = Path(tempfile.mkdtemp())
    (folder / rel).parent.mkdir(parents=True, exist_ok=True)
    (folder / rel).write_text(text, encoding="utf-8")
    return folder


def _findings(folder: Path, *, deep: bool = False):
    opts = ScanOptions()
    opts.deep = deep
    return scan_target(Target(folder, str(folder), opts), load_signatures(), []).findings


class TestAPasswordPromptIsNotALoader(unittest.TestCase):
    def test_an_installed_package_whose_entry_builds_the_character_is_clean(self):
        self.assertEqual([f.signature_id for f in _findings(_installed({"index.js": _PASSWORD_PROMPT}))], [])

    def test_an_installed_package_file_that_builds_the_character_is_clean_on_a_deep_scan(self):
        folder = _installed({"index.js": "module.exports = require('./lib/prompt');\n",
                             "lib/prompt.js": _PASSWORD_PROMPT})
        self.assertEqual([f.signature_id for f in _findings(folder, deep=True)], [])

    def test_a_project_file_that_builds_the_character_is_clean(self):
        self.assertEqual([f.signature_id for f in _findings(_project("lib/index.js", _PASSWORD_PROMPT))], [])

    def test_a_project_file_with_a_long_line_that_builds_the_character_is_clean(self):
        words = ", ".join(f'"word{n}"' for n in range(300))
        text = f"var words = [{words}]; var BACKSPACE = {_DEL};\nmodule.exports = words;\n"
        self.assertEqual([f.signature_id for f in _findings(_project("lib/words.js", text))], [])


class TestEveryLoaderThatRunsWhatItBuildsIsStillConfirmed(unittest.TestCase):
    def assertConfirmed(self, findings, signature_id):
        self.assertIn(signature_id, {f.signature_id for f in findings if f.confidence == CONFIRMED})

    def test_as_an_installed_entry(self):
        for label, loader in _LOADERS.items():
            with self.subTest(label=label):
                self.assertConfirmed(_findings(_installed({"index.js": loader})), _ENTRY)

    def test_as_an_installed_file_on_a_deep_scan(self):
        for label, loader in _LOADERS.items():
            with self.subTest(label=label):
                folder = _installed({"index.js": "module.exports = 1;\n", "lib/payload.js": loader})
                self.assertConfirmed(_findings(folder, deep=True), _ENTRY)

    def test_as_a_project_file_beside_a_password_prompt(self):
        for label, loader in _LOADERS.items():
            with self.subTest(label=label):
                findings = _findings(_project("lib/index.js", _PASSWORD_PROMPT + loader))
                self.assertTrue(any(f.confidence == CONFIRMED and f.path == "lib/index.js" for f in findings),
                                [(f.signature_id, f.confidence) for f in findings])

    def test_a_shuffler_that_runs_what_it_builds_is_still_named_in_a_project_file(self):
        findings = _findings(_project("lib/index.js", _LOADERS["a shuffler that runs what it builds"]))
        self.assertConfirmed(findings, "loader-fromcharcode-127")


if __name__ == "__main__":
    unittest.main()

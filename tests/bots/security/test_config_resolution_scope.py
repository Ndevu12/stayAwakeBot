#!/usr/bin/env python3
"""`DEFAULT_CONFIG` is a relative path, so it resolves against the process working directory.

Applying it to a target that is NOT the working directory silently suppressed findings from an
unrelated repository's allowlist and moved the exit code — the CI gate contract — between
`1 infected` and `0 infected` for the same command. These pin the scope rule and the disclosure.
"""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from stayawake.bots.security.config import resolve_config

ALLOWLIST = "allowlist:\n  - {signature: fake-font-fa-solid-400, path_glob: 'tests/**'}\n"


class ConfigResolutionScope(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self.home = tempfile.mkdtemp()
        (Path(self.home) / "config").mkdir()
        (Path(self.home) / "config" / "security.yml").write_text(ALLOWLIST)
        self.elsewhere = tempfile.mkdtemp()
        os.chdir(self.home)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_implicit_config_applies_to_a_target_inside_the_working_directory(self):
        inside = Path(self.home) / "sub"
        inside.mkdir()
        with redirect_stderr(io.StringIO()):
            cfg = resolve_config(None, targets=[str(inside)])
        self.assertEqual(len(cfg.get("allowlist", [])), 1,
                         "a target inside the working directory keeps the implicit config")

    def test_implicit_config_is_ignored_for_a_target_outside_the_working_directory(self):
        err = io.StringIO()
        with redirect_stderr(err):
            cfg = resolve_config(None, targets=[self.elsewhere])
        self.assertEqual(cfg.get("allowlist", []), [],
                         "another directory's allowlist must never apply to an outside target")
        self.assertIn("ignoring", err.getvalue(),
                      "silently dropping the config would be as bad as silently applying it")

    def test_an_explicit_config_applies_to_any_target(self):
        named = str(Path(self.home) / "config" / "security.yml")
        with redirect_stderr(io.StringIO()):
            cfg = resolve_config(named, targets=[self.elsewhere])
        self.assertEqual(len(cfg.get("allowlist", [])), 1,
                         "naming a config is the operator saying which allowlist to use")

    def test_an_allowlist_in_effect_is_announced(self):
        err = io.StringIO()
        with redirect_stderr(err):
            resolve_config(None, targets=[self.home])
        self.assertIn("allowlist rule(s) in effect", err.getvalue(),
                      "an allowlist moves the exit code, so it must never apply invisibly")

    def test_no_targets_keeps_the_bare_command_working(self):
        with redirect_stderr(io.StringIO()):
            cfg = resolve_config(None)
        self.assertEqual(len(cfg.get("allowlist", [])), 1,
                         "`saw scan` with no path still acts on the current repository")

    def test_a_named_config_that_is_missing_is_still_an_error(self):
        with redirect_stderr(io.StringIO()):
            self.assertIsNone(resolve_config(str(Path(self.home) / "nope.yml")))


if __name__ == "__main__":
    unittest.main()

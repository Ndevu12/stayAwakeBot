#!/usr/bin/env python3
"""A run's config is the operator's: the one named with `-c`, else the one saw's hooks were
installed with. A config file that sits in the working directory is not read on its own, and every
command refuses an allowlist it cannot apply."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hookscript
from stayawake.bots.security.config import resolve_config
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.remediator import _options as fix_options
from stayawake.bots.security.service.config import _options as scan_options

ALLOWLIST = "allowlist:\n  - {signature: fake-font-fa-solid-400, path_glob: 'tests/**'}\n"
UNUSABLE = "allowlist:\n  signature: fake-font-fa-solid-400\n"


class ConfigResolutionScope(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self.home = tempfile.mkdtemp()
        (Path(self.home) / "config").mkdir()
        self.here = Path(self.home) / "config" / "security.yml"
        self.here.write_text(ALLOWLIST)
        self.elsewhere = tempfile.mkdtemp()
        env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(self.elsewhere) / "xdg")})
        env.start()
        self.addCleanup(env.stop)
        os.chdir(self.home)

    def tearDown(self):
        os.chdir(self._cwd)

    def _resolve(self, *a, **kw):
        err = io.StringIO()
        with redirect_stderr(err):
            cfg = resolve_config(*a, **kw)
        return cfg, err.getvalue()

    def test_a_config_in_the_working_directory_is_not_read_on_its_own(self):
        cfg, said = self._resolve(None, targets=[str(Path(self.home) / "sub")])
        self.assertEqual(cfg, {})
        self.assertIn("was not read", said)

    def test_the_config_the_hooks_were_installed_with_applies_when_none_is_named(self):
        self.assertTrue(hookscript.declare("/usr/bin/saw", str(self.here)))
        cfg, said = self._resolve(None)
        self.assertEqual(len(cfg.get("allowlist", [])), 1)
        self.assertIn("allowlist rule(s) in effect", said)

    def test_a_scan_and_a_hook_judge_under_the_same_policy(self):
        self.assertTrue(hookscript.declare("/usr/bin/saw", str(self.here)))
        cfg, _ = self._resolve(None)
        recorded = hookscript.installed()[1]
        self.assertEqual(cfg.get("allowlist"), operator_policy(recorded).allowlist)

    def test_an_explicit_config_applies_to_any_target(self):
        cfg, said = self._resolve(str(self.here), targets=[self.elsewhere])
        self.assertEqual(len(cfg.get("allowlist", [])), 1)
        self.assertIn("allowlist rule(s) in effect", said)

    def test_a_named_config_that_is_missing_is_still_an_error(self):
        cfg, _ = self._resolve(str(Path(self.home) / "nope.yml"))
        self.assertIsNone(cfg)

    def test_every_command_refuses_an_allowlist_it_cannot_apply(self):
        bad = Path(self.elsewhere) / "bad.yml"
        bad.write_text(UNUSABLE)
        cfg, said = self._resolve(str(bad))
        self.assertIsNone(cfg)
        self.assertIn("must be a list", said)
        with self.assertRaises(ValueError):
            operator_policy(str(bad))


class FixUsesTheScanOptions(unittest.TestCase):
    def test_fix_and_scan_build_the_same_options_from_a_config(self):
        settings = {"scan_build_outputs": True, "keep_dirs": ["vendor"], "max_file_bytes": 1234}
        self.assertEqual(fix_options(settings), scan_options(settings))
        self.assertEqual(fix_options(settings).keep_dirs, {"vendor"})


if __name__ == "__main__":
    unittest.main()

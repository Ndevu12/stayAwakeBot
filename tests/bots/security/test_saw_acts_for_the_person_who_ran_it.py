#!/usr/bin/env python3
"""Under sudo, saw harden and saw audit cover the person who ran them as well as this process."""
from __future__ import annotations

import os
import pwd
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import global_prefix, host_artifacts
from stayawake.utils import operator

_ME = pwd.getpwuid(os.getuid())
_SUDO_BY_ME = {"SUDO_UID": str(_ME.pw_uid), "SUDO_USER": _ME.pw_name}


class TestTheHomesActedFor(unittest.TestCase):
    def test_a_run_without_sudo_covers_its_own_home_whatever_its_environment_says(self):
        with mock.patch.object(operator.os, "geteuid", return_value=_ME.pw_uid or 1):
            self.assertEqual(operator.homes_acted_for(_SUDO_BY_ME, own_home=lambda: Path("/own")),
                             [Path("/own")])

    def test_a_run_under_sudo_covers_its_own_home_and_the_person_who_ran_it(self):
        with mock.patch.object(operator.os, "geteuid", return_value=0):
            self.assertEqual(
                operator.homes_acted_for(_SUDO_BY_ME, own_home=lambda: Path("/var/root")),
                [Path("/var/root"), Path(_ME.pw_dir)])

    def test_a_run_under_sudo_that_kept_the_persons_home_names_it_once(self):
        with mock.patch.object(operator.os, "geteuid", return_value=0):
            self.assertEqual(
                operator.homes_acted_for(_SUDO_BY_ME, own_home=lambda: Path(_ME.pw_dir)),
                [Path(_ME.pw_dir)])

    def test_a_run_under_sudo_that_cannot_name_the_person_covers_its_own_home(self):
        with mock.patch.object(operator.os, "geteuid", return_value=0):
            self.assertEqual(operator.homes_acted_for({}, own_home=lambda: Path("/var/root")),
                             [Path("/var/root")])


class TestBothHomesAreLookedAt(unittest.TestCase):
    def setUp(self):
        self.own = Path(tempfile.mkdtemp(prefix="own-home-"))
        self.theirs = Path(tempfile.mkdtemp(prefix="their-home-"))
        for home in (self.own, self.theirs):
            self.addCleanup(shutil.rmtree, home, True)
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        for var in ("PREFIX", "NODE_PREFIX", "npm_config_prefix", "NPM_CONFIG_USERCONFIG",
                    "NVM_DIR", "VOLTA_HOME", "FNM_DIR"):
            os.environ.pop(var, None)
        homes = mock.patch.object(operator, "homes_acted_for",
                                  lambda env=None, own_home=None: [self.own, self.theirs])
        homes.start()
        self.addCleanup(homes.stop)

    def test_the_guarded_folders_are_in_both_homes(self):
        folders = {str(p) for p in host_artifacts._global_folders()}
        for home in (self.own, self.theirs):
            self.assertIn(str(home / ".node_modules"), folders)
            self.assertIn(str(home / ".node_libraries"), folders)

    def test_a_folder_named_in_an_npm_configuration_is_never_guarded(self):
        (self.theirs / ".npmrc").write_text(f"prefix={self.theirs / 'elsewhere'}\n")
        folders = {str(p) for p in host_artifacts._global_folders()}
        self.assertNotIn(str(self.theirs / "elsewhere" / "lib" / "node"), folders)

    def test_the_npm_prefix_either_configuration_sets_is_checked(self):
        for home in (self.own, self.theirs):
            (home / ".npmrc").write_text(f"prefix={home / 'npm-global'}\n")
        declared = global_prefix._declared_prefixes()
        for home in (self.own, self.theirs):
            self.assertIn(home / "npm-global", declared)

    def test_the_node_version_managers_in_either_home_are_checked(self):
        versions = [home / ".nvm" / "versions" / "node" / "v20.0.0" for home in (self.own, self.theirs)]
        for version in versions:
            version.mkdir(parents=True)
        managed = global_prefix._managed_prefixes()
        for version in versions:
            self.assertIn(version, managed)


if __name__ == "__main__":
    unittest.main()

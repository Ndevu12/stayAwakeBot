#!/usr/bin/env python3
"""Every setting the git on this machine documents whose last part names a program is in
`lib/data/git_exec_keys.yml`: among the keys whose value git runs, or among those that run nothing,
with why. A setting a later git adds fails here until it is listed."""
from __future__ import annotations

import re
import subprocess
import unittest

from stayawake.lib.git.exec_keys import exec_keys, rule_for, runs_nothing

PROGRAM_WORDS = ("command", "cmd", "path", "program", "tunnel", "helper", "driver", "textconv",
                 "clean", "smudge", "process", "editor", "pager", "proxy", "httpd", "askpass",
                 "sshcommand", "receivepack", "uploadpack", "vcs", "exec", "hook")
_PLACEHOLDER = re.compile(r"<[^>]*>|\*")


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=60).stdout


def _names_a_program(key: str) -> bool:
    return key.rsplit(".", 1)[-1].lower().endswith(PROGRAM_WORDS)


def _as_listed(key: str) -> str:
    """A documented key as `git config --list` would print one of its instances."""
    return _PLACEHOLDER.sub("x", key).lower()


class TestEveryProgramSettingIsListed(unittest.TestCase):
    def setUp(self):
        self.version = _git("--version").strip()
        self.documented = [line.strip() for line in _git("help", "--config").splitlines() if line.strip()]
        if not self.documented:
            self.skipTest(f"{self.version or 'git'} lists no settings")

    def test_each_one_runs_a_program_or_is_listed_as_running_nothing(self):
        unlisted = [key for key in self.documented if _names_a_program(key)
                    and rule_for(_as_listed(key)) is None
                    and not any(entry.matches(_as_listed(key)) for entry in runs_nothing())]
        self.assertEqual([], unlisted, f"settings {self.version} documents that are in neither list")

    def test_no_setting_is_in_both_lists(self):
        both = [key for key in self.documented
                if rule_for(_as_listed(key)) is not None
                and any(entry.matches(_as_listed(key)) for entry in runs_nothing())]
        self.assertEqual([], both, self.version)

    def test_the_settings_found_by_review_are_listed_as_running_a_program(self):
        for key in ("tar.x.command", "difftool.x.path", "mergetool.x.path", "man.x.path", "man.x.cmd",
                    "browser.x.path", "browser.x.cmd", "imap.tunnel", "instaweb.httpd", "remote.x.vcs",
                    "guitool.x.cmd", "gc.recentobjectshook", "sendemail.smtpserver"):
            with self.subTest(key=key):
                self.assertIsNotNone(rule_for(key))

    def test_every_way_a_value_is_kept_from_running_names_one_way(self):
        for rule in exec_keys():
            ways = [rule.override.setting, rule.override.environment, rule.override.reset]
            with self.subTest(key=rule.key):
                self.assertLessEqual(sum(way is not None for way in ways) + rule.override.refuse, 1)


if __name__ == "__main__":
    unittest.main()

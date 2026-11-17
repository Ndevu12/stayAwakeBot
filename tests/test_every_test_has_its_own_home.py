"""Every test runs in a home of its own, never the operator's."""

import os
import subprocess
import unittest
from pathlib import Path

from stayawake.bots.security import watchrecord
from tests.support import isolation

try:
    import pwd
except ImportError:
    pwd = None

_HOMES_SEEN: list[Path] = []


class EveryTestHasItsOwnHome(unittest.TestCase):

    def _home(self) -> Path:
        return Path(os.environ["HOME"])

    def test_the_home_is_a_test_home_and_not_the_operators(self):
        home = self._home()
        self.assertTrue(home.name.startswith(isolation.PREFIX), home)
        self.assertNotEqual(home, isolation.REAL_HOME)
        self.assertEqual(Path.home(), home)
        for name in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "GIT_CONFIG_GLOBAL"):
            self.assertTrue(Path(os.environ[name]).is_relative_to(home), name)

    def test_a_global_git_setting_lands_in_the_test_home(self):
        global_config = Path(os.environ.get("GIT_CONFIG_GLOBAL", isolation.REAL_HOME / ".gitconfig"))
        if not global_config.is_relative_to(self._home()) or not self._home().name.startswith(isolation.PREFIX):
            self.fail("git's global config is not in a test home, so this test does not write to it")
        subprocess.run(["git", "config", "--global", "saw.isolation", "held"], check=True)
        self.assertIn("held", (self._home() / ".gitconfig").read_text())

    @unittest.skipIf(pwd is None, "this platform has no account database")
    def test_the_account_database_names_the_test_home(self):
        self.assertEqual(Path(pwd.getpwuid(os.getuid()).pw_dir), self._home())
        self.assertTrue(watchrecord.shared_folder().is_relative_to(self._home()))

    def test_one_test_and_the_next_have_different_homes_1(self):
        _HOMES_SEEN.append(self._home())
        self.assertEqual(len(set(_HOMES_SEEN)), len(_HOMES_SEEN))

    def test_one_test_and_the_next_have_different_homes_2(self):
        _HOMES_SEEN.append(self._home())
        self.assertEqual(len(set(_HOMES_SEEN)), len(_HOMES_SEEN))


if __name__ == "__main__":
    unittest.main()

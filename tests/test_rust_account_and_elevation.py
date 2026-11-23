"""saw-platform finds the account saw acts for, asks for privilege and finds system programs exactly
as main does."""
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import elevate, operator, systembin

REPO_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class AccountAndElevationMatchMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "account_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "account_probe"

    def ask(self, cases: list[dict]) -> list:
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        return [json.loads(line) for line in printed]

    def test_the_acting_account(self):
        envs = [{"HOME": "/home/me", "USER": "me"}, {"HOME": ""}, {}, {"HOME": "/h", "SUDO_UID": "0", "SUDO_USER": "root"},
                {"SUDO_UID": "0", "SUDO_USER": "root"}, {"SUDO_UID": "1", "SUDO_USER": "root"}, {"SUDO_UID": " 1 "},
                {"SUDO_USER": "daemon"}, {"PKEXEC_UID": "1"}, {"SUDO_UID": "no", "DOAS_USER": "daemon"},
                {"SUDO_UID": "99999999999"}, {"SUDO_UID": "-1"}, {"SUDO_UID": "1_0"}, {"HOME": "/h"}]
        cases = [{"ask_about": "acting", "env": env, "euid": euid} for env in envs for euid in (0, 501)]
        for case, rust in zip(cases, self.ask(cases)):
            with self.subTest(case=case), mock.patch.object(operator.os, "geteuid", lambda: case["euid"]):
                found = operator.resolve(case["env"])
                main = None if found is None else [found.name, found.uid, str(found.home), found.via]
                self.assertEqual(rust, main)

    def test_administrators_trusted_sudo_and_system_programs(self):
        groups = [[], ["staff"], ["wheel"], ["admin", "staff"], ["sudo"], ["Wheel"]]
        candidates = [["/bin/sh"], ["/usr/bin/git", "/bin/sh"], [shutil.which("git") or "/x"], ["sh"], ["/no/such"],
                      [str(Path(__file__).resolve())], ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/true"]]
        cases = ([{"ask_about": "admin", "groups": g} for g in groups] + [{"ask_about": "sudo"}]
                 + [{"ask_about": "system", "candidates": c} for c in candidates])
        rust = self.ask(cases)
        main = ([elevate.may_use_sudo(groups=g) for g in groups] + [elevate.trusted_sudo()]
                + [systembin.system_binary(c) for c in candidates])
        self.assertEqual(rust, main)

    def test_asking_for_privilege(self):
        scenarios = [{"sudo": None}, {"sudo": "/usr/bin/sudo", "quiet": 0}, {"sudo": "/usr/bin/sudo", "quiet": None},
                     {"sudo": "/usr/bin/sudo", "quiet": 1, "admin": False},
                     {"sudo": "/usr/bin/sudo", "quiet": 1, "admin": True, "ask": False},
                     {"sudo": "/usr/bin/sudo", "quiet": 1, "admin": True, "ask": True, "asked": 0},
                     {"sudo": "/usr/bin/sudo", "quiet": 1, "admin": True, "ask": True, "asked": 1},
                     {"sudo": "/usr/bin/sudo", "quiet": 1, "admin": True, "ask": True, "asked": None}]
        rust = self.ask([{"ask_about": "elevate", **s} for s in scenarios])
        for scenario, answer in zip(scenarios, rust):
            seen = []

            def run(argv, **_):
                seen.append(argv)
                code = scenario["quiet"] if len(seen) == 1 else scenario.get("asked")
                if code is None:
                    raise OSError("could not run")
                return subprocess.CompletedProcess(argv, code)

            outcome, _ = elevate.run_as_root(["chflags", "uchg", "/x"], sudo=lambda: scenario["sudo"],
                                             ask=lambda: scenario.get("ask", False), admin=lambda: scenario.get("admin", False),
                                             run=run, quiet_spinners=lambda: __import__("contextlib").nullcontext())
            with self.subTest(scenario=scenario):
                self.assertEqual(answer, [outcome, seen])


if __name__ == "__main__":
    unittest.main()

"""saw-platform reads the environment exactly as main does."""
import json
import math
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import env

REPO_ROOT = Path(__file__).resolve().parents[1]
_WORDS = ["", " ", "1", "0", "off", "OFF", "False", "no", "yes", "on", "\x1c1\x1f", "\xa0off\xa0", "  0  ", "N"]
_NUMBERS = ["5", " 7.5 ", "0", "-5", "1e2", "+3", "1_000", "1__0", "_1", "inf", "-inf", "nan", "infinity", "1.", ".5",
            "abc", "0x10", "\x1c2\x1f"]
_SLUGS = ["owner/name", "owner/", "/name", "a/b/c", "plain", " a/b ", ""]


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class TheEnvironmentMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "env_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "env_probe"

    def homes(self) -> dict[str, str]:
        work = Path(tempfile.mkdtemp(prefix="env-homes-")).resolve()
        self.addCleanup(shutil.rmtree, work, True)
        keyed, public = work / "keyed", work / "public-only"
        (keyed / ".ssh").mkdir(parents=True)
        (keyed / ".ssh" / "id_ed25519").write_text("x")
        (public / ".ssh").mkdir(parents=True)
        (public / ".ssh" / "id_ed25519.pub").write_text("x")
        return {"keyed": str(keyed), "public": str(public), "trailing": str(public) + "/", "empty": ""}

    def cases(self) -> list[dict[str, str]]:
        homes = self.homes()
        cases = []
        for index, word in enumerate(_WORDS):
            cases.append({"HOME": homes["keyed"], "NO_COLOR": word, "CLICOLOR_FORCE": word, "CI": word,
                          "STAYAWAKE_STREAM": word, "SAW_HOOK_DISABLED": word, "NO_STREAM": word})
        for number in _NUMBERS:
            cases.append({"HOME": homes["public"], "SAW_HOOK_TIMEOUT": number})
        for slug in _SLUGS:
            cases.append({"HOME": homes["public"], "GITHUB_REPOSITORY": slug, "GITHUB_TOKEN": slug,
                          "SLACK_WEBHOOK_URL": slug})
        for name, home in homes.items():
            for marker in ({}, {"GITHUB_ACTIONS": "true"}, {"RUNNER_OS": " "}):
                cases.append({"HOME": home, **marker})
        cases.append({"HOME": homes["public"], "XDG_CONFIG_HOME": "/x/conf/", "XDG_CACHE_HOME": " rel/cache ",
                      "XDG_STATE_HOME": "", "SAW_AUTORUN_BASELINE": "/b/line"})
        return cases

    def main_answers(self, case: dict[str, str]) -> dict:
        with mock.patch.dict(os.environ, case, clear=True):
            slug = env.github_slug()
            return {
                "github_token": env.github_token(), "github_repository": env.github_repository(),
                "github_slug": list(slug) if slug else None, "slack_webhook": env.slack_webhook(),
                "no_color": env.no_color(), "clicolor_force": env.clicolor_force(), "is_ci": env.is_ci(),
                "stream_disabled": env.stream_disabled(), "stream_forced": env.stream_forced(),
                "hook_disabled": env.hook_disabled(), "hook_timeout": env.hook_timeout(),
                "hook_timeout_push": env.hook_timeout("pre-push"), "xdg_config_home": env.xdg_config_home(),
                "xdg_cache_home": env.xdg_cache_home(), "xdg_state_home": env.xdg_state_home(),
                "autorun_baseline_path": env.autorun_baseline_path(), "is_ephemeral_runner": env.is_ephemeral_runner(),
            }

    def test_every_answer_is_mains(self):
        cases = self.cases()
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        for case, line in zip(cases, printed):
            rust, main = json.loads(line), self.main_answers(case)
            for key in ("hook_timeout", "hook_timeout_push"):
                if isinstance(main[key], float) and math.isinf(main[key]):
                    main[key] = None
            with self.subTest(case=case):
                self.assertEqual(rust, main)


if __name__ == "__main__":
    unittest.main()

"""saw-platform puts every one of saw's stores exactly where main does."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import (clean_contents, clean_ledger, govern_status, hookscript, liveledger,
                                     push_record, schedule)
from stayawake.bots.security.dependencies import db
from stayawake.bots.security.harden import approvals, live, settings
from stayawake.bots.security.hygiene.autorun import baseline
from stayawake.bots.security.pr import arrival_record
from stayawake.lib import github_app

REPO_ROOT = Path(__file__).resolve().parents[1]


def _main(case: dict) -> dict:
    with mock.patch.dict(os.environ, case["env"], clear=True):
        s = str
        return {
            "git_template": s(hookscript.template_dir()), "hooks": s(hookscript.hooks_dir()),
            "hook_install": s(hookscript.declaration_path()), "hook_history_checked": s(hookscript.history_checked_path()),
            "hook_settings_scans": s(hookscript.settings_scan_path()), "hook_warnings_shown": s(hookscript.warnings_shown_path()),
            "hook_checks_made": s(hookscript.checks_made_path()), "hook_scan_cache": s(hookscript.cache_path()),
            "govern_applied": s(clean_ledger.applied_path()), "govern_accepted": s(clean_ledger.accepted_path()),
            "clean_contents_folder": s(hookscript.clean_contents_dir()),
            "clean_contents": s(clean_contents.store_path(Path(case["root"]))),
            "push_record": s(push_record.record_path(case["git_dir"])),
            "set_aside_hooks": s(hookscript.set_aside_dir()), "watch_install": s(schedule.record_path()),
            "live_code": s(liveledger.ledger_path()), "agent_approvals": s(approvals.record_path()),
            "editor_changes": s(settings.record_path()), "captured": s(live.capture_path()),
            "govern_status": s(govern_status.status_dir()), "autorun_baseline": s(baseline.baseline_path()),
            "amend_state": s(arrival_record.state_dir(case["slug"])), "advisories": s(db.default_cache_dir()),
            "github_app": s(github_app.config_path()), "github_app_earlier": s(github_app.legacy_config_path()),
            "watch_schedule": s(schedule.item_path()),
            "watch_shared": s(Path.home() / ".local" / "state" / "saw"),
        }


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class StoresAreWhereMainPutsThem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "stores_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "stores_probe"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="stores-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def keys(self) -> list[dict]:
        real = self.work / "real" / "repo"
        (real / ".git").mkdir(parents=True)
        os.symlink(self.work / "real", self.work / "linked")
        os.symlink("../real/repo", self.work / "relative-link")
        os.symlink(self.work / "loop-b", self.work / "loop-a")
        os.symlink(self.work / "loop-a", self.work / "loop-b")
        roots = [real, self.work / "linked" / "repo", self.work / "relative-link", self.work / "linked" / "missing" / "x",
                 self.work / "real" / ".." / "real" / "repo", self.work / "loop-a" / "x", Path("relative/path")]
        slugs = ["owner/name", "Owner/Name.js", "a b@c", "", "///", "café/repo", "x٣y"]
        return [{"root": str(root), "git_dir": str(root / ".git"), "slug": slug} for root, slug in zip(roots, slugs)]

    def envs(self) -> list[dict]:
        home = str(self.work / "home")
        return [
            {"HOME": home},
            {"HOME": home + "/", "XDG_CONFIG_HOME": "/x/conf/", "XDG_CACHE_HOME": " /x/cache ", "XDG_STATE_HOME": "/x//state"},
            {"HOME": home, "XDG_CONFIG_HOME": " ", "XDG_CACHE_HOME": "", "XDG_STATE_HOME": "rel/state"},
            {"HOME": home, "SAW_ADVISORY_CACHE_DIR": "~/adv", "SAW_AUTORUN_BASELINE": "/b/line.json"},
            {"HOME": home, "SAW_ADVISORY_CACHE_DIR": "~root/adv"},
            {"HOME": home, "SAW_ADVISORY_CACHE_DIR": "/plain/adv/"},
        ]

    def test_every_store_is_where_main_puts_it(self):
        keys = self.keys()
        cases = [{"env": env, **key} for env in self.envs() for key in keys]
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        for case, line in zip(cases, printed):
            rust, main = json.loads(line), _main(case)
            for store in main:
                with self.subTest(store=store, env=case["env"], root=case["root"], slug=case["slug"]):
                    self.assertEqual(rust[store], main[store])


if __name__ == "__main__":
    unittest.main()

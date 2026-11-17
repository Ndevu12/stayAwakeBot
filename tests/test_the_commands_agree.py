"""The hook, scan, fix and push checks give the same verdict on the same repository."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import ROLLBACK_DIR
from tests.support import samples

REPO_ROOT = Path(__file__).resolve().parents[1]
OPERATOR_ALLOWS_NOTHING = "allowlist: []\n"


class _Repositories(unittest.TestCase):
    """Repositories driven by real git commands, with this checkout's saw installed as the hooks."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="commands-agree-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)
        launcher = self.work / "bin" / "saw"
        launcher.parent.mkdir()
        launcher.write_text(f'#!/bin/sh\nPYTHONPATH={REPO_ROOT / "src"} exec {sys.executable} -m stayawake "$@"\n')
        launcher.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{launcher.parent}{os.pathsep}{os.environ['PATH']}"}
        self.assertEqual(self.run_saw("hook", "install").returncode, 0)

    def run_saw(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(["saw", *args], cwd=cwd or self.work, env=self.env, capture_output=True, text=True)

    def git(self, repo: Path, *args: str) -> str:
        done = subprocess.run(["git", "-c", "protocol.file.allow=always", "-c", "commit.gpgsign=false", *args],
                              cwd=repo, env=self.env, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout + done.stderr

    def write(self, repo: Path, files: dict[str, str]) -> None:
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)

    def source(self, files: dict[str, str]) -> Path:
        repo = self.work / f"source-{len(list(self.work.iterdir()))}"
        repo.mkdir()
        self.git(repo, "init", "-q", "-b", "main")
        self.commit(repo, files, "first")
        return repo

    def commit(self, repo: Path, files: dict[str, str], message: str) -> None:
        self.write(repo, files)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "--allow-empty", "-m", message)

    def clone(self, source: Path, name: str = "clone") -> tuple[Path, str]:
        dest = self.work / name
        printed = self.git(self.work, "clone", "-q", str(source), str(dest))
        return dest, printed

    def scan_document(self, target: Path, *extra: str, cwd: Path | None = None) -> dict:
        return json.loads(self.run_saw("scan", str(target), "--json", "--no-stream", *extra, cwd=cwd).stdout)

    def scan_verdict(self, target: Path, *extra: str, cwd: Path | None = None) -> str:
        document = self.scan_document(target, *extra, cwd=cwd)
        for flag, verdict in (("any_infected", "infected"), ("any_error", "not verified"),
                              ("any_suspicious", "suspicious"), ("any_residue", "residue")):
            if document.get(flag):
                return verdict
        return "clean"

    def hook_verdict(self, printed: str) -> str:
        if "WORM DETECTED" in printed:
            return "infected"
        if "what the project would not carry" in printed:
            return "residue"
        if "scanned clean" in printed:
            return "clean"
        return "silent"

    def fix_finds(self, repo: Path, *extra: str) -> bool:
        printed = self.run_saw("fix", "--path", str(repo), "--json", "--no-stream", *extra, cwd=repo).stdout
        return any(result.get("removed") for result in json.loads(printed).get("results", []))


class TheCommandsAgree(_Repositories):

    def test_1_a_repository_cannot_allow_its_own_finding(self):
        allows_itself = ("allowlist:\n  - signature_id: gitignore-autopush-markers\n    path_glob: '**'\n")
        clone, printed = self.clone(self.source({".gitignore": samples._gitignore(),
                                                 "config/security.yml": allows_itself}))
        self.assertEqual(self.hook_verdict(printed), "infected")
        self.assertEqual(self.scan_verdict(Path("."), cwd=clone), "infected")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertTrue(self.fix_finds(clone))

    @unittest.expectedFailure  # until M3, the engine
    def test_2_a_pull_that_touches_another_file_still_reports_what_the_repository_holds(self):
        source = self.source({".gitignore": samples._gitignore(), "README.md": "one\n"})
        self.env["SAW_HOOK_DISABLED"] = "1"
        clone, _ = self.clone(source)
        del self.env["SAW_HOOK_DISABLED"]
        self.commit(source, {"README.md": "two\n"}, "second")
        printed = self.git(clone, "pull", "-q", "--no-rebase")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

    def test_3_a_path_git_quotes_is_still_read(self):
        source = self.source({"README.md": "one\n"})
        clone, _ = self.clone(source)
        self.commit(source, {"dossier-été/.gitignore": samples._gitignore()}, "second")
        printed = self.git(clone, "pull", "-q", "--no-rebase")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

    @unittest.expectedFailure  # until M3, the engine
    def test_4_a_second_checkout_of_an_infected_head_still_reports_it(self):
        clone, first = self.clone(self.source({".gitignore": samples._gitignore()}))
        self.assertEqual(self.hook_verdict(first), "infected")
        self.git(clone, "switch", "-q", "-c", "other")
        printed = self.git(clone, "switch", "-q", "main")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

    def test_5_an_infection_outranks_a_file_that_could_not_be_read(self):
        source = self.source({"README.md": "one\n", "locked.txt": "x\n"})
        clone, _ = self.clone(source)
        (clone / "locked.txt").chmod(0)
        self.addCleanup((clone / "locked.txt").chmod, 0o644)
        self.commit(source, {".gitignore": samples._gitignore()}, "second")
        printed = self.git(clone, "pull", "-q", "--no-rebase")
        document = self.scan_document(clone)
        self.assertTrue(document["any_error"] or any(r["error"] for r in document["results"]))
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

    def test_6_a_repository_that_runs_its_hooks_from_elsewhere_is_still_checked(self):
        source = self.source({"README.md": "one\n"})
        clone, _ = self.clone(source)
        (clone / ".husky").mkdir()
        self.git(clone, "config", "core.hooksPath", ".husky")
        self.commit(source, {".gitignore": samples._gitignore()}, "second")
        printed = self.git(clone, "pull", "-q", "--no-rebase")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

    def test_7_fix_judges_the_branch_that_is_checked_out(self):
        clone, _ = self.clone(self.source({"README.md": "one\n"}))
        self.git(clone, "switch", "-q", "-c", "feature")
        self.commit(clone, {".gitignore": samples._gitignore()}, "feature work")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertTrue(self.fix_finds(clone))

    def test_8_fix_reads_build_output_when_the_scan_does(self):
        config = self.work / "operator.yml"
        config.write_text("allowlist: []\nsettings:\n  scan_build_outputs: true\n")
        clone, _ = self.clone(self.source({"README.md": "one\n", "dist/.gitignore": samples._gitignore()}))
        self.assertEqual(self.scan_verdict(clone, "-c", str(config)), "infected")
        self.assertTrue(self.fix_finds(clone, "-c", str(config)))

    def test_9_every_command_refuses_a_config_it_cannot_read(self):
        broken = self.work / "broken.yml"
        broken.write_text("allowlist: [\n")
        clone, _ = self.clone(self.source({"README.md": "one\n"}))
        for command in (["scan", str(clone)], ["fix", "--path", str(clone)], ["hook", "install"]):
            refused = self.run_saw(*command, "-c", str(broken), "--no-stream", cwd=clone)
            self.assertNotEqual(refused.returncode, 0, command)
            self.assertIn("config", (refused.stdout + refused.stderr).lower(), command)

    def test_10_residue_is_never_reported_as_clean(self):
        clone, printed = self.clone(self.source({"README.md": "one\n", f"{ROLLBACK_DIR}/README.md": "one\n"}))
        self.assertEqual(self.scan_verdict(clone), "residue")
        self.assertEqual(self.hook_verdict(printed), "residue")


    def test_11_the_push_check_reports_what_the_scan_reports(self):
        remote = self.work / "remote.git"
        self.git(self.work, "init", "-q", "--bare", "-b", "main", str(remote))
        clone, _ = self.clone(self.source({"README.md": "one\n"}))
        self.git(clone, "remote", "add", "out", str(remote))
        self.commit(clone, {".gitignore": samples._gitignore()}, "payload")
        printed = self.git(clone, "push", "-q", "out", "main")
        self.assertEqual(self.scan_verdict(clone), "infected")
        self.assertEqual(self.hook_verdict(printed), "infected")

if __name__ == "__main__":
    unittest.main()

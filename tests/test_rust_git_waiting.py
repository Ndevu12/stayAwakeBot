"""saw-platform says a repository's configuration would make git wait exactly when main does."""
import getpass
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib.git.exec_surface import config_waits

REPO_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("cargo") and hasattr(os, "mkfifo"), "needs cargo and named pipes")
class WaitingConfigurationMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "git_config_waits"],
                       cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "git_config_waits"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="git-waits-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)

    def repo(self, name: str) -> Path:
        repo = self.work / name
        subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
        return repo

    def include(self, repo: Path, value: str) -> None:
        with (repo / ".git" / "config").open("a") as config:
            config.write(f"[include]\n\tpath = {value}\n")

    def pipe(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(path)
        return path

    def scenarios(self) -> list[Path]:
        plain = self.repo("plain")
        piped = self.repo("piped-config")
        (piped / ".git" / "config").unlink()
        self.pipe(piped / ".git" / "config")
        relative = self.repo("relative-include")
        self.pipe(relative / ".git" / "fifo")
        self.include(relative, "fifo")
        absolute = self.repo("absolute-include")
        self.include(absolute, str(self.pipe(self.work / "elsewhere" / "fifo")))
        tilde = self.repo("tilde-user-include")
        self.include(tilde, f"~{getpass.getuser()}/no-such-file-saw-checks")
        tilde_pipe = self.repo("tilde-include-to-pipe")
        self.include(tilde_pipe, f"~{getpass.getuser()}/{'../' * 40}{self.pipe(self.work / 'home-pipe').relative_to('/')}")
        conditional = self.repo("expanded-include")
        self.include(conditional, "%(prefix)/fifo")
        cycle = self.repo("include-cycle")
        (cycle / ".git" / "a").write_text("[include]\n\tpath = b\n")
        (cycle / ".git" / "b").write_text("[include]\n\tpath = a\n")
        self.include(cycle, "a")
        deep = self.repo("deep-include")
        for level in range(12):
            (deep / ".git" / f"d{level}").write_text(f"[include]\n\tpath = d{level + 1}\n")
        self.pipe(deep / ".git" / "d12")
        self.include(deep, "d0")
        main_repo = self.repo("main-of-worktree")
        subprocess.run(["git", "-C", str(main_repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "one"], check=True,
                       capture_output=True)
        linked = self.work / "linked-worktree"
        subprocess.run(["git", "-C", str(main_repo), "worktree", "add", "-q", str(linked)], check=True, capture_output=True)
        (main_repo / ".git" / "config").rename(main_repo / ".git" / "config.real")
        self.pipe(main_repo / ".git" / "config")
        not_a_repo = self.work / "plain-folder"
        not_a_repo.mkdir()
        return [plain, piped, relative, absolute, tilde, tilde_pipe, conditional, cycle, deep, linked, main_repo,
                not_a_repo, self.work / "missing"]

    def test_every_scenario_is_answered_as_main_answers_it(self):
        hooks, neutral = self.work / "hooks", self.work / "neutral" / "dir"
        hooks.mkdir()
        neutral.mkdir(parents=True)
        repos = self.scenarios()
        printed = subprocess.run([str(self.tool)], input="\n".join([f"{hooks}\t{neutral}", *map(str, repos)]),
                                 capture_output=True, text=True, timeout=120, check=True).stdout.split()
        main_answers = [config_waits(repo) for repo in repos]
        for repo, rust, main_answer in zip(repos, printed, main_answers):
            with self.subTest(repo=repo.name):
                self.assertEqual(rust, str(main_answer).lower())
        self.assertEqual(len(printed), len(repos))
        self.assertGreaterEqual(main_answers.count(True), 5)


if __name__ == "__main__":
    unittest.main()

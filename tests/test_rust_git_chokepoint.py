"""saw-platform's git chokepoint runs a command exactly as main's does: the same refusals, and for an
allowed command the same arguments, environment and folder."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git import allowlist, contexts, owned
import importlib

git_run = importlib.import_module("stayawake.lib.git.run")

REPO_ROOT = Path(__file__).resolve().parents[1]
CONTEXTS = {"UNTRUSTED": contexts.UNTRUSTED, "SAW_OWNED": contexts.SAW_OWNED,
            "OPERATOR_PUSH": contexts.OPERATOR_PUSH, "OPERATOR_CONFIG": contexts.OPERATOR_CONFIG}
ARGS = [
    ["cat-file", "-p", "HEAD"], ["cat-file", "--textconv", "HEAD:a"], ["log", "--format=%H"],
    ["log", "--show-signature"], ["log", "--format=%G?"], ["diff", "HEAD"], ["diff", "a", "b"], ["diff", "a..b"],
    ["diff", "--no-index", "a", "b"], ["show", "HEAD"], ["config", "--get", "user.name"], ["config", "--add", "a.b", "c"],
    ["config", "user.name"], ["rev-parse", "--git-path", "hooks"], ["rev-parse", "HEAD"], ["ls-files", "-m"],
    ["ls-files", "-z"], ["read-tree", "HEAD"], ["update-index", "--add", "--cacheinfo", "100644,abc,a"],
    ["update-index", "--add", "a"], ["hash-object", "-w", "a"], ["hash-object", "--no-filters", "a"],
    ["tag", "-l"], ["tag", "-a", "v1"], ["symbolic-ref", "HEAD"], ["symbolic-ref", "HEAD", "refs/heads/x"],
    ["remote", "get-url", "origin"], ["remote", "add", "x", "y"], ["worktree", "list"], ["worktree", "add", "x"],
    ["checkout", "x"], ["merge", "x"], ["fetch", "origin"], ["pull"], ["push", "origin", "main"], ["clone", "u", "d"],
    ["ls-remote", "u"], ["credential", "fill"], ["credential", "approve"], ["version"],
    ["-c", "core.pager=less", "log"], ["-c", "user.name=x", "log"], ["-c", "hook.pre-push.command=x", "log"],
    ["-c", "includeIf.x.path=y", "log"], ["--config-env=a.b=C", "log"], ["--literal-pathspecs", "ls-files"], ["-p"],
]
ENVS = [None, {"PATH": "/usr/bin:/bin"},
        {"PATH": "/usr/bin", "GIT_DIR": "/elsewhere", "GIT_INDEX_FILE": "/tmp/index", "GIT_CONFIG_PARAMETERS": "'a.b'='c'",
         "GIT_CONFIG_GLOBAL": "/tmp/g", "GIT_AUTHOR_NAME": "a", "SAW_GOVERN_SYSTEM": "1", "SAW_GOVERN_HOLDING": "/h"}]


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class TheGitChokepointMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "git_prepared"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "git_prepared"

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="git-chokepoint-")).resolve()
        self.addCleanup(shutil.rmtree, self.work, True)
        self.hooks, self.neutral = self.work / "hooks", self.work / "neutral" / "dir"
        self.hooks.mkdir()
        self.neutral.mkdir(parents=True)
        self.repo = self.work / "repo"
        self.repo.mkdir()
        for name, value in (("_hooks_dir", self.hooks), ("_neutral_dir", self.neutral)):
            patcher = mock.patch.object(contexts, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(allowlist, "RAISE_ON_REFUSAL", True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _main(self, case: dict) -> dict:
        repo = case["repo"]
        if case["owned"]:
            owned.own(repo)
        try:
            argv, env, cwd = git_run._prepare(repo, list(case["args"]), case["env"], CONTEXTS[case["context"]])
            return {"argv": argv, "env": env, "cwd": cwd}
        except allowlist.GitRefused as refused:
            return {"refused": str(refused)}
        finally:
            owned.disown(repo) if repo else None

    def test_every_case_is_prepared_as_main_prepares_it(self):
        cases = [{"context": name, "repo": repo, "owned": owned_, "args": args, "env": env,
                  "inherited": dict(os.environ), "hooks": str(self.hooks), "neutral": str(self.neutral)}
                 for name in CONTEXTS for repo, owned_ in ((None, False), (str(self.repo), True), (str(self.repo), False))
                 for args in ARGS for env in ENVS]
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        allowed = 0
        for case, line in zip(cases, printed):
            with self.subTest(context=case["context"], repo=bool(case["repo"]), owned=case["owned"], args=case["args"],
                              env=sorted(case["env"]) if case["env"] else None):
                rust = json.loads(line)
                self.assertEqual(rust, self._main(case))
                allowed += "argv" in rust
        self.assertGreater(allowed, 100)


if __name__ == "__main__":
    unittest.main()

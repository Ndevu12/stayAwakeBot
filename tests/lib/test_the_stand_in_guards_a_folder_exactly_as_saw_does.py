#!/usr/bin/env python3
"""saw's git stand-in works out `run_with` itself, without starting saw, for each command it runs
directly. It answers the same as `saw govern classify`: both read the cases in `bots/mcp/session/tests/folder_guard_cases.json`, the stand-in's
crate tests in Rust and this module against `folder_guard`."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.lib.git import folder_guard, runs_directly, subcommand_options
from stayawake.lib.git.run import real_git

CASES_FILE = (Path(__file__).resolve().parents[2] / "src" / "stayawake" / "bots" / "mcp" / "session" / "tests"
              / "folder_guard_cases.json")
NO_HOOKS = "@NO_HOOKS@"


def build_folder(root: Path, case: dict, git: str) -> Path:
    """Make the folder one case runs in. Takes the case's own folder, the case and the git to make
    it with. Returns the folder the command runs in."""
    quiet = {"HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
             "PATH": os.environ.get("PATH", "")}

    def init(*args: str) -> None:
        subprocess.run([git, "init", "-q", *args], env=quiet, check=True, stdin=subprocess.DEVNULL)

    layout = case["layout"]
    if layout == "plain":
        (root / "folder").mkdir(parents=True)
        return root / "folder"
    if layout == "bare":
        init("--bare", str(root / "repo.git"))
        folder, settings = root / "repo.git", root / "repo.git"
    else:
        init(str(root / "repo"))
        folder, settings = root / "repo", root / "repo" / ".git"
        if layout == "submodule":
            init("--bare", str(settings / "modules" / "sub"))
            settings = settings / "modules" / "sub"
    with open(settings / "config", "a", encoding="utf-8") as handle:
        handle.write(case["settings"])
    for name, text in case.get("included", {}).items():
        (settings / name).write_text(text, encoding="utf-8")
    return folder


def environment(home: Path, case: dict) -> dict[str, str]:
    """The environment one case runs in. Takes the operator's home folder and the case."""
    return {"HOME": str(home), "XDG_STATE_HOME": str(home / "state"), "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1", **case.get("environment", {})}


def answer(folder: Path, case: dict, environ: dict[str, str]) -> dict:
    """Answer one case with saw's own guard. Returns the refusal or `run_with`, saw's empty hooks
    folder spelled `@NO_HOOKS@`."""
    with mock.patch.dict(os.environ, environ, clear=True):
        guarded = folder_guard.guard(folder, list(case["args"]), dict(environ))
    if guarded.refusal:
        return {"refused": True}
    hooks = str(Path(environ["XDG_STATE_HOME"]) / "saw" / "git-runs-no-hooks")
    shown = json.loads(json.dumps(guarded.run_with()).replace(json.dumps(hooks)[1:-1], NO_HOOKS))
    return {"settings": [[s["key"], s["value"]] for s in shown["settings"]], "arguments": shown["arguments"],
            "environment": shown["environment"]}


def answers(cases: dict) -> dict[str, dict]:
    """Answer every case with saw's own guard, each in a folder made for it. Returns them by name."""
    git = real_git()
    found: dict[str, dict] = {}
    with tempfile.TemporaryDirectory() as made:
        home = Path(os.path.realpath(made))
        (home / ".gitconfig").write_text(cases["operator_settings"], encoding="utf-8")
        for case in cases["cases"]:
            folder = build_folder(home / "cases" / case["name"], case, git)
            found[case["name"]] = answer(folder, case, environment(home, case))
            shutil.rmtree(home / "cases" / case["name"], ignore_errors=True)
    return found


class TheStandInGuardsAFolderExactlyAsSawDoes(unittest.TestCase):
    def test_saw_answers_every_shared_case_as_the_table_says(self) -> None:
        cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(cases["cases"]), 25)
        found = answers(cases)
        for case in cases["cases"]:
            with self.subTest(case["name"]):
                self.assertEqual(found[case["name"]], case["expected"])

    def test_the_table_covers_a_refusal_and_every_kind_of_override(self) -> None:
        cases = json.loads(CASES_FILE.read_text(encoding="utf-8"))["cases"]
        expected = [case["expected"] for case in cases]
        self.assertTrue(any(each.get("refused") for each in expected))
        self.assertTrue(any(each.get("environment") for each in expected))
        self.assertTrue(any(arg.startswith("--config-env=") for each in expected for arg in each.get("arguments", ())))

    def test_the_subcommands_no_alias_replaces_are_the_ones_saw_reads_option_by_option(self) -> None:
        self.assertEqual(set(runs_directly.tables()["subcommands_read_option_by_option"]),
                         set(subcommand_options.LISTED))


if __name__ == "__main__":
    unittest.main()

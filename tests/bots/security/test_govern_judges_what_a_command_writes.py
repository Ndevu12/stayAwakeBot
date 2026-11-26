#!/usr/bin/env python3
"""saw judges a git command by what it would write into the folder, replayed in a copy saw owns,
however the command is spelled and whichever repository, index or objects it names."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from stayawake.bots.security import govern, govern_command
from stayawake.lib.git import replay
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_LOADER = 'var _0x=[String.%s(127)];eval(_0x.join(""));\n' % samples.FROM_CHAR_CODE


class _Fetched(_TrackingCheckout):
    """A checkout tracking an upstream with a clean commit on main and, on evil, a commit that adds
    a payload followed by one that removes it."""

    def setUp(self):
        super().setUp()
        self.git(self.upstream, "checkout", "-q", "-b", "evil")
        self.write(self.upstream, "loader.js", _LOADER)
        self.commit(self.upstream, "worm")
        self.git(self.upstream, "rm", "-q", "loader.js")
        self.commit(self.upstream, "worm removed")
        self.git(self.upstream, "checkout", "-q", "main")
        self.git(self.open, "fetch", "-q")
        self.start = self.rev(self.open)

    def _prepare(self, *args: str, environment: "dict | None" = None, brings_no_files: bool = False):
        return govern.prepare(str(self.open), str(self.into), "git", list(args), environment=environment,
                              brings_no_files=brings_no_files)

    def _untouched(self) -> None:
        self.assertEqual(self.rev(self.open), self.start)
        self.assertFalse((self.open / "loader.js").exists())
        self.assertEqual(self.git(self.open, "status", "--porcelain").strip(), "")

    def _held(self, *args: str, environment: "dict | None" = None) -> dict:
        answer, code = self._prepare(*args, environment=environment)
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self._untouched()
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self._untouched()
        return answer

    def _asked(self, *args: str, environment: "dict | None" = None, brings_no_files: bool = False) -> dict:
        answer, code = self._prepare(*args, environment=environment, brings_no_files=brings_no_files)
        self.assertEqual(code, exitcodes.INCOMPLETE, answer)
        self.assertNotIn("passthrough", answer)
        self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"], answer)
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self._untouched()
        return answer

    def _passes(self, *args: str, brings_no_files: bool = False) -> None:
        answer, code = self._prepare(*args, brings_no_files=brings_no_files)
        self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
        self._untouched()

    def _blob(self, text: str) -> str:
        source = self.root / "staged-content"
        source.write_text(text, encoding="utf-8")
        return self.git(self.open, "hash-object", "-w", str(source)).strip()

    def _raw(self, *args: str, cwd: "Path | None" = None, env: "dict | None" = None) -> None:
        subprocess.run(["git", *args], cwd=cwd or self.open, check=True, capture_output=True,
                       env={**os.environ, **(env or {})})


class EverySpellingIsJudgedByWhatItWrites(_Fetched):

    def test_each_command_that_writes_the_payload_is_held(self):
        for args in (["reset", "--hard", "origin/evil~1"], ["reset", "origin/evil~1", "--hard"],
                     ["reset", "-q", "--keep", "origin/evil~1"], ["reset", "--merge", "origin/evil~1"],
                     ["reset", "--ha", "origin/evil~1"], ["-C", ".", "reset", "--hard", "origin/evil~1"],
                     ["--literal-pathspecs", "reset", "--hard", "origin/evil~1"],
                     ["--no-replace-objects", "checkout", "origin/evil~1"], ["-P", "checkout", "origin/evil~1"],
                     ["checkout", "origin/evil~1", "--", "."], ["cherry-pick", "origin/evil~1"],
                     ["cherry-pick", "-n", "origin/evil~1"], ["revert", "--no-edit", "origin/evil"],
                     ["restore", "-s", "origin/evil~1", "."], ["restore", "--source=origin/evil~1", "--", "."],
                     ["restore", "-Ws", "origin/evil~1", "."], ["restore", "--sou", "origin/evil~1", "."],
                     ["read-tree", "-u", "--reset", "origin/evil~1"], ["read-tree", "-mu", "HEAD", "origin/evil~1"],
                     ["merge", "origin/evil~1"], ["switch", "--detach", "origin/evil~1"]):
            with self.subTest(args=args):
                self._held(*args)

    def test_a_clean_reset_hard_moves_the_branch_and_the_files(self):
        answer, code = self._prepare("reset", "--hard", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/main"))
        self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), "main")
        self.assertEqual((self.open / "new.txt").read_text(encoding="utf-8"), "new\n")
        self.assertEqual(self.git(self.open, "status", "--porcelain").strip(), "")

    def test_a_clean_cherry_pick_lands_as_a_new_commit_on_the_branch(self):
        answer, code = self._prepare("cherry-pick", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertEqual(self.rev(self.open, "HEAD~1"), self.start)
        self.assertTrue((self.open / "new.txt").is_file())

    def test_a_command_that_writes_nothing_runs_as_typed(self):
        for args in (["reset", "--soft", "HEAD"], ["reset", "--hard"], ["reset", "--", "kept.txt"],
                     ["reset", "origin/feature"], ["checkout", "-b", "try"], ["switch", "-c", "try-too"],
                     ["stash", "list"], ["worktree", "list"], ["submodule", "status"],
                     ["update-ref", "refs/heads/elsewhere", "HEAD"], ["reset", "--soft", "origin/evil~1"]):
            with self.subTest(args=args):
                self._passes(*args)

    def test_the_files_a_moved_head_would_bring_are_judged_when_they_are_written(self):
        self._passes("reset", "--soft", "origin/evil~1")
        self.git(self.open, "reset", "-q", "--soft", "origin/evil~1")
        self.start = self.rev(self.open)
        answer, code = self._prepare("reset", "--hard")
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertFalse((self.open / "loader.js").exists())

    def test_staging_another_commits_files_is_judged_before_the_index_changes(self):
        self._held("reset", "origin/evil~1")
        answer, code = self._prepare("reset", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/main"))
        self.assertIn("new.txt", self.git(self.open, "ls-files"))
        self.assertFalse((self.open / "new.txt").exists())

    def test_staging_a_blob_is_judged_and_a_clean_one_lands_in_the_index(self):
        clean = self._blob("mine\n")
        answer, code = self._prepare("update-index", "--add", "--cacheinfo", "100644", clean, "kept.txt")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.assertIn(clean, self.git(self.open, "ls-files", "-s", "kept.txt"))
        self.git(self.open, "reset", "-q", "--", "kept.txt")
        infected = self._blob(_LOADER)
        for args in (["update-index", "--add", "--cacheinfo", "100644", infected, "loader.js"],
                     ["update-index", "--add", "--cacheinfo", f"100644,{infected},loader.js"]):
            with self.subTest(args=args):
                self._held(*args)
        self._asked("update-index", "--add", f"--cacheinfo=100644,{infected},loader.js")


class ACommandNamingAnotherRepositoryIsJudged(_Fetched):
    """The command names another repository, index or object store, whose files carry a payload."""

    def setUp(self):
        super().setUp()
        self.evil = self.new_repo("evil")
        self.write(self.evil, "loader.js", _LOADER)
        self.commit(self.evil, "payload")

    def test_a_repository_named_on_the_command_line_is_held(self):
        for args in ([f"--git-dir={self.evil / '.git'}", "--work-tree=.", "reset", "--hard"],
                     [f"--git-dir={self.evil / '.git'}", "--work-tree=.", "checkout", "-f"],
                     ["--git-dir", str(self.evil / ".git"), "--work-tree", str(self.open), "checkout", "-f"]):
            with self.subTest(args=args):
                self.assertNotIn("decision", self._held(*args))

    def test_a_repository_named_in_the_environment_is_held(self):
        for environment in ({"GIT_DIR": str(self.evil / ".git"), "GIT_WORK_TREE": str(self.open)},
                            {"GIT_DIR": str(self.evil / ".git")}):
            with self.subTest(environment=environment):
                self._held("checkout", "-f", environment=environment)

    def test_an_index_and_object_store_named_in_the_environment_are_held(self):
        index = self.root / "evil.index"
        self._raw("read-tree", "HEAD", cwd=self.evil, env={"GIT_INDEX_FILE": str(index)})
        self._held("checkout-index", "-a", "-f", environment={
            "GIT_INDEX_FILE": str(index), "GIT_OBJECT_DIRECTORY": str(self.evil / ".git" / "objects")})

    def test_a_bare_repository_committed_as_plain_files_is_held(self):
        bare = self.open / "vendor" / "x.git"
        self._raw("clone", "-q", "--bare", str(self.evil), str(bare))
        shutil.rmtree(bare / "hooks", ignore_errors=True)
        self.git(self.open, "add", "vendor")
        self.git(self.open, "commit", "-qm", "vendor")
        self.start = self.rev(self.open)
        self._held("--git-dir=vendor/x.git", "--work-tree=.", "checkout", "-f")

    def test_the_folders_own_repository_named_in_the_environment_is_written_as_usual(self):
        answer, code = self._prepare("reset", "--hard", "origin/main", environment={"GIT_DIR": str(self.open / ".git")})
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertTrue(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertTrue((self.open / "new.txt").exists())

    def test_a_clean_command_on_another_repository_is_the_operators_to_run(self):
        clean = self.new_repo("clean")
        self.write(clean, "a.txt", "plain\n")
        self.commit(clean, "plain")
        answer = self._asked(f"--git-dir={clean / '.git'}", "--work-tree=.", "checkout", "-f")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean")


class ACommandSawDoesNotReplayIsAsked(_Fetched):

    def test_it_is_left_to_the_operator_with_the_folder_unchanged(self):
        for args in (["co", "origin/evil~1"], ["chekout", "origin/evil~1"], ["clone", "https://example.invalid/r"],
                     ["worktree", "add", "../wt", "origin/evil~1"], ["submodule", "add", "https://example.invalid/r"],
                     ["submodule", "foreach", "git", "pull"], ["submodule", "update"], ["am"], ["bisect", "start"],
                     ["apply"], ["update-ref", "--stdin"], ["update-index", "--index-info"],
                     ["checkout-index", "-a", "--prefix=../export/"], ["read-tree", "--index-output=../i", "HEAD"],
                     ["rebase", "-x", "true", "origin/main"], ["merge", "-s", "custom", "origin/main"],
                     ["-c", "core.pager=less", "checkout", "origin/evil~1"],
                     ["--exec-path=/tmp", "checkout", "origin/evil~1"], ["--config-env=a.b=HOME", "status"]):
            with self.subTest(args=args):
                self._asked(*args)

    def test_after_a_clone_or_a_new_worktree_runs_as_typed_the_folder_it_creates_is_scanned(self):
        for created, args in (("tool", ["clone", "https://example.invalid/team/tool.git"]),
                              ("tool.git", ["clone", "--bare", "https://example.invalid/team/tool.git/"]),
                              ("dest", ["clone", "-o", "upstream", "https://example.invalid/team/tool", "dest"]),
                              ("../wt", ["worktree", "add", "-b", "try", "../wt", "origin/main"])):
            with self.subTest(args=args):
                answer, _code = self._prepare(*args)
                self.assertEqual(answer["decision"]["scan_after"], ["saw", "scan", str(Path(self.open) / created)])

    def test_a_command_that_would_update_submodules_is_asked(self):
        self._passes("checkout", "--recurse-submodules", "--", "kept.txt")
        (self.open / ".gitmodules").write_text('[submodule "sub"]\n\tpath = sub\n\turl = ../sub\n', encoding="utf-8")
        self.git(self.open, "add", ".gitmodules")
        self.git(self.open, "commit", "-qm", "modules")
        self.start = self.rev(self.open)
        for args in (["checkout", "--recurse-submodules", "--", "kept.txt"],
                     ["-c", "submodule.recurse=true", "reset", "--hard"], ["-c", "submodule.recurse", "restore", "."]):
            with self.subTest(args=args):
                self.assertEqual(self._asked(*args)["reason"], govern_command.UPDATES_SUBMODULES)
        self.git(self.open, "config", "submodule.recurse", "true")
        self._asked("restore", "kept.txt")
        self._passes("restore", "--no-recurse-submodules", "kept.txt")


class AnUpdateLandsAsGitWouldLandIt(_Fetched):
    """A clean pull, merge, checkout or hard reset leaves the folder the way git leaves a twin."""

    def _twin(self, name: str) -> Path:
        twin = self.root / name
        self._raw("clone", "-q", str(self.open), str(twin))
        self._raw("remote", "set-url", "origin", str(self.upstream), cwd=twin)
        self._raw("fetch", "-q", cwd=twin)
        return twin

    def _state(self, repo: Path) -> tuple:
        files = sorted(str(path.relative_to(repo)) + ":" + path.read_text(encoding="utf-8")
                       for path in repo.rglob("*") if path.is_file() and ".git" not in path.parts)
        return (files, self.git(repo, "ls-files", "-s"), self.git(repo, "rev-parse", "HEAD^{tree}"),
                self.git(repo, "status", "--porcelain"), self.git(repo, "branch", "--show-current"))

    def test_each_lands_what_git_lands(self):
        self.write(self.open, "mine.txt", "untracked work\n")
        for args in (["merge", "--ff-only", "origin/main"], ["checkout", "origin/main"], ["reset", "--hard", "origin/main"],
                     ["rebase", "origin/main"], ["pull", "--ff-only"]):
            with self.subTest(args=args):
                twin = self._twin("twin-" + "-".join(arg.strip("-/") for arg in args))
                self.write(twin, "mine.txt", "untracked work\n")
                self._raw(*args, cwd=twin)
                answer, code = self._prepare(*args)
                self.assertEqual(code, exitcodes.CLEAN, answer)
                self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
                self.assertEqual(self._state(self.open), self._state(twin))
                self.git(self.open, "checkout", "-q", "main")
                self.git(self.open, "reset", "-q", "--hard", self.start)

    def test_stashing_and_popping_work_round_trips(self):
        self.write(self.open, "kept.txt", "work in progress\n")
        for args in (["stash"], ["stash", "pop"]):
            answer, code = self._prepare(*args)
            self.assertEqual(code, exitcodes.CLEAN, answer)
            self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
            if args == ["stash"]:
                self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "kept\n")
                self.assertIn("stash@{0}", self.git(self.open, "stash", "list"))
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "work in progress\n")
        self.assertEqual(self.git(self.open, "stash", "list").strip(), "")

    def test_content_let_in_before_is_judged_from_the_record(self):
        answer, _code = self._prepare("checkout", "origin/main")
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True})
        self.git(self.open, "checkout", "-q", "main")
        scanned = []
        real = govern._scan_arrived

        def counted(root, landing, paths, *rest, **kw):
            scanned.extend(paths)
            return real(root, landing, paths, *rest, **kw)
        from unittest import mock
        with mock.patch.object(govern, "_scan_arrived", side_effect=counted):
            answer, code = self._prepare("checkout", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertNotIn("new.txt", scanned)


class WhatMakesGitRunFolderFilesIsAskedAbout(_Fetched):
    """An update to a file a hook manager runs is held for review even when it is clean, and a
    command that points git at folder files to run asks first."""

    def _held_for_review(self, *changed: str) -> dict:
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("merge", "--ff-only", "origin/main")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean", answer)
        self.assertIn("let-in", answer["decision"]["choices"], answer)
        for name in changed:
            self.assertTrue(any(name in step for step in answer["next_steps"]), (name, answer))
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        return answer

    def _upstream(self, files: dict) -> None:
        for name, text in files.items():
            self.write(self.upstream, name, text)
        self.commit(self.upstream, "tooling")

    def test_a_husky_hook_is_held_for_review(self):
        self._upstream({".husky/pre-commit": "npm test\n", ".husky/_/h": "#!/bin/sh\n"})
        self._held_for_review(".husky/pre-commit")

    def test_lefthook_and_the_scripts_it_names_are_held_for_review(self):
        self._upstream({"lefthook.yml": "pre-commit:\n  commands:\n    check:\n      run: ./scripts/check.sh\n",
                        "scripts/check.sh": "exit 0\n"})
        self._held_for_review("lefthook.yml", "scripts/check.sh")
        self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
        self.start = self.rev(self.open)
        self._upstream({"scripts/check.sh": "echo changed\n"})
        self._held_for_review("scripts/check.sh")

    def test_a_local_pre_commit_hook_is_held_for_review(self):
        config = "repos:\n- repo: local\n  hooks:\n  - id: lint\n    entry: tools/lint.sh\n    language: script\n"
        self._upstream({".pre-commit-config.yaml": config, "tools/lint.sh": "exit 0\n"})
        self._held_for_review(".pre-commit-config.yaml", "tools/lint.sh")

    def test_a_hook_manager_entry_in_package_json_is_held_and_other_changes_are_not(self):
        self._upstream({"package.json": json.dumps({"name": "a"})})
        self.git(self.open, "pull", "-q", "--ff-only")
        self.start = self.rev(self.open)
        self._upstream({"package.json": json.dumps({"name": "a", "simple-git-hooks": {"pre-commit": "x"}})})
        self._held_for_review("package.json")
        self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
        self.start = self.rev(self.open)
        self._upstream({"package.json": json.dumps({"name": "b", "simple-git-hooks": {"pre-commit": "x"}})})
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("merge", "--ff-only", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertNotIn("decision", answer)

    def test_pointing_git_at_a_folder_of_hooks_asks_first(self):
        (self.open / ".githooks").mkdir()
        for args in (["config", "core.hooksPath", ".githooks"], ["config", "set", "core.hookspath", ".githooks"],
                     ["config", "--local", "core.hooksPath", "./.githooks"], ["config", "--edit"],
                     ["-c", "core.hooksPath=.githooks", "commit", "-m", "x"], ["config", "alias.c", "!./run.sh"]):
            with self.subTest(args=args):
                answer = self._asked(*args, brings_no_files=True)
                self.assertTrue(answer["checked"], answer)
        self._asked("commit", "-m", "x", environment={"GIT_CONFIG_PARAMETERS": "'core.hooksPath'='.githooks'"},
                    brings_no_files=True)
        for args in (["config", "core.hooksPath", str(self.root / "elsewhere")], ["config", "user.name", "Me"],
                     ["config", "--get", "core.hooksPath"], ["-c", "color.ui=always", "status"]):
            with self.subTest(args=args):
                self._passes(*args, brings_no_files=True)

    def test_copying_hooks_from_a_folder_in_a_working_tree_asks_first(self):
        (self.open / "templates" / "hooks").mkdir(parents=True)
        for args, environment in ((["init", "--template=templates", str(self.root / "new")], None),
                                  (["init", "--templ", "templates", str(self.root / "new")], None),
                                  (["init", str(self.root / "new")], {"GIT_TEMPLATE_DIR": str(self.open / "templates")})):
            with self.subTest(args=args):
                self._asked(*args, environment=environment, brings_no_files=True)
        outside = self.root / "plain-template"
        outside.mkdir()
        self._passes("init", f"--template={outside}", str(self.root / "new"), brings_no_files=True)


class ACommandThatWritesAFileItNamesIsAsked(_Fetched):

    def test_an_output_file_or_a_fetch_it_names_is_left_to_the_operator(self):
        for args in (["diff", "--output=loader.js", "HEAD", "origin/evil~1"], ["log", "--output", "x.sh", "-1"],
                     ["show", "--output=x", "origin/evil~1"], ["remote", "add", "-f", "other", str(self.upstream)],
                     ["remote", "update"]):
            with self.subTest(args=args):
                self._asked(*args, brings_no_files=True)
                self.assertFalse((self.open / "x.sh").exists())

    def test_the_same_commands_without_them_run_as_typed(self):
        for args in (["diff", "HEAD", "origin/evil~1"], ["remote", "add", "other", str(self.upstream)],
                     ["log", "-1", "--", "--output=x"]):
            with self.subTest(args=args):
                self._passes(*args, brings_no_files=True)


class TheReplayRunsNothingOfTheFolders(_Fetched):

    def test_a_replay_never_writes_outside_its_copy(self):
        for args in (["checkout-index", "-a", "--prefix=../export/"], ["read-tree", "--index-output=../i", "HEAD"],
                     ["apply", "--build-fake-ancestor=../a", "x.patch"], ["apply", "--unsafe-paths", "x.patch"]):
            with self.subTest(args=args):
                self.assertIn(replay.refusal(__import__("stayawake.lib.git.typed_command", fromlist=["read"]).read(args)),
                              (replay.WRITES_ELSEWHERE, replay.READS_STANDARD_INPUT))
        self.assertFalse((self.root / "export").exists())


if __name__ == "__main__":
    import unittest
    unittest.main()

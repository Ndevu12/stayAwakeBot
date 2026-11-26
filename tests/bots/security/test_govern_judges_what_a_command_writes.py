#!/usr/bin/env python3
"""saw judges a git command by what it would write into the folder, replayed in a copy saw owns,
however the command is spelled and whichever repository, index or objects it names."""
from __future__ import annotations

import base64
import json
import os
import random
import shutil
import subprocess
from pathlib import Path

from stayawake.bots.security import govern, govern_command
from stayawake.lib.git import replay
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_LOADER = 'var _0x=[String.%s(127)];eval(_0x.join(""));\n' % samples.FROM_CHAR_CODE
_PACKED = "const s='%s';new Function(Buffer.from(s,'base64').toString())();\n" % base64.b64encode(
    random.Random(7).randbytes(4500)).decode()


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

    def _written_by_saw(self, *args: str, environment: "dict | None" = None) -> dict:
        answer, code = self._prepare(*args, environment=environment)
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertNotIn("passthrough", answer)
        self.assertIn("output", answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertFalse((self.open / "loader.js").exists())
        return answer

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
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/main"))
        self.assertEqual(self.git(self.open, "branch", "--show-current").strip(), "main")
        self.assertEqual((self.open / "new.txt").read_text(encoding="utf-8"), "new\n")
        self.assertEqual(self.git(self.open, "status", "--porcelain").strip(), "")

    def test_a_clean_cherry_pick_lands_as_a_new_commit_on_the_branch(self):
        answer, code = self._prepare("cherry-pick", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual(self.rev(self.open, "HEAD~1"), self.start)
        self.assertTrue((self.open / "new.txt").is_file())

    def test_a_command_that_writes_nothing_is_written_by_saw_and_never_run_again(self):
        for args in (["reset", "--soft", "HEAD"], ["reset", "--hard"], ["reset", "--", "kept.txt"],
                     ["reset", "origin/feature"], ["checkout", "-b", "try"], ["switch", "-c", "try-too"],
                     ["stash", "list"], ["update-ref", "refs/heads/elsewhere", "HEAD"]):
            with self.subTest(args=args):
                self._written_by_saw(*args)
                self.assertEqual(self.rev(self.open), self.start)
                self.git(self.open, "checkout", "-q", "main")
        self.assertIn("try", self.git(self.open, "branch"))
        for args in (["worktree", "list"], ["submodule", "status"]):
            with self.subTest(args=args):
                self._passes(*args)

    def test_what_the_replay_said_is_handed_back(self):
        answer = self._written_by_saw("checkout", "-b", "said")
        self.assertIn("said", answer["output"]["stderr"])

    def test_a_ref_moved_after_the_check_brings_nothing_in(self):
        answer, code = self._prepare("checkout", "-b", "raced", "origin/feature")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.git(self.open, "update-ref", "refs/remotes/origin/feature", "refs/remotes/origin/evil~1")
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual(self.rev(self.open), self.start)
        self.assertFalse((self.open / "loader.js").exists())

    def test_pathspec_settings_in_the_environment_are_replayed(self):
        self._held("reset", "origin/evil~1", "--", "LOADER.JS", environment={"GIT_ICASE_PATHSPECS": "1"})
        self._held("--icase-pathspecs", "checkout", "origin/evil~1", "--", "LOADER.JS")
        answer, code = self._prepare("checkout", "origin/evil~1", "--", "*.js", environment={"GIT_LITERAL_PATHSPECS": "1"})
        self.assertEqual(code, exitcodes.INCOMPLETE, answer)
        self._untouched()
        self._held("checkout", "origin/evil~1", "--", "*.js", environment={"GIT_GLOB_PATHSPECS": "1"})

    def test_the_files_a_moved_head_would_bring_are_judged_when_they_are_written(self):
        self._written_by_saw("reset", "--soft", "origin/evil~1")
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/evil~1"))
        self.start = self.rev(self.open)
        answer, code = self._prepare("reset", "--hard")
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertFalse((self.open / "loader.js").exists())

    def test_staging_another_commits_files_is_judged_before_the_index_changes(self):
        self._held("reset", "origin/evil~1")
        answer, code = self._prepare("reset", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual(self.rev(self.open), self.rev(self.open, "origin/main"))
        self.assertIn("new.txt", self.git(self.open, "ls-files"))
        self.assertFalse((self.open / "new.txt").exists())

    def test_staging_a_blob_is_judged_and_a_clean_one_lands_in_the_index(self):
        clean = self._blob("mine\n")
        answer, code = self._prepare("update-index", "--add", "--cacheinfo", "100644", clean, "kept.txt")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertIn(clean, self.git(self.open, "ls-files", "-s", "kept.txt"))
        self.git(self.open, "reset", "-q", "--", "kept.txt")
        infected = self._blob(_LOADER)
        for args in (["update-index", "--add", "--cacheinfo", "100644", infected, "loader.js"],
                     ["update-index", "--add", "--cacheinfo", f"100644,{infected},loader.js"]):
            with self.subTest(args=args):
                self._held(*args)
        self._asked("update-index", "--add", f"--cacheinfo=100644,{infected},loader.js")


class AMovedHeadIsNeverTakenAsJudged(_Fetched):
    """HEAD reaches a commit saw held without anything being written. The files it would bring are
    judged in full when they are."""

    def _then_a_hard_reset_is_held(self) -> None:
        moved = self.rev(self.open)
        answer, code = self._prepare("reset", "--hard")
        self.assertEqual(code, exitcodes.FINDINGS, answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertEqual(self.rev(self.open), moved)
        self.assertFalse((self.open / "loader.js").exists())

    def test_a_suspicious_file_another_working_tree_would_stage_is_held_with_a_failing_exit(self):
        other = self.root / "packed"
        other.mkdir()
        (other / "loader.js").write_text(_PACKED, encoding="utf-8")
        answer, code = self._prepare(f"--work-tree={other}", "add", "loader.js")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "suspicious", answer)
        self.assertNotEqual(code, exitcodes.CLEAN)
        self.assertNotIn("decision", answer)
        self.assertNotIn("loader.js", self.git(self.open, "ls-files"))

    def test_a_soft_reset_to_a_held_commit_records_nothing_and_its_files_are_judged(self):
        from stayawake.bots.security import clean_ledger
        self._written_by_saw("reset", "--soft", "origin/evil~1")
        moved = self.rev(self.open)
        self.assertEqual(moved, self.rev(self.open, "origin/evil~1"))
        self.assertFalse(clean_ledger.is_applied(self.open, clean_ledger.clean_key(moved, None)))
        self.assertFalse(clean_ledger.scanned_clean(self.open, clean_ledger.clean_key(moved, None)))
        self.assertIsNone(clean_ledger.let_in_commit(self.open, None))
        self._then_a_hard_reset_is_held()

    def test_a_branch_pointed_at_a_held_commit_and_made_head_is_judged_when_written(self):
        self.git(self.open, "branch", "elsewhere", "origin/evil~1")
        self.git(self.open, "symbolic-ref", "HEAD", "refs/heads/elsewhere")
        self._then_a_hard_reset_is_held()

    def test_a_suspicious_file_head_already_holds_is_still_held_when_written(self):
        self.write(self.upstream, "loader.js", _PACKED)
        self.commit(self.upstream, "packed")
        self.git(self.open, "fetch", "-q")
        answer, _code = self._prepare("checkout", "origin/main")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "suspicious", answer)
        for chain in ((["reset", "-q", "--soft", "origin/main"],),
                      (["branch", "packed", "origin/main"], ["symbolic-ref", "HEAD", "refs/heads/packed"])):
            with self.subTest(chain=chain):
                self.git(self.open, "checkout", "-q", "-f", "main")
                self.git(self.open, "reset", "-q", "--hard", self.start)
                for step in chain:
                    self.git(self.open, *step)
                moved = self.rev(self.open)
                answer, code = self._prepare("reset", "--hard")
                self.assertEqual(answer["scan"]["results"][0]["verdict"], "suspicious", answer)
                self.assertNotIn("pre_existing", answer)
                self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
                self.assertEqual(self.rev(self.open), moved)
                self.assertFalse((self.open / "loader.js").exists())

    def test_a_commit_made_from_another_working_tree_is_judged_when_written(self):
        other = self.root / "other"
        other.mkdir()
        (other / "loader.js").write_text(_LOADER, encoding="utf-8")
        self._held(f"--work-tree={other}", "add", "loader.js")
        self._raw(f"--work-tree={other}", "add", "loader.js")
        self._raw("commit", "-qm", "from elsewhere")
        self._then_a_hard_reset_is_held()

    def test_a_clean_update_onto_a_tree_saw_never_judged_is_not_recorded_as_judged(self):
        from stayawake.bots.security import clean_ledger
        answer, code = self._prepare("merge", "--ff-only", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertTrue(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertIsNone(clean_ledger.let_in_commit(self.open, None))

    def test_another_working_tree_on_a_command_that_brings_nothing_is_asked(self):
        self._asked(f"--work-tree={self.root}", "status")


class ConfigurationFilesTheEnvironmentNamesAreChecked(_Fetched):

    def test_one_in_the_folder_or_one_running_folder_files_asks_first(self):
        self.write(self.open, "tools/dev.gitconfig", "[diff]\n\trenames = true\n")
        outside = self.root / "outside.gitconfig"
        outside.write_text("[core]\n\tfsmonitor = sh tools/mon.sh\n", encoding="utf-8")
        self.write(self.open, "tools/mon.sh", "exit 0\n")
        self.git(self.open, "add", "tools")
        self.git(self.open, "commit", "-qm", "tools")
        self.start = self.rev(self.open)
        for name, value in (("GIT_CONFIG_GLOBAL", "tools/dev.gitconfig"), ("GIT_CONFIG_SYSTEM", str(outside)),
                            ("GIT_CONFIG", str(outside))):
            with self.subTest(name=name):
                self._asked("status", environment={name: value}, brings_no_files=True)
        plain = self.root / "plain.gitconfig"
        plain.write_text("[user]\n\tname = Me\n", encoding="utf-8")
        answer, code = self._prepare("status", environment={"GIT_CONFIG_GLOBAL": str(plain)}, brings_no_files=True)
        self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)


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
        self._written_by_saw("checkout", "--recurse-submodules", "--", "kept.txt")
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
        self._written_by_saw("restore", "--no-recurse-submodules", "kept.txt")


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
                self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
                self.assertEqual(self._state(self.open), self._state(twin))
                self.git(self.open, "checkout", "-q", "main")
                self.git(self.open, "reset", "-q", "--hard", self.start)

    def test_stashing_and_popping_work_round_trips(self):
        self.write(self.open, "kept.txt", "work in progress\n")
        for args in (["stash"], ["stash", "pop"]):
            answer, code = self._prepare(*args)
            self.assertEqual(code, exitcodes.CLEAN, answer)
            self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
            if args == ["stash"]:
                self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "kept\n")
                self.assertIn("stash@{0}", self.git(self.open, "stash", "list"))
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "work in progress\n")
        self.assertEqual(self.git(self.open, "stash", "list").strip(), "")

    def test_content_let_in_before_is_judged_from_the_record(self):
        answer, _code = self._prepare("checkout", "origin/main")
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
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

    def test_content_let_in_before_is_judged_again_under_another_mode(self):
        self._prepare("checkout", "origin/main")
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})
        self.git(self.open, "checkout", "-q", "main")
        blob = self.git(self.upstream, "rev-parse", "main:new.txt").strip()
        changed = {}
        for name, entry in (("executable", f"100755,{blob},new.txt"), ("link", f"120000,{blob},new.txt")):
            self.git(self.upstream, "checkout", "-q", "-f", "-B", name, "main")
            self.git(self.upstream, "update-index", "--cacheinfo", entry)
            self.git(self.upstream, "commit", "-qm", name)
            changed[name] = self.rev(self.upstream)
        self.git(self.upstream, "checkout", "-q", "-f", "main")
        self.git(self.open, "fetch", "-q")
        real = govern._scan_arrived
        from unittest import mock
        for name, args in (*((mode, ("checkout", commit)) for mode, commit in changed.items()),
                           ("staged executable", ("update-index", "--add", "--cacheinfo", f"100755,{blob},new.txt"))):
            with self.subTest(mode=name):
                scanned = []

                def counted(root, landing, paths, *rest, **kw):
                    scanned.extend(paths)
                    scanned.extend(rel for _copies, names in rest[3] for rel in names)
                    return real(root, landing, paths, *rest, **kw)
                with mock.patch.object(govern, "_scan_arrived", side_effect=counted):
                    answer, _code = self._prepare(*args)
                self.assertIn("new.txt", scanned, answer)


class WhatMakesGitRunFolderFilesIsAskedAbout(_Fetched):
    """An update to a file a hook manager runs is held for review even when it is clean, and a
    command that points git at folder files to run asks first."""

    def _held_for_review(self, *changed: str) -> dict:
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("merge", "--ff-only", "origin/main")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean", answer)
        self.assertIn("decision", answer, (code, answer))
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

    def _folder_configured(self, key: str, value: str, files: dict) -> None:
        self._upstream(files)
        self.git(self.open, "pull", "-q", "--ff-only")
        self.git(self.open, "config", key, value)
        self.start = self.rev(self.open)

    def test_a_file_the_folders_configuration_includes_or_runs_is_held_for_review(self):
        for key, value, name in (("include.path", "../shared.gitconfig", "shared.gitconfig"),
                                 ("core.fsmonitor", "tools/fsm.sh", "tools/fsm.sh"),
                                 ("core.fsmonitor", "sh tools/fsmon.sh", "tools/fsmon.sh"),
                                 ("filter.x.clean", "sh tools/filter.sh", "tools/filter.sh"),
                                 ("filter.x.smudge", "sh '$(git rev-parse --show-toplevel)/tools/smudge.sh'",
                                  "tools/smudge.sh"),
                                 ("includeIf.onbranch:main.path", "../shared.gitconfig", "shared.gitconfig")):
            with self.subTest(key=key):
                self._folder_configured(key, value, {name: "# first\n"})
                self._upstream({name: "# changed\n"})
                self._held_for_review(name)
                self.git(self.open, "config", "--unset", key)
                self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
                self.start = self.rev(self.open)

    def test_a_file_the_global_configuration_runs_is_held_for_review(self):
        from unittest import mock
        global_config = self.root / "global.gitconfig"
        global_config.write_text("[core]\n\tfsmonitor = tools/watch.sh\n", encoding="utf-8")
        self._upstream({"tools/watch.sh": "exit 0\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        self.start = self.rev(self.open)
        self._upstream({"tools/watch.sh": "echo changed\n"})
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
            self._held_for_review("tools/watch.sh")

    def _lands_without_asking(self, files: dict) -> None:
        self._upstream(files)
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("merge", "--ff-only", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertNotIn("decision", answer)
        self.assertTrue(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.start = self.rev(self.open)

    def test_a_file_a_hook_names_is_held_for_review_and_what_that_file_runs_is_left_to_the_scan(self):
        self._folder_configured("core.hooksPath", ".husky/_", {
            ".husky/pre-commit": "sh tools/check.sh\n", "tools/check.sh": "sh tools/deeper.sh\n",
            "tools/deeper.sh": "exit 0\n"})
        self._upstream({"tools/check.sh": "sh tools/deeper.sh\necho changed\n"})
        self._held_for_review("tools/check.sh")
        self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
        self.start = self.rev(self.open)
        self._lands_without_asking({"tools/deeper.sh": "echo changed\n"})

    def test_a_hook_naming_a_file_in_any_spelling_is_held_for_review(self):
        self._upstream({"scripts/x.sh": "exit 0\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        hook = self.open / ".git" / "hooks" / "pre-commit"
        for line in ('"$(git rev-parse --show-toplevel)/scripts/x.sh"', 'sh "$GIT_DIR/../scripts/x.sh"',
                     f"'{self.open}/scripts/x.sh'", '`git rev-parse --show-toplevel`/scripts/x.sh'):
            with self.subTest(line=line):
                hook.write_text(f"#!/bin/sh\n{line}\n", encoding="utf-8")
                self.start = self.rev(self.open)
                self._upstream({"scripts/x.sh": f"echo {len(line)}\n"})
                self._held_for_review("scripts/x.sh")
                self.git(self.open, "merge", "-q", "--ff-only", "origin/main")

    def test_a_script_a_hook_runs_through_npm_and_the_files_it_names_are_held_and_code_they_load_is_not(self):
        package = json.dumps({"scripts": {"test": "node tools/t.js"}})
        self._upstream({"package.json": package, "tools/t.js": "require('./util');\n", "tools/util.js": "1\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        (self.open / ".git" / "hooks" / "pre-push").write_text("#!/bin/sh\nnpm test\n", encoding="utf-8")
        self.start = self.rev(self.open)
        self._upstream({"tools/t.js": "require('./util');\n// changed\n"})
        self._held_for_review("tools/t.js")
        self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
        self.start = self.rev(self.open)
        self._upstream({"package.json": json.dumps({"scripts": {"test": "node tools/u.js"}}), "tools/u.js": "1\n"})
        self._held_for_review("package.json")
        self.git(self.open, "merge", "-q", "--ff-only", "origin/main")
        self.start = self.rev(self.open)
        self._lands_without_asking({"tools/util.js": "2\n"})

    def test_a_makefile_a_hook_runs_is_held_for_review(self):
        self._upstream({"Makefile": "lint:\n\t@echo lint\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        (self.open / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\nmake lint\n", encoding="utf-8")
        self.start = self.rev(self.open)
        self._upstream({"Makefile": "lint:\n\t@echo changed\n"})
        self._held_for_review("Makefile")

    def test_a_file_a_hook_outside_the_working_tree_names_is_held_for_review(self):
        self._upstream({"scripts/pre.sh": "exit 0\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        hook = self.open / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\n./scripts/pre.sh\n", encoding="utf-8")
        self.start = self.rev(self.open)
        self._upstream({"scripts/pre.sh": "echo changed\n"})
        self._held_for_review("scripts/pre.sh")

    def test_each_hook_manager_and_the_scripts_it_names_are_held_for_review(self):
        for files in ({".huskyrc.json": '{"hooks":{"pre-commit":"node tools/check.js"}}'},
                      {"husky.config.js": 'module.exports = {hooks: {"pre-commit": "node tools/check.js"}};'},
                      {".overcommit.yml": "PreCommit:\n  Custom:\n    required_executable: tools/check.sh\n"},
                      {".rusty-hook.toml": '[hooks]\npre-commit = "sh tools/check.sh"\n'},
                      {"lefthook-local.toml": '[pre-commit.commands.check]\nrun = "sh tools/check.sh"\n'},
                      {".config/lefthook.toml": '[pre-commit.commands.check]\nrun = "sh tools/check.sh"\n'},
                      {"lint-staged.config.js": 'module.exports = { "*.js": "node tools/check.js" };'},
                      {".lintstagedrc.json": '{"*.js": "node tools/check.js"}'},
                      {"package.json": json.dumps({"gitHooks": {"pre-commit": "node tools/check.js"}})},
                      {"package.json": json.dumps({"pre-commit": ["lint"], "scripts": {"lint": "node tools/check.js"}})},
                      {"package.json": json.dumps({"lint-staged": {"*.js": "node tools/check.js"}})}):
            name = next(iter(files))
            with self.subTest(name=name, files=files):
                self._held_for_review(*self._arrives(files))

    def test_a_script_a_hook_key_runs_through_npm_is_held_for_review(self):
        package = json.dumps({"pre-commit": ["lint"], "scripts": {"lint": "node tools/check.js"}})
        self._upstream({"package.json": package, "tools/check.js": "1\n"})
        self.git(self.open, "pull", "-q", "--ff-only")
        self.start = self.rev(self.open)
        self._upstream({"tools/check.js": "2\n"})
        self._held_for_review("tools/check.js")

    def _arrives(self, files: dict) -> tuple:
        self.git(self.open, "checkout", "-q", "main")
        self.git(self.open, "reset", "-q", "--hard", self.start)
        self._upstream({**files, "tools/check.js": "1\n", "tools/check.sh": "exit 0\n"})
        return tuple(files)

    def test_letting_a_push_change_the_folders_files_asks_first(self):
        for args in (["config", "receive.denyCurrentBranch", "updateInstead"],
                     ["config", "set", "receive.denycurrentbranch", "updateinstead"]):
            with self.subTest(args=args):
                self.assertEqual(self._asked(*args, brings_no_files=True)["reason"], govern_command.LETS_A_PUSH_WRITE)
        self._passes("config", "receive.denyCurrentBranch", "refuse", brings_no_files=True)

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

    def test_a_push_that_can_change_a_folder_on_this_machine_is_asked(self):
        other = self.root / "other"
        self._raw("clone", "-q", str(self.upstream), str(other))
        for args in (["push", ".", "HEAD:refs/heads/elsewhere"], ["push", str(other), "HEAD:refs/heads/x"],
                     ["push", f"file://{other}", "HEAD:refs/heads/x"], ["push", "origin", "HEAD:refs/heads/x"],
                     ["push"], ["push", "--receive-pack=git receive-pack", "https://example.invalid/r"],
                     ["push", "--exec", "git receive-pack", "https://example.invalid/r"],
                     ["-c", "receive.denyCurrentBranch=updateInstead", "push", ".", "HEAD:main"]):
            with self.subTest(args=args):
                self._asked(*args, brings_no_files=True)

    def test_a_push_elsewhere_or_into_a_repository_without_files_runs_as_typed(self):
        bare = self.root / "bare.git"
        self._raw("clone", "-q", "--bare", str(self.upstream), str(bare))
        self.git(self.open, "remote", "set-url", "origin", "https://example.invalid/team/r")
        for args in (["push", str(bare), "HEAD:refs/heads/x"], ["push", "https://example.invalid/r", "main"],
                     ["push", "git@example.invalid:team/r", "main"], ["push", "origin", "main"], ["push"]):
            with self.subTest(args=args):
                self._passes(*args, brings_no_files=True)

    def test_maintenance_that_fetches_or_schedules_runs_is_asked(self):
        for args in (["maintenance", "run", "--task=prefetch"], ["maintenance", "run", "--task", "prefetch"],
                     ["maintenance", "run", "--schedule=hourly"], ["maintenance", "start"],
                     ["maintenance", "register"]):
            with self.subTest(args=args):
                self.assertEqual(self._asked(*args, brings_no_files=True)["reason"], govern_command.FETCHES)
        for args in (["maintenance", "run", "--task=gc"], ["maintenance", "unregister"]):
            with self.subTest(args=args):
                self._passes(*args, brings_no_files=True)
        self.git(self.open, "config", "maintenance.prefetch.enabled", "true")
        self._asked("maintenance", "run", brings_no_files=True)

    def test_a_template_folder_the_configuration_names_asks_before_init(self):
        (self.open / "tpl" / "hooks").mkdir(parents=True)
        self.git(self.open, "config", "init.templateDir", str(self.open / "tpl"))
        self._asked("init", "-q", brings_no_files=True)

    def test_an_output_file_or_a_fetch_it_names_is_left_to_the_operator(self):
        for args in (["diff", "--output=loader.js", "HEAD", "origin/evil~1"], ["log", "--output", "x.sh", "-1"],
                     ["show", "--output=x", "origin/evil~1"], ["remote", "add", "-f", "other", str(self.upstream)],
                     ["remote", "update"]):
            with self.subTest(args=args):
                self._asked(*args, brings_no_files=True)
                self.assertFalse((self.open / "x.sh").exists())

    def test_a_grep_opening_the_files_it_finds_in_a_program_is_asked(self):
        for args in (["grep", "-Otouch", "new"], ["grep", "-iO", "new"], ["grep", "--open-files-in-pager=touch", "new"],
                     ["grep", "--open", "new"], ["grep", "-e", "new", "-O"], ["grep", "-e", "--", "-Otouch x; true"],
                     ["grep", "-e", "--", "--open-files-in-pager=touch"], ["grep", "-e", "--", "--open-files=touch"]):
            with self.subTest(args=args):
                self.assertEqual(self._asked(*args, brings_no_files=True)["reason"], govern_command.RUNS_A_PROGRAM)

    def test_the_same_commands_without_them_run_as_typed(self):
        for args in (["diff", "HEAD", "origin/evil~1"], ["remote", "add", "other", str(self.upstream)],
                     ["log", "-1", "--", "--output=x"], ["grep", "-n", "new"], ["grep", "-eO", "new"],
                     ["grep", "-n", "new", "--", "-O"]):
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

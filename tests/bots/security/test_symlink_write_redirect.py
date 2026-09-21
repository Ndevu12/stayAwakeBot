#!/usr/bin/env python3
"""#1161 — a committed symlink that redirects a WRITE into a sensitive sink (GhostApproval / SymJacking).

The scan-side complement to the `saw audit` mechanism-persistence checks: flag a repo that ships a
symlink whose target escapes into ~/.ssh, a shell startup file, credentials, a GPG keyring, an
OS-persistence dir, or an AI-agent config — so any tool told to write the link's path writes THROUGH it.
CONFIRMED / critical (no legitimate purpose); never follows the link. All against inert fixtures.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, CLEAN, SUSPICIOUS
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security import write_sinks
from stayawake.bots.security.matchers import symlink
from stayawake.lib.git import query
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions


def _stored(name: str, target: str):
    """Grade one stored version the way history does. Takes the path and the target it names.
    Returns the findings."""
    return symlink._stored_finding(
        name, target, {},
        {"id": WRITE_REDIRECT, "category": "c", "severity": "4", "description": "d"})

SIGS = load_signatures()
WRITE_REDIRECT = "symlink-write-redirect"
ESCAPE = "symlink-escapes-repo"


class _Base(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.outside = Path(tempfile.mkdtemp())
        (self.repo / "a.js").write_text("const x = 1;\n")

    def _scan(self):
        return scan_target(LocalRepoTarget(self.repo, "t", ScanOptions()), SIGS, [])

    def _ids(self):
        return {f.signature_id for f in self._scan().findings}

    def _link(self, name: str, target: Path, is_dir: bool = False):
        target.parent.mkdir(parents=True, exist_ok=True)
        if is_dir:
            target.mkdir(parents=True, exist_ok=True)
        (self.repo / name).symlink_to(target, target_is_directory=is_dir)


class TestSinkTruePositives(_Base):
    SINKS = {
        ".ssh/authorized_keys": "SSH", ".ssh/id_ed25519": "SSH key",
        ".bashrc": "bash", ".zshrc": "zsh", ".profile": "profile", ".bash_aliases": "bash_aliases",
        ".config/fish/config.fish": "fish",
        ".gitconfig": "gitconfig", ".config/git/config": "xdg git",
        ".aws/credentials": "aws", ".kube/config": "kube", ".config/gcloud/x": "gcloud",
        ".pypirc": "pypi", ".netrc": "netrc", ".gem/credentials": "gem",
        ".gnupg/secring.gpg": "gpg",
        "Library/LaunchAgents/x.plist": "launchagent", ".config/systemd/user/x.service": "systemd",
        ".config/autostart/x.desktop": "autostart", ".crontab": "crontab",
        ".local/share/systemd/user/x.service": "systemd-user",
        ".local/bin/black": "path-bin", ".cargo/bin/x": "cargo-bin",
        ".deno/bin/x": "deno-bin", ".bun/bin/npm": "bun-bin",
        ".config/fish/conf.d/00-x.fish": "fish drop-in",
        ".vimrc": "vim", ".config/nvim/init.lua": "nvim", ".emacs": "emacs", ".emacs.d/init.el": "emacs.d",
        ".config/Code/User/settings.json": "vscode-user-settings",
        ".ipython/profile_default/startup/00-x.py": "ipython", ".jupyter/x.py": "jupyter",
        ".gdbinit": "gdb", ".lldbinit": "lldb", ".tmux.conf": "tmux", ".Rprofile": "rprofile",
    }

    def test_every_sink_is_infected(self):
        for rel, why in self.SINKS.items():
            with self.subTest(sink=rel):
                repo = Path(tempfile.mkdtemp()); outside = Path(tempfile.mkdtemp())
                (repo / "a.js").write_text("x")
                tgt = outside / rel; tgt.parent.mkdir(parents=True, exist_ok=True); tgt.write_text("x")
                (repo / "innocuous.json").symlink_to(tgt)
                r = scan_target(LocalRepoTarget(repo, "t", ScanOptions()), SIGS, [])
                ids = {f.signature_id for f in r.findings}
                self.assertIn(WRITE_REDIRECT, ids, f"{why}: {rel}")
                self.assertEqual(r.verdict, INFECTED, why)

    def test_relative_escape_to_ssh_is_flagged(self):
        # The portable attack shape: a RELATIVE `../…/.ssh/authorized_keys` that climbs out of the repo.
        deep = self.repo / "src" / "nested"; deep.mkdir(parents=True)
        ak = self.outside / ".ssh" / "authorized_keys"
        ak.parent.mkdir(parents=True); ak.write_text("")
        rel_target = os.path.relpath(ak, deep)
        (deep / "config.json").symlink_to(rel_target)
        self.assertIn(WRITE_REDIRECT, self._ids())

    def test_dangling_symlink_to_sink_is_flagged(self):
        # The real attack state: the target does NOT exist yet — the victim's WRITE creates it. resolve()
        # canonicalizes a dangling link without requiring existence, so it is still caught.
        ak = self.outside / ".ssh" / "authorized_keys"     # never created
        (self.repo / "config.json").symlink_to(ak)
        self.assertIn(WRITE_REDIRECT, self._ids())

    def test_directory_symlink_to_sink_is_write_redirect_not_escape(self):
        # A DIR symlink into a sink is the stronger write-redirect, not the scan-evasion heuristic.
        self._link("dotssh", self.outside / ".ssh", is_dir=True)
        ids = self._ids()
        self.assertIn(WRITE_REDIRECT, ids)
        self.assertNotIn(ESCAPE, ids)

    def test_excluded_dir_named_symlink_still_caught(self):
        # A write-redirect symlink whose NAME is an excluded dir (dist/build/node_modules — exactly
        # where build tools write) must still be flagged; pruning only stops DESCENT, not classification.
        for name in ("dist", "build", "node_modules", ".git"):
            with self.subTest(name=name):
                repo = Path(tempfile.mkdtemp()); outside = Path(tempfile.mkdtemp())
                (repo / "a.js").write_text("x")
                (outside / ".ssh").mkdir()
                (repo / name).symlink_to(outside / ".ssh", target_is_directory=True)
                r = scan_target(LocalRepoTarget(repo, "t", ScanOptions()), SIGS, [])
                self.assertIn(WRITE_REDIRECT, {f.signature_id for f in r.findings}, name)

    def test_case_insensitive_sink_is_flagged(self):
        # macOS/Windows case-insensitive FS: ~/.SSH/authorized_keys is the SAME file as ~/.ssh/... —
        # a case-flip must not evade the sink patterns.
        tgt = self.outside / ".SSH" / "AUTHORIZED_KEYS"
        tgt.parent.mkdir(parents=True); tgt.write_text("")
        (self.repo / "k").symlink_to(tgt)
        self.assertIn(WRITE_REDIRECT, self._ids())

    def test_system_persistence_absolute_target_flagged(self):
        # System persistence paths (root-gated but real in CI-as-root/Docker) via absolute raw target.
        for tgt in ("/etc/systemd/system/evil.service", "/etc/profile.d/evil.sh",
                    "/etc/cron.d/evil"):
            with self.subTest(tgt=tgt):
                repo = Path(tempfile.mkdtemp())
                (repo / "a.js").write_text("x")
                (repo / "unit").symlink_to(tgt)
                r = scan_target(LocalRepoTarget(repo, "t", ScanOptions()), SIGS, [])
                self.assertIn(WRITE_REDIRECT, {f.signature_id for f in r.findings}, tgt)


class TestFalsePositiveBoundaries(_Base):
    def test_escaping_file_symlink_to_non_sink_is_clean(self):
        # A venv-style interpreter shim / any non-sink escaping file link is NOT flagged.
        tgt = self.outside / "usr" / "bin" / "python3"
        self._link("python", tgt)
        self.assertEqual(self._scan().verdict, CLEAN)

    def test_in_repo_symlink_to_own_dotfile_is_clean(self):
        # A link to the repo's OWN .npmrc / .vscode (inside the repo) is not a redirect — no escape.
        (self.repo / ".npmrc").write_text("registry=...\n")
        (self.repo / "pkg").mkdir()
        (self.repo / "pkg" / ".npmrc").symlink_to(self.repo / ".npmrc")
        self.assertNotIn(WRITE_REDIRECT, self._ids())

    def test_substring_not_component_is_clean(self):
        # A path merely CONTAINING a sink word as a longer segment (`.sshfoo`, `myssh`) must not match.
        for rel in (".sshfoo/x", "myssh/notes", "config.fishy/x", "npmrc.bak"):
            with self.subTest(rel=rel):
                repo = Path(tempfile.mkdtemp()); outside = Path(tempfile.mkdtemp())
                (repo / "a.js").write_text("x")
                tgt = outside / rel; tgt.parent.mkdir(parents=True, exist_ok=True); tgt.write_text("x")
                (repo / "link").symlink_to(tgt)
                r = scan_target(LocalRepoTarget(repo, "t", ScanOptions()), SIGS, [])
                self.assertNotIn(WRITE_REDIRECT, {f.signature_id for f in r.findings}, rel)

    def test_escaping_dir_to_non_sink_is_still_only_heuristic(self):
        # The pre-existing scan-evasion behavior is preserved: a dir link escaping to a NON-sink is the
        # heuristic escape (SUSPICIOUS), not a write-redirect.
        self._link("escape", self.outside / "shared" / "lib", is_dir=True)
        ids = self._ids()
        self.assertIn(ESCAPE, ids)
        self.assertNotIn(WRITE_REDIRECT, ids)
        self.assertEqual(self._scan().verdict, SUSPICIOUS)

    def test_workspace_shared_project_config_is_not_confirmed(self):
        # A polyrepo/microservice workspace routinely shares .npmrc / .vscode / .docker/config.json via
        # a sibling symlink. These are shareable PROJECT artifacts, deliberately excluded from the
        # CONFIRMED sinks — a FILE link to one must be CLEAN (not INFECTED).
        shared = self.outside / ".shared"; shared.mkdir()
        (shared / ".npmrc").write_text("registry=https://npm.internal\n")
        (shared / "config.json").write_text("{}")
        (self.repo / ".npmrc").symlink_to(shared / ".npmrc")
        (self.repo / "docker").mkdir()
        (self.repo / "docker" / "config.json").symlink_to(shared / "config.json")
        r = self._scan()
        self.assertNotIn(WRITE_REDIRECT, {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, CLEAN)


    def test_a_repository_that_links_into_its_own_control_directory_is_not_confirmed(self):
        objects = self.repo / ".git" / "annex" / "objects" / "Wz"
        objects.mkdir(parents=True, exist_ok=True)
        (objects / "SHA256E-data").write_text("x\n")
        (self.repo / "data.nii").symlink_to(objects / "SHA256E-data")
        self.assertNotIn(WRITE_REDIRECT, {f.signature_id for f in self._scan().findings})
        self._link("leaked", self.outside / ".ssh" / "authorized_keys")
        self.assertIn(WRITE_REDIRECT, self._ids())


class TestGitsOwnExecSurface(_Base):
    """A link into what git runs from a control directory is a redirect wherever it lands."""

    EXEC = {"githooks": ".git/hooks", "hook": ".git/hooks/pre-commit", "cfg": ".git/config",
            "deep": "../.git/config", "sub": "../.git/modules/pkg/hooks",
            "wt": ".git/worktrees/w/config.worktree",
            "nested-sub": ".git/modules/vendor/libfoo/hooks/pre-commit",
            "nested-cfg": ".git/modules/packages/ui/config",
            "bare": "../mirror.git/hooks/post-receive"}
    STORAGE = {"annexed": "../.git/annex/objects/Wz/8j/SHA256E-x",
               "lfs": ".git/lfs/objects/aa/bb", "packed": ".git/objects/pack/p.pack",
               "workflow": ".github/workflows", "ignore": ".gitignore",
               "own-hooks-dir": "scripts/.git-hooks",
               "lock": ".git/config.lock", "backup": ".git/config.bak",
               "turned-off": ".git/hooks-disabled/x", "longer": ".git/hooksomething"}

    def test_what_git_runs_is_a_redirect(self):
        for name, target in self.EXEC.items():
            with self.subTest(target=target):
                (self.repo / name).symlink_to(self.repo / target)
                self.assertIn(WRITE_REDIRECT, self._ids(), target)
                self.assertIn(WRITE_REDIRECT,
                              {f.signature_id for f in _stored(name, target)}, target)
                (self.repo / name).unlink()

    def test_where_it_lands_decides_and_not_how_it_is_spelled(self):
        (self.repo / "docs").mkdir(exist_ok=True)
        (self.repo / "docs" / "README.md").write_text("x\n")
        (self.repo / "doc").symlink_to(self.repo / ".git" / "hooks" / ".." / ".." / "docs"
                                       / "README.md")
        self.assertNotIn(WRITE_REDIRECT, self._ids())

    def test_what_git_only_stores_is_not(self):
        for name, target in self.STORAGE.items():
            with self.subTest(target=target):
                (self.repo / name).symlink_to(self.repo / target)
                self.assertNotIn(WRITE_REDIRECT, self._ids(), target)
                self.assertEqual([], _stored(name, target), target)
                (self.repo / name).unlink()
        self._link("leaked", self.outside / ".ssh" / "authorized_keys")
        self.assertIn(WRITE_REDIRECT, self._ids())


class TestTheLinkTextAndTheLanding(unittest.TestCase):
    """Check that the link text and where it lands are each matched."""

    def test_the_link_text_alone_names_a_sink(self):
        self.assertEqual("shell startup file",
                         write_sinks.sink_label("../../.zshrc", Path("/elsewhere/tmpfile")))

    def test_where_it_lands_alone_names_a_sink(self):
        self.assertEqual("SSH keys/config (~/.ssh)",
                         write_sinks.sink_label("x", Path("/u/.ssh/id_ed25519")))


class TestACheckoutInsideASinkIsOneQuestion(unittest.TestCase):
    """Check that a repository inside a sink and a link to a sibling are answered alike."""

    SIG = {"id": WRITE_REDIRECT, "category": "c", "severity": "4", "description": "d"}
    ROOT = "/u/.vim/pack/p/start/pkgA"

    def _graded(self, raw, resolved):
        return bool(symlink._graded("k", raw, Path(resolved), Path(self.ROOT),
                                    self.SIG, None, False))

    def test_the_inert_sibling_and_the_executed_one_are_answered_alike(self):
        inert = self._graded("../pkgB/doc/x.txt", "/u/.vim/pack/p/start/pkgB/doc/x.txt")
        executed = self._graded("../pkgB/plugin/x.vim", "/u/.vim/pack/p/start/pkgB/plugin/x.vim")
        self.assertEqual(inert, executed, "the two were separated — update this characterisation")
        self.assertTrue(executed, "the one the sink's owner executes must still be reported")

    def test_a_checkout_inside_a_sink_still_reports_reaching_it(self):
        for raw, resolved, root in (
                ("../../../..", "/u/.vim", "/u/.vim/pack/x/start/plug"),
                ("../cron.d/evil.sh", "/etc/cron.d/evil.sh", "/etc/nixos"),
                ("../LaunchAgents/x.plist", "/u/Library/LaunchAgents/x.plist", "/u/Library/proj"),
                ("../../bin/black", "/u/.local/bin/black", "/u/.local/share/proj")):
            with self.subTest(root=root):
                self.assertTrue(bool(symlink._graded("k", raw, Path(resolved), Path(root),
                                                     self.SIG, None, False)))


class TestWhereARepositoryRuns(unittest.TestCase):
    """Check that a repository is asked where it executes from."""

    def _repo(self, name):
        root = Path(tempfile.mkdtemp()) / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for k, v in (("user.email", "t@t"), ("user.name", "t")):
            subprocess.run(["git", "-C", str(root), "config", k, v], check=True)
        (root / "a.js").write_text("const x = 1;\n")
        return root

    def _reports(self, root):
        r = scan_target(LocalRepoTarget(root, "t", ScanOptions()), SIGS, [])
        return WRITE_REDIRECT in {f.signature_id for f in r.findings}

    def test_a_hooks_directory_kept_in_the_tree_is_still_where_it_runs(self):
        root = self._repo("tracked")
        (root / ".githooks").mkdir()
        shutil.rmtree(root / ".git" / "hooks", ignore_errors=True)
        (root / ".git" / "hooks").symlink_to("../.githooks")
        (root / "x").symlink_to(".git/hooks/pre-commit")
        self.assertTrue(self._reports(root))

    def test_a_repository_that_names_its_own_hooks_directory_is_believed(self):
        root = self._repo("hookspath")
        (root / "myhooks").mkdir()
        subprocess.run(["git", "-C", str(root), "config", "core.hooksPath", "myhooks"], check=True)
        (root / "x").symlink_to("myhooks/pre-commit")
        self.assertTrue(self._reports(root))

    def test_a_control_directory_kept_elsewhere_is_still_found(self):
        root = self._repo("elsewhere")
        moved = root.parent / "realgitdir"
        (root / ".git").rename(moved)
        (root / ".git").symlink_to("../realgitdir")
        (root / "x").symlink_to(".git/config")
        self.assertTrue(self._reports(root))

    def test_the_scanned_repository_answers_not_one_named_in_the_environment(self):
        root = self._repo("asked")
        (root / "myhooks").mkdir()
        subprocess.run(["git", "-C", str(root), "config", "core.hooksPath", "myhooks"], check=True)
        (root / "x").symlink_to("myhooks/pre-commit")
        elsewhere = self._repo("unrelated")
        prior = os.environ.get("GIT_DIR")
        os.environ["GIT_DIR"] = str(elsewhere / ".git")
        try:
            runs_from = query.exec_paths(root)
            self.assertTrue(self._reports(root))
        finally:
            if prior is None:
                os.environ.pop("GIT_DIR", None)
            else:
                os.environ["GIT_DIR"] = prior
        self.assertTrue(any(str(root) in p for p in runs_from), runs_from)
        self.assertFalse(any(str(elsewhere) in p for p in runs_from), runs_from)


class TestSafety(_Base):
    def test_symlink_loop_completes(self):
        (self.repo / "loop_a").symlink_to(self.repo / "loop_b")
        (self.repo / "loop_b").symlink_to(self.repo / "loop_a")
        self._scan()   # must not hang or raise

    def test_absolute_sink_target_is_flagged(self):
        # An absolute target naming a sink (attacker who knows the layout) is caught via the raw text.
        (self.repo / "k").symlink_to("/home/victim/.ssh/authorized_keys")
        self.assertIn(WRITE_REDIRECT, self._ids())

class TestWhatFollowsAControlDirectory(unittest.TestCase):
    """Check what a control directory is followed through to."""

    REPORT = (
        "/r/.git",
        "/r/.git/modules/pkg",
        "/r/.git/worktrees/w",
        "/r/.git/hooks/pre-commit",
        "/r/.git/config",
        "/r/.git/worktrees/w/config.worktree",
        "/r/.git/modules/pkg/hooks/pre-commit",
        "/r/.git/modules/" + "a/" * 18 + "hooks/pre-commit",
        "/other/.git/hooks/pre-commit",
        "/srv/foo.git/hooks/pre-commit",
    )
    SILENT = (
        "/w/app.git/packages/web/config",
        "/w/app.git/packages/web/src/hooks",
        "/labs/mirrors.git/proj/etc/config",
        "/r/.git/annex/objects/x/y/f",
        "/r/.git/lfs/objects/aa/bb/f",
        "/r/.git/objects/pack/p.pack",
        "/r/.git/refs/heads/config",
        "/r/.git/refs/heads/feature/hooks",
        "/r/.git/config.lock",
        "/r/.git/hooks-disabled/x",
    )

    def test_it_reports_what_git_runs(self):
        for path in self.REPORT:
            with self.subTest(path):
                self.assertTrue(write_sinks.control_exec_sink(Path(path)))

    def test_it_stays_silent_on_what_git_stores(self):
        for path in self.SILENT:
            with self.subTest(path):
                self.assertFalse(write_sinks.control_exec_sink(Path(path)))


class TestWhatARepositorySaysAboutItself(unittest.TestCase):
    """Check which answers about where a repository runs are believed."""

    def _repo(self, hooks_path):
        root = Path(tempfile.mkdtemp()) / "handed-over"
        (root / "docs").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "core.hooksPath", hooks_path], check=True)
        (root / "a.js").write_text("const x = 1;\n")
        (root / "README.md").write_text("hi\n")
        (root / "alias").symlink_to("README.md")
        (root / "docsalias").symlink_to("docs")
        return root

    def _reports(self, root):
        r = scan_target(LocalRepoTarget(root, "t", ScanOptions()), SIGS, [])
        return WRITE_REDIRECT in {f.signature_id for f in r.findings}

    def test_an_answer_naming_the_working_tree_is_dropped(self):
        root = self._repo(".")
        self.assertFalse(self._reports(root))
        self.assertFalse(any(str(root) == p for p in query.exec_paths(root)))

    def test_an_answer_naming_a_parent_of_the_working_tree_is_dropped(self):
        root = self._repo("..")
        self.assertFalse(self._reports(root))

    def test_an_ordinary_hooks_directory_is_still_believed(self):
        root = self._repo("myhooks")
        (root / "myhooks").mkdir()
        (root / "x").symlink_to("myhooks/pre-commit")
        self.assertTrue(self._reports(root))

    def test_it_is_believed_whatever_case_the_link_spells_it_in(self):
        root = self._repo("myhooks")
        (root / "myhooks").mkdir()
        (root / "x").symlink_to("MyHooks/pre-commit")
        self.assertTrue(self._reports(root))


class TestPerUserExecutableDirectories(unittest.TestCase):
    """Check which directories of executables are matched."""

    REPORT = ("/Users/u/.yarn/bin/yarn", "/Users/u/.volta/bin/node", "/Users/u/.asdf/shims/python",
              "/home/u/.rbenv/shims/ruby", "/root/.local/bin/x",
              "/Users/u/.nvm/versions/node/v20.11.0/bin/node",
              "/Users/u/.sdkman/candidates/java/current/bin/java")
    SILENT = ("/Users/u/dev/tools/proj/.venv/bin/python", "/Users/u/dev/proj/.venv-verify/bin/python3",
              "/Users/u/dev/other-repo/.github/bin/lint.sh", "/Users/u/dev/p/.tox/py311/bin/pytest")

    def test_it_reports_a_per_user_executable_directory(self):
        for path in self.REPORT:
            with self.subTest(path):
                self.assertEqual("PATH executable dir", write_sinks.sink_label(path, Path(path)))

    def test_it_leaves_a_workspace_directory_alone(self):
        for path in self.SILENT:
            with self.subTest(path):
                self.assertIsNone(write_sinks.sink_label(path, Path(path)))


class TestPythonStartupHooks(unittest.TestCase):
    """Check that a file the interpreter executes at start is a sink."""

    def test_it_reports_a_path_configuration_file(self):
        p = "/Users/u/.local/lib/python3.11/site-packages/evil.pth"
        self.assertEqual("Python startup hook (exec-on-start)", write_sinks.sink_label(p, Path(p)))

    def test_it_reports_a_customize_module(self):
        p = "/usr/lib/python3/dist-packages/usercustomize.py"
        self.assertEqual("Python startup hook (exec-on-start)", write_sinks.sink_label(p, Path(p)))

    def test_it_leaves_an_ordinary_module_alone(self):
        self.assertIsNone(write_sinks.sink_label("docs/customize.py", Path("/r/docs/customize.py")))


if __name__ == "__main__":
    unittest.main()

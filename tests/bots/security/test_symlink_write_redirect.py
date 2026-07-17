#!/usr/bin/env python3
"""#1161 — a committed symlink that redirects a WRITE into a sensitive sink (GhostApproval / SymJacking).

The scan-side complement to the `saw audit` mechanism-persistence checks: flag a repo that ships a
symlink whose target escapes into ~/.ssh, a shell startup file, credentials, a GPG keyring, an
OS-persistence dir, or an AI-agent config — so any tool told to write the link's path writes THROUGH it.
CONFIRMED / critical (no legitimate purpose); never follows the link. All against inert fixtures.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, CLEAN, SUSPICIOUS
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

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


class TestSafety(_Base):
    def test_symlink_loop_completes(self):
        (self.repo / "loop_a").symlink_to(self.repo / "loop_b")
        (self.repo / "loop_b").symlink_to(self.repo / "loop_a")
        self._scan()   # must not hang or raise

    def test_absolute_sink_target_is_flagged(self):
        # An absolute target naming a sink (attacker who knows the layout) is caught via the raw text.
        (self.repo / "k").symlink_to("/home/victim/.ssh/authorized_keys")
        self.assertIn(WRITE_REDIRECT, self._ids())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A repository whose own configuration names a program for every place git will run one. Every
program leaves a marker file, named after the setting that ran it, in a sentinel directory outside
the repository. The repository is armed last, so building it runs none of its programs. All the
programs are one script reached through links named after each marker."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

from stayawake.utils import scratch
from tests.support.gitrepo import GitSandbox

HOOK_NAMES = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
    "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit", "post-index-change",
)
"""Every hook name `githooks(5)` documents for git 2.39."""

# What each program does after leaving its marker; a marker not named here exits 0.
_PASSES_STDIN = ("filter.clean", "filter.smudge", "filter-named-a=b.clean",
                 "filter-named-a=b.smudge", "core.pager", "core.worktree")
_FAILS = ("core.fsmonitor", "core.sshCommand", "url.insteadOf", "url.pushInsteadOf",
          "gpg.program", "gpg.ssh.program")

_MARK = """#!/bin/sh
marker="${{0##*/}}"
case "$0" in */hooks/*) marker="hook-$marker" ;; esac
: > "{sentinel}/$marker"
case "$marker" in
  {passes}) exec cat ;;
  {fails}) exit 1 ;;
  diff.textconv) exec cat "$1" ;;
  uploadpack.packObjectsHook) exec "$@" ;;
  filter.process) exec "{python}" "{process_filter}" ;;
esac
exit 0
"""

# A long-running filter that speaks the protocol and hands content back unchanged.
_PROCESS_FILTER = r'''
import sys
i, o = sys.stdin.buffer, sys.stdout.buffer
def read():
    n = i.read(4)
    if not n:
        sys.exit(0)
    n = int(n, 16)
    return None if n == 0 else i.read(n - 4)
def packets():
    out = []
    while True:
        p = read()
        if p is None:
            return out
        out.append(p)
def send(*lines):
    for line in lines:
        o.write(b"%04x" % (len(line) + 4) + line)
    o.write(b"0000")
    o.flush()
packets()
send(b"git-filter-server\n", b"version=2\n")
packets()
send(b"capability=clean\n", b"capability=smudge\n")
while True:
    packets()
    content = b"".join(packets())
    send(b"status=success\n")
    send(*[content[at:at + 65516] for at in range(0, len(content), 65516)])
    send()
'''

_ATTRIBUTES = (
    "*.txt filter=evil merge=evil diff=evil\n"
    "*.cfg filter=a=b merge=a=b diff=evilcmd\n"
    "*.on filter=evilproc merge=onbranch\n"
    "*.gd merge=gitdir\n"
    "*.inc merge=included\n"
)
_ATTRIBUTES_BY_REPLACEMENT = _ATTRIBUTES + "*.rep merge=viareplace\n"

# One file per driver-bearing pattern.
_DRIVEN_FILES = ("notes.txt", "settings.cfg", "branch.on", "place.gd", "shared.inc", "swap.rep")

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
LAUNCHER = ('{"version":"2.0.0","tasks":[{"label":"prep","type":"shell",'
            '"command":"node ./public/fonts/text.woff",'
            '"runOptions":{"runOn":"folderOpen"}}]}\n')


@dataclass
class HostileRepo:
    """The armed repository, the bare repository it calls `origin`, and where markers land.

    `triggers` names every marker a program in this repository can leave.
    """

    repo: Path
    origin: Path
    sentinel: Path
    bin: Path
    triggers: list[str] = field(default_factory=list)

    def fired(self) -> list[str]:
        """The markers present now, sorted."""
        return sorted(p.name for p in self.sentinel.iterdir())

    def clear(self) -> None:
        """Remove every marker, so the next step is measured on its own."""
        for marker in self.sentinel.iterdir():
            marker.unlink()


class HostileRepoSandbox(GitSandbox):
    """A `GitSandbox` that allows the `ext::` transport and keeps saw's own scratch under the test's
    root."""

    PROTOCOLS = "file:ext"

    def setUp(self):
        super().setUp()
        tmp = self.owned(self.root / "tmp")
        tmp.mkdir()
        isolated = mock.patch.dict(os.environ, {"TMPDIR": str(tmp)})
        isolated.start()
        self.addCleanup(isolated.stop)
        tempfile.tempdir = None
        self.addCleanup(setattr, tempfile, "tempdir", None)
        # saw's own scratch lands under this test's root too, and is released when it ends;
        # whatever an earlier test still held is set aside and handed back untouched.
        held_before = (scratch._root, list(scratch._areas))
        scratch._root = None
        scratch._areas.clear()
        self.addCleanup(self._restore_scratch, held_before)
        self.addCleanup(scratch.release)

    @staticmethod
    def _restore_scratch(held_before) -> None:
        scratch._root, areas = held_before
        scratch._areas[:] = areas

    def hostile_repo(self, name: str = "hostile", *, redirect_worktree: bool = False) -> HostileRepo:
        """Build and arm a hostile repository under this test's root. `redirect_worktree` also points
        `core.worktree` at a decoy directory whose attributes name a filter of their own."""
        repo = self.new_repo(name, user__name="Tester")
        origin = self.owned(self.root / f"{name}-origin.git")
        sentinel = self.owned(self.root / f"{name}-sentinel")
        bin_dir = self.owned(self.root / f"{name}-bin")
        sentinel.mkdir()
        bin_dir.mkdir()
        hostile = HostileRepo(repo=repo, origin=origin, sentinel=sentinel, bin=bin_dir)
        self._build_history(repo)
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)],
                       check=True, capture_output=True)
        self.git(repo, "remote", "add", "origin", str(origin))
        self.git(repo, "push", "-q", "origin", "main", "conflict", "side")
        self.git(repo, "fetch", "-q", "origin")
        self.git(repo, "remote", "set-head", "origin", "main")
        self._arm(hostile, redirect_worktree=redirect_worktree)
        self._make_stat_dirty(repo)
        leftover = hostile.fired()
        if leftover:
            raise AssertionError(f"building the fixture ran its own programs: {leftover}")
        return hostile

    # --- building -------------------------------------------------------------------------

    def _build_history(self, repo: Path) -> None:
        """`main` holds the payload from a past commit on, and a merge whose two sides changed
        every driven file; `conflict` changes each of them again, differently."""
        self.write(repo, ".gitattributes", _ATTRIBUTES)
        self.write(repo, "package.json", '{"name":"example-app","version":"1.0.0"}\n')
        self.write(repo, "src/index.js", "export const greet = (n) => `hi ${n}`;\n")
        for rel in _DRIVEN_FILES:
            self.write(repo, rel, f"base {rel}\n")
        self.commit(repo, "project")
        self.write(repo, "public/fonts/text.woff", LOADER)
        self.write(repo, ".vscode/tasks.json", LAUNCHER)
        self.commit(repo, "fonts and tasks")
        self.git(repo, "checkout", "-q", "-b", "side")
        for rel in _DRIVEN_FILES:
            self.write(repo, rel, f"side {rel}\n")
        self.commit(repo, "side changes every driven file")
        self.git(repo, "checkout", "-q", "main")
        for rel in _DRIVEN_FILES:
            self.write(repo, rel, f"main {rel}\n")
        self.commit(repo, "main changes every driven file")
        self.git_may_fail(repo, "merge", "--no-ff", "--no-commit", "-q", "side")
        for rel in _DRIVEN_FILES:
            self.write(repo, rel, f"merged {rel}\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch 'side'")
        self.git(repo, "checkout", "-q", "-b", "conflict", "main~1")
        for rel in _DRIVEN_FILES:
            self.write(repo, rel, f"conflict {rel}\n")
        self.commit(repo, "conflict changes every driven file")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "notes.txt", "merged notes.txt\nlater\n")
        self.write(repo, "settings.cfg", "merged settings.cfg\nlater\n")
        self.commit(repo, "later work")

    def _write_mark(self, hostile: HostileRepo) -> Path:
        """Write the one program every marker runs, and return its path."""
        process_filter = hostile.bin / "process_filter.py"
        process_filter.write_text(_PROCESS_FILTER, encoding="utf-8")
        mark = hostile.bin / "mark"
        mark.write_text(_MARK.format(sentinel=hostile.sentinel, passes="|".join(_PASSES_STDIN),
                                     fails="|".join(_FAILS), python=sys.executable,
                                     process_filter=process_filter), encoding="utf-8")
        mark.chmod(0o755)
        return mark

    def _program(self, hostile: HostileRepo, marker: str) -> str:
        """The path that runs the shared program as `marker`."""
        link = hostile.bin / marker
        link.symlink_to("mark")
        hostile.triggers.append(marker)
        return str(link)

    def _arm(self, hostile: HostileRepo, *, redirect_worktree: bool) -> None:
        repo, git_dir = hostile.repo, hostile.repo / ".git"
        self._arm_replace_ref(repo)
        mark = self._write_mark(hostile)
        hooks = git_dir / "hooks"
        for sample in hooks.iterdir():
            sample.unlink()
        for name in HOOK_NAMES:
            (hooks / name).symlink_to(mark)
            hostile.triggers.append(f"hook-{name}")

        p = lambda marker: self._program(hostile, marker)  # noqa: E731
        included = {
            "includeIf.onbranch": (git_dir / "onbranch.inc", "onbranch"),
            "includeIf.gitdir": (git_dir / "gitdir.inc", "gitdir"),
            "include.path": (git_dir / "included.inc", "included"),
        }
        for marker, (path, driver) in included.items():
            path.write_text(f'[merge "{driver}"]\n\tdriver = {p(marker)}\n', encoding="utf-8")

        config = (
            "[core]\n"
            f"\tfsmonitor = {p('core.fsmonitor')}\n"
            f"\tsshCommand = {p('core.sshCommand')}\n"
            f"\tpager = {p('core.pager')}\n"
            f"\teditor = {p('core.editor')}\n"
            "[sequence]\n"
            f"\teditor = {p('sequence.editor')}\n"
            '[filter "evil"]\n'
            f"\tclean = {p('filter.clean')}\n"
            f"\tsmudge = {p('filter.smudge')}\n"
            '[filter "a=b"]\n'
            f"\tclean = {p('filter-named-a=b.clean')}\n"
            f"\tsmudge = {p('filter-named-a=b.smudge')}\n"
            '[filter "evilproc"]\n'
            f"\tprocess = {p('filter.process')}\n"
            '[diff "evil"]\n'
            f"\ttextconv = {p('diff.textconv')}\n"
            '[diff "evilcmd"]\n'
            f"\tcommand = {p('diff.command')}\n"
            "[diff]\n"
            f"\texternal = {p('diff.external')}\n"
            '[merge "evil"]\n'
            f"\tdriver = {p('merge.driver')}\n"
            '[merge "a=b"]\n'
            f"\tdriver = {p('merge-named-a=b.driver')}\n"
            '[merge "viareplace"]\n'
            f"\tdriver = {p('refs-replace')}\n"
            '[includeIf "onbranch:main"]\n'
            f"\tpath = {included['includeIf.onbranch'][0]}\n"
            f'[includeIf "gitdir:{repo}/"]\n'
            f"\tpath = {included['includeIf.gitdir'][0]}\n"
            "[include]\n"
            f"\tpath = {included['include.path'][0]}\n"
            f'[url "ext::{p("url.insteadOf")}"]\n'
            f"\tinsteadOf = {hostile.origin}\n"
            f'[url "ext::{p("url.pushInsteadOf")}"]\n'
            f"\tpushInsteadOf = {hostile.origin}\n"
            "[credential]\n"
            f"\thelper = !{p('credential.helper')}\n"
            "[gpg]\n"
            f"\tprogram = {p('gpg.program')}\n"
            '[gpg "ssh"]\n'
            f"\tprogram = {p('gpg.ssh.program')}\n"
            "[commit]\n"
            "\tgpgSign = true\n"
            "[tag]\n"
            "\tgpgSign = true\n"
            "[uploadpack]\n"
            f"\tpackObjectsHook = {p('uploadpack.packObjectsHook')}\n"
        )
        with (git_dir / "config").open("a", encoding="utf-8") as fh:
            fh.write(config)
        if redirect_worktree:
            self._arm_worktree_redirect(hostile)

    def _arm_replace_ref(self, repo: Path) -> None:
        """Replace the committed `.gitattributes` blob with one that also names `viareplace`,
        whose driver only a reader honouring `refs/replace/` can reach."""
        original = self.git(repo, "rev-parse", "HEAD:.gitattributes").strip()
        replacement = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-w", "--no-filters", "--stdin"],
            input=_ATTRIBUTES_BY_REPLACEMENT, check=True, capture_output=True,
            text=True).stdout.strip()
        self.git(repo, "update-ref", f"refs/replace/{original}", replacement)

    def _arm_worktree_redirect(self, hostile: HostileRepo) -> None:
        decoy = self.owned(self.root / f"{hostile.repo.name}-decoy")
        decoy.mkdir()
        program = self._program(hostile, "core.worktree")
        (decoy / ".gitattributes").write_text("* filter=redirected\n", encoding="utf-8")
        (decoy / "notes.txt").write_text("decoy\n", encoding="utf-8")
        with (hostile.repo / ".git" / "config").open("a", encoding="utf-8") as fh:
            fh.write(f"[core]\n\tworktree = {decoy}\n"
                     f'[filter "redirected"]\n\tclean = {program}\n\tsmudge = {program}\n')

    def _make_stat_dirty(self, repo: Path) -> None:
        """Rewrite every tracked driven file with the bytes it already has and a new mtime, so
        the index no longer vouches for it and a status has to read it through its filter."""
        for rel in _DRIVEN_FILES:
            path = repo / rel
            path.write_bytes(path.read_bytes())
            later = path.stat().st_mtime + 5
            os.utime(path, (later, later))

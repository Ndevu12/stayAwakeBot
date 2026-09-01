#!/usr/bin/env python3
"""One place a test gets a git repository, and a sandbox it cannot reach out of.

Tests here drive REAL git on purpose: every defect this suite exists to catch was git's own
behaviour, not our logic — `update-ref` moving a branch a linked worktree has checked out,
`ls-remote` tail-matching at a slash, `commit-tree` re-encoding a message from the locale,
`%G?` reporting `N` for a signature it simply cannot verify. A mock returns what the author
believed, and the belief was the defect each time.

What real git needs is a BOUNDARY, and three separate failures came from not having one: a test
globbed the system temp directory and pointed a branch-force-updating verb at every repository
in it; another answered "does this repository sign?" from the developer's own global config, so
the same code took a different path on a machine that does not sign; two more reached
`github.com` and waited out the network timeout instead of failing.

So a test gets isolation by DEFAULT and has to opt out of it, rather than remembering to ask.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class OutsideTheSandbox(AssertionError):
    """A helper was pointed at a path this test does not own."""


class GitSandbox(unittest.TestCase):
    """Base for a test that builds real repositories.

    Every repository lives under a directory this test owns, global and system git config are
    neutralised, cross-run state is redirected, and git is denied every network protocol — so a
    call that would have gone to a remote fails at once instead of after the network timeout.
    """

    PROTOCOLS = "file"

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="saw-sandbox-")).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        isolated = mock.patch.dict(os.environ, {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "XDG_STATE_HOME": str(self.root / "state"),
            "XDG_CACHE_HOME": str(self.root / "cache"),
            # A remote operation fails here rather than dialling out and waiting for the timeout.
            "GIT_ALLOW_PROTOCOL": self.PROTOCOLS,
            "GIT_TERMINAL_PROMPT": "0",
        })
        isolated.start()
        self.addCleanup(isolated.stop)

    # --- the boundary ---------------------------------------------------------------------

    def owned(self, path: Path | str) -> Path:
        """`path`, once it is established this test owns it. Raises otherwise.

        The check is on the RESOLVED path, so a symlink out of the sandbox is caught too.
        """
        resolved = Path(path).resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise OutsideTheSandbox(f"{resolved} is not under {self.root}")
        return resolved

    # --- building -------------------------------------------------------------------------

    def new_repo(self, name: str = "repo", **config: str) -> Path:
        """An empty repository on `main`. `config` keys use `__` for `.` (`user__name=...`)."""
        repo = self.owned(self.root / name)
        repo.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)],
                       check=True, capture_output=True)
        settings = {"user.email": "t@t.test", "user.name": "T", "commit.gpgsign": "false",
                    "tag.gpgsign": "false"}
        settings.update({k.replace("__", "."): v for k, v in config.items()})
        for key, value in settings.items():
            self.git(repo, "config", key, value)
        return repo

    def write(self, repo: Path, rel: str, text: str) -> None:
        path = self.owned(Path(repo) / rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, repo: Path, message: str) -> str:
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", message)
        return self.rev(repo)

    # --- asking ---------------------------------------------------------------------------

    def git(self, repo: Path, *args: str) -> str:
        """A git command that must succeed."""
        res = subprocess.run(["git", "-C", str(self.owned(repo)), *args],
                             check=True, capture_output=True, text=True)
        return res.stdout

    def git_may_fail(self, repo: Path, *args: str) -> subprocess.CompletedProcess:
        """A git command whose non-zero exit is part of the fixture — a conflicting merge, say."""
        return subprocess.run(["git", "-C", str(self.owned(repo)), *args],
                              capture_output=True, text=True)

    def rev(self, repo: Path, ref: str = "HEAD") -> str:
        return self.git(repo, "rev-parse", ref).strip()

    def raw_commit(self, repo: Path, rev: str) -> bytes:
        """The commit object's bytes, undecoded — a message in a legacy encoding does not survive
        being read as text, which is the thing several of these tests are about."""
        return subprocess.run(["git", "-C", str(self.owned(repo)), "cat-file", "commit", rev],
                              capture_output=True).stdout

    def raw_body(self, repo: Path, rev: str) -> bytes:
        return self.raw_commit(repo, rev).partition(b"\n\n")[2]

    def header(self, repo: Path, rev: str, name: str) -> bytes:
        prefix = name.encode() + b" "
        return next(ln for ln in self.raw_commit(repo, rev).split(b"\n") if ln.startswith(prefix))

    # --- shapes ---------------------------------------------------------------------------

    def evil_merge_repo(self, name: str = "evil") -> tuple[Path, str]:
        """`main` at a two-parent merge whose parents auto-merge CLEANLY, and whose recorded tree
        holds two things that auto-merge does not: `payload.js`, in neither parent, and a hand
        edit to `README.md` made while the merge was open. Only the first is a reason to replace
        it — that is what makes this the shape worth testing against."""
        repo = self.new_repo(name)
        self.write(repo, "README.md", "readme\n")
        self.write(repo, "app.js", "base\n")
        self.commit(repo, "init")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "side.js", "side\n")
        self.commit(repo, "side work")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "main.js", "main\n")
        self.commit(repo, "main work")
        self.git(repo, "merge", "--no-ff", "--no-commit", "-q", "side")
        self.write(repo, "payload.js", "PAYLOAD\n")
        self.write(repo, "README.md", "readme\nnote added while merging\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch 'side'")
        return repo, self.rev(repo)

    def ssh_signing_key(self) -> Path:
        key = self.owned(self.root / "keys") / "id_ed25519"
        key.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "saw-test",
                        "-f", str(key)], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL)
        return key

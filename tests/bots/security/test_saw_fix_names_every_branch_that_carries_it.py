#!/usr/bin/env python3
"""`saw fix` names every branch that still carries what it took out of the checkout, a branch fetched
from origin as well as a local one, as `saw fix amend` lists them, and names each branch once."""
from __future__ import annotations

import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security import remediator
from stayawake.bots.security.pr import held
from stayawake.bots.security.pr.fix_verdict import Remedy
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions

_PAYLOAD = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


def _identity(repo: Path) -> None:
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
        _git(repo, "config", key, value)


def _clone() -> Path:
    """Make a clone of a remote whose main and every branch carry the payload in `.gitignore`, with
    `feat-local` checked out once so it is a local branch too, `feat-remote-only` only on origin,
    and `cleaned` on origin without it. Returns the folder holding the remote and the clone."""
    top = Path(tempfile.mkdtemp(prefix="branches-"))
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(top / "origin.git")],
                   check=True, capture_output=True)
    seed = top / "seed"
    subprocess.run(["git", "init", "-q", "-b", "main", str(seed)], check=True, capture_output=True)
    _identity(seed)
    (seed / "README.md").write_text("# app\n")
    (seed / ".gitignore").write_text(_PAYLOAD)
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "with payload")
    for branch in ("feat-local", "feat-remote-only", "cleaned"):
        _git(seed, "switch", "-q", "-c", branch, "main")
        (seed / f"{branch}.txt").write_text(f"{branch}\n")
        if branch == "cleaned":
            (seed / ".gitignore").write_text("node_modules/\n")
        _git(seed, "add", "-A")
        _git(seed, "commit", "-qm", branch)
    _git(seed, "remote", "add", "origin", str(top / "origin.git"))
    _git(seed, "push", "-q", "origin", "main", "feat-local", "feat-remote-only", "cleaned")
    subprocess.run(["git", "clone", "-q", str(top / "origin.git"), str(top / "clone")], check=True,
                   capture_output=True)
    _identity(top / "clone")
    _git(top / "clone", "switch", "-q", "feat-local")
    _git(top / "clone", "switch", "-q", "main")
    return top


def _branch_holds(repo: Path) -> dict[str, Remedy]:
    history = held.history_holds(repo, [".gitignore"], "main", load_signatures(), [],
                                 ScanOptions())
    assert not history.unread, history.unread
    return {hold.name: hold.remedy for hold in history.holds if hold.where == "branch"}


class TestEveryBranchThatCarriesItIsNamed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.top = _clone()
        cls.named = _branch_holds(cls.top / "clone")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.top, True)

    def test_a_branch_only_on_origin_is_named_as_git_names_it(self):
        self.assertEqual(Remedy.AMEND, self.named.get("origin/feat-remote-only"))

    def test_a_local_branch_and_its_origin_copy_are_named_once(self):
        self.assertIn("feat-local", self.named)
        self.assertNotIn("origin/feat-local", self.named)

    def test_the_branch_checked_out_is_not_named_as_another_branch(self):
        self.assertNotIn("main", self.named)
        self.assertNotIn("origin/main", self.named)

    def test_a_branch_that_no_longer_carries_it_is_not_named(self):
        self.assertNotIn("origin/cleaned", self.named)
        self.assertEqual({"feat-local", "origin/feat-remote-only"}, set(self.named))


class TestABranchThatDiffersFromItsCopyOnOrigin(unittest.TestCase):
    def setUp(self):
        self.top = _clone()
        self.addCleanup(shutil.rmtree, self.top, True)

    def test_one_that_needs_amend_only_on_origin_is_named_with_amend(self):
        repo = self.top / "clone"
        _git(repo, "branch", "-f", "feat-local", "main")
        self.assertEqual(Remedy.AMEND, _branch_holds(repo).get("feat-local"))

    def test_one_that_needs_amend_only_here_is_named_with_amend(self):
        repo = self.top / "clone"
        _git(repo, "update-ref", "refs/remotes/origin/feat-local", "main")
        self.assertEqual(Remedy.AMEND, _branch_holds(repo).get("feat-local"))

    def test_one_cleaned_here_but_not_pushed_is_named_by_its_copy_on_origin(self):
        repo = self.top / "clone"
        _git(repo, "switch", "-q", "feat-local")
        (repo / ".gitignore").write_text("node_modules/\n")
        _git(repo, "commit", "-qam", "cleaned here")
        _git(repo, "switch", "-q", "main")
        named = _branch_holds(repo)
        self.assertIn("origin/feat-local", named)
        self.assertNotIn("feat-local", named)


class TestSawFixSaysSo(unittest.TestCase):
    def test_saw_fix_names_the_branch_only_on_origin_and_what_removes_it(self):
        top = _clone()
        self.addCleanup(shutil.rmtree, top, True)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            remediator.fix(None, paths=[str(top / "clone")], no_stream=True)
        text = out.getvalue() + err.getvalue()
        self.assertIn("branch 'origin/feat-remote-only' carries it — saw fix amend removes it", text)
        self.assertIn("branch 'feat-local' carries it — saw fix amend removes it", text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""`saw scan --history` reads what a repository keeps in every stash entry and in each of its
checkouts, as `saw fix amend` does when it checks what still holds a payload: an older stash entry,
another checkout's own refs and its ORIG_HEAD. When it cannot list them, the history reads as read
in part, never as clean."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import stayawake.lib.git.history_tips as tipsmod
from stayawake.bots.security.scanner import history_residue_note
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions

_PAYLOAD = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"
_FOUND = "1 file(s) are still stored with the payload in this repository's history: .gitignore."


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


class _Repo(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="history-tips-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q", "-b", "main")
        for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false"),
                           ("core.hooksPath", "/dev/null")):
            _git(self.repo, "config", key, value)
        (self.repo / "README.md").write_text("one\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "init")

    def _checkout(self) -> Path:
        other = self.root / "other"
        _git(self.repo, "worktree", "add", "-q", str(other), "-b", "side")
        return other

    def _note(self) -> str:
        return history_residue_note(self.repo, ScanOptions(), load_signatures(), [])


class TestAPayloadKeptOnlyOutsideTheRefsIsReported(_Repo):
    def test_a_payload_in_an_older_stash_entry_is_reported(self):
        (self.repo / ".gitignore").write_text(_PAYLOAD)
        _git(self.repo, "stash", "push", "-qu", "-m", "payload")
        (self.repo / "README.md").write_text("two\n")
        _git(self.repo, "stash", "push", "-q", "-m", "clean")
        self.assertIn(_FOUND, self._note())

    def test_a_payload_only_another_checkouts_own_ref_keeps_is_reported(self):
        other = self._checkout()
        _git(other, "checkout", "-q", "--detach")
        (other / ".gitignore").write_text(_PAYLOAD)
        _git(other, "add", "-A")
        _git(other, "commit", "-qm", "payload")
        _git(other, "update-ref", "refs/bisect/bad", "HEAD")
        _git(other, "checkout", "-q", "side")
        self.assertIn(_FOUND, self._note())

    def test_a_payload_another_checkouts_own_ref_keeps_through_an_annotated_tag_is_reported(self):
        other = self._checkout()
        _git(other, "checkout", "-q", "--detach")
        (other / ".gitignore").write_text(_PAYLOAD)
        _git(other, "add", "-A")
        _git(other, "commit", "-qm", "payload")
        (other / ".gitignore").unlink()
        _git(other, "commit", "-qam", "cleaned")
        _git(other, "tag", "-a", "-m", "kept", "kept")
        _git(other, "update-ref", "refs/bisect/bad", _git(other, "rev-parse", "refs/tags/kept").strip())
        _git(other, "tag", "-d", "kept")
        _git(other, "checkout", "-q", "side")
        self.assertIn(_FOUND, self._note())

    def test_a_payload_only_another_checkouts_orig_head_keeps_is_reported(self):
        other = self._checkout()
        (other / ".gitignore").write_text(_PAYLOAD)
        _git(other, "add", "-A")
        _git(other, "commit", "-qm", "payload")
        _git(other, "reset", "-q", "--hard", "HEAD~1")
        self.assertIn(_FOUND, self._note())


class TestCleanStashesAndCheckoutsReadClean(_Repo):
    def test_history_kept_by_stashes_and_another_checkout_with_nothing_in_it_reads_clean(self):
        other = self._checkout()
        (other / "app.js").write_text("export const a = 1;\n")
        _git(other, "add", "-A")
        _git(other, "commit", "-qm", "work")
        _git(other, "update-ref", "refs/bisect/good", "HEAD")
        for n in range(2):
            (self.repo / "README.md").write_text(f"draft {n}\n")
            _git(self.repo, "stash", "push", "-q", "-m", f"draft {n}")
        self.assertTrue(self._note().startswith("History was read: no confirmed payload"), self._note())


class TestWhatCannotBeListedLeavesTheHistoryUnknown(_Repo):
    def _failing(self, failed_when):
        real = tipsmod.answer

        def answer(repo, args, **kw):
            return None if failed_when(args) else real(repo, args, **kw)
        return mock.patch.object(tipsmod, "answer", answer)

    def test_stash_entries_git_could_not_list_leave_the_history_read_in_part(self):
        (self.repo / "README.md").write_text("draft\n")
        _git(self.repo, "stash", "push", "-q", "-m", "draft")
        with self._failing(lambda args: args[:2] == ["rev-list", "-g"]):
            note = self._note()
        self.assertTrue(note.startswith("History was read in part"), note)
        self.assertIn("UNKNOWN, not no", note)

    def test_checkouts_git_could_not_list_leave_the_history_read_in_part(self):
        self._checkout()
        with self._failing(lambda args: args[:1] == ["worktree"]):
            note = self._note()
        self.assertTrue(note.startswith("History was read in part"), note)


if __name__ == "__main__":
    unittest.main()

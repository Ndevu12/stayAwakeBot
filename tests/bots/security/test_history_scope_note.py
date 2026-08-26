#!/usr/bin/env python3
"""A scan of the working tree says which entry points it did not look at.

Earlier commits, other branches and tags are all one command away from being on disk, and a fix is
a forward commit on one branch — so a repository can be correctly remediated and still serve the old
contents from a tag.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import _history_scope_note


def _repo(commits: int, *, branches: int = 0, tags: int = 0) -> Path:
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "-C", str(d), "init", "-q"], capture_output=True)
    for i in range(commits):
        (d / "f.txt").write_text(str(i))
        subprocess.run(["git", "-C", str(d), "add", "-A"], capture_output=True)
        subprocess.run(["git", "-C", str(d), "-c", "user.email=t@t", "-c", "user.name=t",
                        "commit", "-q", "-m", f"c{i}"], capture_output=True)
    for b in range(branches):
        subprocess.run(["git", "-C", str(d), "branch", f"b{b}"], capture_output=True)
    for t in range(tags):
        subprocess.run(["git", "-C", str(d), "tag", f"v{t}"], capture_output=True)
    return d


class HistoryScopeNote(unittest.TestCase):
    def _repo(self, n, **kw):
        d = _repo(n, **kw)
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_a_repository_with_earlier_commits_says_they_were_not_examined(self):
        note = _history_scope_note(self._repo(3))
        self.assertIsNotNone(note)
        self.assertIn("2 earlier commits", note)
        # The reader must learn it can come BACK, not merely be read: one command puts it on disk.
        self.assertIn("on disk", note)
        self.assertIn("one command", note.lower())

    def test_one_earlier_commit_reads_as_singular(self):
        self.assertIn("1 earlier commit not examined", _history_scope_note(self._repo(2)))

    def test_a_single_commit_repository_with_no_other_refs_gets_no_note(self):
        self.assertIsNone(_history_scope_note(self._repo(1)))

    def test_tags_are_disclosed_even_when_there_is_no_earlier_commit(self):
        # A tag is a published entry point: `clone --branch` is one command, and no remediation of
        # a branch ever moves it.
        note = _history_scope_note(self._repo(1, tags=3))
        self.assertIsNotNone(note)
        self.assertIn("3 tags", note)

    def test_other_branches_are_disclosed(self):
        note = _history_scope_note(self._repo(2, branches=2))
        self.assertIn("2 other branches", note)

    def test_the_checked_out_branch_is_not_counted_as_unexamined(self):
        note = _history_scope_note(self._repo(2))
        self.assertNotIn("other branch", note)

    def test_all_three_axes_appear_together(self):
        note = _history_scope_note(self._repo(3, branches=1, tags=2))
        for part in ("2 earlier commits", "1 other branch", "2 tags"):
            with self.subTest(part=part):
                self.assertIn(part, note)

    def test_an_empty_repository_gets_no_note(self):
        self.assertIsNone(_history_scope_note(self._repo(0)))

    def test_a_plain_directory_gets_no_note(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        self.assertIsNone(_history_scope_note(d))

    def test_an_unreadable_target_is_silent_rather_than_raising(self):
        self.assertIsNone(_history_scope_note(Path("/nonexistent-9f3a")))


class ItDoesNotGate(unittest.TestCase):
    def test_the_note_is_a_coverage_note_not_a_finding(self):
        # Residue is not execution: nothing runs it on clone or build, so it must not move the
        # exit code and turn every remediated repository red.
        from stayawake.bots.security.models import ScanResult
        r = ScanResult(target="t", source="local", findings=[], notes=[])
        r.notes.append(_history_scope_note(_repo(2)) or "")
        self.assertFalse(r.infected)
        self.assertFalse(r.suspicious)


if __name__ == "__main__":
    unittest.main()

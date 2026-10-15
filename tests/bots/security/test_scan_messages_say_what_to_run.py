#!/usr/bin/env python3
"""What a scan says about what it covered states the user's condition and the command that acts on it."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import scanner
from stayawake.bots.security.service import workers
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions, Target

_ENV = dict(os.environ, SAW_HOOK_DISABLED="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
_MARKERS = "temp_auto_push.bat\nbranch_structure.json\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
                   cwd=repo, env=_ENV, check=True, capture_output=True, stdin=subprocess.DEVNULL)


def _repo(*versions: tuple[str, str]) -> Path:
    """A repository with one commit per (file, content) pair."""
    repo = Path(tempfile.mkdtemp())
    _git(repo, "init", "-q")
    for name, content in versions:
        (repo / name).write_text(content, encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"change {name}")
    return repo


def _stored(repo: Path) -> str:
    return scanner.history_residue_note(repo, ScanOptions(history=True), load_signatures(), [])


class TestTheHistoryNoteSaysWhatItRead(unittest.TestCase):
    def test_a_history_read_in_full_says_so(self):
        note = _stored(_repo(("a.js", "one\n"), ("a.js", "two\n"), ("a.js", "three\n")))
        self.assertTrue(note.startswith("History was read: no confirmed payload"), note)

    def test_a_stored_payload_names_the_command_that_takes_it_out(self):
        repo = _repo((".gitignore", _MARKERS), (".gitignore", "node_modules/\n"))
        note = _stored(repo)
        self.assertIn("still stored with the payload in this repository's history", note)
        self.assertIn("Run `saw fix amend` to take them out.", note)
        self.assertNotIn("reachable from a ref", note)


class TestTheScopeNoteNamesTheCommand(unittest.TestCase):
    def test_a_working_tree_scan_names_what_history_holds_and_how_to_check_it(self):
        repo = _repo(("a.js", "one\n"), ("a.js", "two\n"))
        note = scanner._history_scope_note(repo)
        self.assertTrue(note.startswith(scanner._CHECKED_OUT_ONLY), note)
        self.assertIn("not the 1 earlier commit", note)
        self.assertIn("Run `saw scan --history` to check those too.", note)


class TestWhatAScanLeavesOutNamesNoPlace(unittest.TestCase):
    def test_a_folder_left_out_is_said_without_its_name(self):
        note = workers.pruning_note({"node_modules", "dist"})
        self.assertEqual(note, "Folders the `exclude_dirs` setting leaves out were not scanned.")

    def test_a_link_to_a_sensitive_file_keeps_its_content_out_of_the_report(self):
        folder = Path(tempfile.mkdtemp())
        link = folder / "keys.js"
        link.symlink_to(Path.home() / ".ssh" / "saw-test-not-a-real-key")
        target = Target(folder, str(folder), ScanOptions())
        self.assertTrue(target._redirects_into_a_sink(link))
        self.assertEqual(target.coverage_notes, [
            "`keys.js` points at a sensitive file outside this folder, so its content was not read "
            "into this report."])


class TestTheScanHelpNamesNoExitCode(unittest.TestCase):
    def test_the_help_says_verdict_not_exit_code(self):
        from stayawake.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            main(["scan", "--help"])
        self.assertNotIn("exit code", out.getvalue())
        self.assertIn("verdict", out.getvalue())


if __name__ == "__main__":
    unittest.main()

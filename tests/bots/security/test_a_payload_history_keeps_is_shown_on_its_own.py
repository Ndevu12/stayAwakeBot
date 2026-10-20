#!/usr/bin/env python3
"""A payload the repository's history still stores is shown under its own heading, apart from the
notes on what a scan covered, in the terminal and in the Markdown report; `--json` keeps it in the
notes and names it on its own too. The verdict is what the files checked out give, as before. A
read that stops at the versions it reads of each path says how many it left and that their state
is unknown."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import ScanResult
from stayawake.bots.security.scanner import attach_history_note, history_reading
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.sinks.render import render_markdown, render_terminal
from stayawake.bots.security.targets import ScanOptions

_PAYLOAD = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"
_STORED = "1 file(s) are still stored with the payload in this repository's history: .gitignore."


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(versions_of_app: int = 0) -> Path:
    """Make a repository whose payload is only in its first commit. Takes how many versions of a
    second path to commit after it. Returns its root."""
    repo = Path(tempfile.mkdtemp(prefix="stored-"))
    _git(repo, "init", "-q", "-b", "main")
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
        _git(repo, "config", key, value)
    (repo / ".gitignore").write_text(_PAYLOAD)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "with payload")
    (repo / ".gitignore").write_text("node_modules/\n")
    _git(repo, "commit", "-qam", "clean")
    for n in range(versions_of_app):
        (repo / "app.js").write_text(f"export const v = {n};\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", f"v{n}")
    return repo


def _scanned(repo: Path) -> ScanResult:
    result = ScanResult(target=str(repo), source="local")
    attach_history_note(result, str(repo), ScanOptions(history=True), load_signatures(), [])
    return result


def _payload(*results: ScanResult) -> dict:
    return {"summary": {"targets": len(results), "infected": 0, "suspicious": 0, "residue": 0,
                        "findings": 0, "critical": 0, "high": 0, "advisories": 0},
            "results": [r.to_dict() for r in results], "any_error": False, "generated_at": "t"}


class TestAPayloadHistoryKeepsHasItsOwnHeading(unittest.TestCase):
    def setUp(self):
        self.repo = _repo()
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.result = _scanned(self.repo)

    def test_the_terminal_shows_it_under_its_own_heading_and_not_among_the_notes(self):
        text = render_terminal(_payload(self.result))
        stored = text.index("Stored in history:")
        self.assertIn(_STORED, text[stored:])
        self.assertNotIn("Notes:", text)

    def test_the_markdown_report_shows_it_under_its_own_heading(self):
        text = render_markdown(_payload(self.result))
        self.assertIn("## Stored in history", text)
        self.assertNotIn("## Notes", text)

    def test_json_keeps_it_among_the_notes_and_names_it_on_its_own(self):
        out = self.result.to_dict()
        self.assertTrue(any(n.startswith(_STORED) for n in out["notes"]))
        self.assertTrue(out["stored_payload"].startswith(_STORED))

    def test_the_verdict_is_what_the_files_checked_out_give(self):
        self.assertEqual(self.result.verdict, "clean")

    def test_with_several_targets_each_line_names_its_target(self):
        clean = ScanResult(target="elsewhere", source="local")
        text = render_terminal(_payload(self.result, clean))
        self.assertIn(f"{self.repo} — {_STORED}", text)


class TestAHistoryWithNothingStoredHasNoSuchHeading(unittest.TestCase):
    def test_a_clean_history_reads_among_the_notes(self):
        repo = Path(tempfile.mkdtemp(prefix="stored-clean-"))
        self.addCleanup(shutil.rmtree, repo, True)
        _git(repo, "init", "-q", "-b", "main")
        for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false")):
            _git(repo, "config", key, value)
        (repo / "README.md").write_text("one\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "one")
        result = _scanned(repo)
        self.assertIsNone(result.stored_payload)
        text = render_terminal(_payload(result))
        self.assertNotIn("Stored in history:", text)
        self.assertIn("History was read", text[text.index("Notes:"):])


class TestAReadStoppedAtItsBoundSaysWhatItLeft(unittest.TestCase):
    def test_the_versions_past_the_bound_are_counted_and_called_unknown(self):
        repo = _repo(versions_of_app=23)
        self.addCleanup(shutil.rmtree, repo, True)
        reading = history_reading(repo, ScanOptions(history=True), load_signatures(), [])
        self.assertTrue(reading.found_payload)
        self.assertIn("3 earlier version(s) of 1 path(s) are past the 20 versions of each path it "
                      "reads, so whether they hold a payload is UNKNOWN, not no.", reading.text)


if __name__ == "__main__":
    unittest.main()

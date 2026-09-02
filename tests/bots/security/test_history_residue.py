#!/usr/bin/env python3
"""A payload the repository still stores is reported, and never moves the verdict.

`saw fix` adds a removal commit — it must not rewrite history — so the payload stays reachable and
one command puts it back. Reporting it is the point; gating on it would turn every correctly
remediated repository red and cost the exit code its meaning.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from support.gitrepo import GitSandbox                                   # noqa: E402
from stayawake.bots.security import scanner                             # noqa: E402
from stayawake.bots.security.models import CLEAN, CONFIRMED             # noqa: E402
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions          # noqa: E402
from stayawake.bots.security.targets.history import (HistoryTarget,               # noqa: E402
                                                     versions_by_path)


def _payload() -> str:
    """A CONFIRMED loader shape, split so this file carries no contiguous indicator."""
    cc = "from" + "CharCode"
    run = "ev" + "al"
    return f"const x = String.{cc}(127) + String.{cc}(127); {run}(x);\n"


class TestWhatHistoryStillCarries(GitSandbox):
    def _remediated(self):
        """The shape `saw fix` leaves: the payload lands, a removal commit cleans the tip."""
        repo = self.new_repo()
        self.write(repo, "index.js", "module.exports = 1;\n")
        self.commit(repo, "first")
        self.write(repo, "loader.js", _payload())
        self.commit(repo, "payload lands")
        (repo / "loader.js").unlink()
        self.commit(repo, "removal commit")
        return repo

    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def test_the_tree_really_is_clean(self):
        repo = self._remediated()
        result = scanner.scan_target(LocalRepoTarget(repo, str(repo), ScanOptions()),
                                     self._sigs(), [])
        self.assertEqual(result.verdict, CLEAN)

    def test_the_payload_is_still_stored_and_is_reported(self):
        repo = self._remediated()
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("still STORE a confirmed payload", note)
        self.assertIn("loader.js", note)

    def test_reporting_it_does_not_move_the_verdict(self):
        """The whole contract. A repository that was correctly remediated must not start failing:
        nothing stored in history runs on clone or on build."""
        repo = self._remediated()
        opts = ScanOptions(history=True)
        tree = scanner.scan_target(LocalRepoTarget(repo, str(repo), opts), self._sigs(), [])
        note = scanner.history_residue_note(repo, opts, self._sigs(), [])
        self.assertIn("loader.js", note, "it really did find one")
        self.assertEqual(tree.verdict, CLEAN, "and the verdict is untouched")
        self.assertEqual(tree.findings, [], "it is a note, never a finding")

    def test_a_repository_with_nothing_stored_says_so_rather_than_nothing(self):
        """Silence would read as 'not looked at'. The run said it read history, so it says what
        that established."""
        repo = self.new_repo()
        self.write(repo, "index.js", "module.exports = 1;\n")
        self.commit(repo, "only commit")
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("History was read", note)
        self.assertNotIn("still STORE", note)

    def test_a_stored_version_can_be_fetched_by_the_name_reported(self):
        """The path is the real one — an identity encoded into it defeats every allowlist glob and
        every extension match. The sha is asked for separately."""
        repo = self._remediated()
        versions, _ = versions_by_path(repo)
        target = HistoryTarget(repo, str(repo), ScanOptions(), versions)
        self.assertIn("loader.js", list(target.iter_files()), "the REAL path, so globs still match")
        self.assertEqual(target.read_bytes("loader.js").decode(), _payload())
        self.assertEqual(self.git(repo, "cat-file", "blob", target.sha_for("loader.js")), _payload())


if __name__ == "__main__":
    unittest.main()

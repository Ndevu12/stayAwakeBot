#!/usr/bin/env python3
"""A payload the repository still stores is reported, and never moves the verdict.

`saw fix` adds a removal commit — it must not rewrite history — so the payload stays reachable and
one command puts it back. Reporting it is the point; gating on it would turn every correctly
remediated repository red and cost the exit code its meaning.
"""
from __future__ import annotations

import sys
import unittest
from unittest import mock
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


class TestManyStoredVersionsOfOnePath(GitSandbox):
    def _sigs(self):
        from stayawake.bots.security.signatures import load_signatures
        return load_signatures()

    def _churned(self, versions: int, payload_at: int | None = None):
        repo = self.new_repo()
        for n in range(versions):
            body = _payload() if n == payload_at else f"// version {n}\n"
            self.write(repo, "churn.js", body)
            self.commit(repo, f"v{n}")
        self.write(repo, "churn.js", "// clean tip\n")
        self.commit(repo, "clean tip")
        return repo

    def test_a_payload_in_a_later_version_is_still_found(self):
        """One round per path would read only the newest stored version, so a payload three
        rewrites back would be missed while the run reported it had read history."""
        repo = self._churned(4, payload_at=1)
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("churn.js", note)

    def test_what_the_bound_cut_is_counted(self):
        """A bound that is not reported reads as coverage of what it cut."""
        repo = self._churned(6)
        with mock.patch.object(scanner, "_HISTORY_ROUNDS", 2):
            note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertIn("were not read", note)
        self.assertIn("path(s)", note)

    def test_a_heuristic_shape_in_history_is_not_called_confirmed(self):
        """Confirmed only. A shape benign code shares, in a five-year-old commit, is a line the
        operator dismisses on every scan."""
        import base64
        import os as _os
        blob = base64.b64encode(_os.urandom(3000)).decode()
        repo = self.new_repo()
        self.write(repo, "min.js", f"var d='{blob}';\n")     # heuristic only: no confirmed signature
        self.commit(repo, "a minified-looking file")
        self.write(repo, "min.js", "// replaced\n")
        self.commit(repo, "replace it")
        versions, _ = versions_by_path(repo)
        found = []
        for index in range(3):
            target = HistoryTarget(repo, str(repo), ScanOptions(), versions, index)
            if not len(target):
                break
            found += scanner.scan_target(target, self._sigs(), []).findings
        self.assertTrue([f for f in found if f.confidence != CONFIRMED],
                        "the fixture must actually produce a heuristic finding")
        self.assertFalse([f for f in found if f.confidence == CONFIRMED])
        note = scanner.history_residue_note(repo, ScanOptions(history=True), self._sigs(), [])
        self.assertNotIn("still STORE a confirmed payload", note)


class TestItAnswersTheSameWayTheTreeScanDoes(GitSandbox):
    def test_a_directory_the_tree_scan_skips_is_skipped_here_too(self):
        """A project that once committed `node_modules` carries thousands of vendored files the
        tree side deliberately never reads. Reading their stored versions would answer differently
        about the same repository."""
        repo = self.new_repo()
        self.write(repo, "node_modules/left-pad/index.js", "module.exports = 1;\n")
        self.write(repo, "dist/bundle.js", "built\n")
        self.write(repo, "app.js", "hello\n")
        self.commit(repo, "committed a vendored tree")
        import shutil
        shutil.rmtree(repo / "node_modules")
        shutil.rmtree(repo / "dist")
        self.commit(repo, "stop shipping the vendored tree")
        opts = ScanOptions()
        versions, _ = versions_by_path(repo)
        history = sorted(HistoryTarget(repo, str(repo), opts, versions).iter_files())
        tree = sorted(LocalRepoTarget(repo, str(repo), opts).iter_files())
        self.assertEqual(history, tree, "the two axes disagreed about the same repository")


class TestARemoteTargetIsRefusedRatherThanHalfAnswered(unittest.TestCase):
    def test_history_with_remote_says_why_instead_of_doing_nothing(self):
        """A remote target is fetched shallow, so its history is not there. Doing nothing silently
        is the failure this whole feature exists to fix."""
        import io, contextlib
        from stayawake.cli import main
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = main(["scan", "--history", "--remote", "owner/name"])
        self.assertNotEqual(rc, 0)
        self.assertIn("shallow", err.getvalue())


if __name__ == "__main__":
    unittest.main()

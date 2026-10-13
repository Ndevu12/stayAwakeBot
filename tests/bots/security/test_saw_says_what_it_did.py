#!/usr/bin/env python3
"""Each line saw prints after a scan, a fix or a guard run states what it really did."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import host_note, remediator, resolution, scanner
from stayawake.bots.security.guard import sweep

_CONFIG = {"settings": {}, "targets": {}, "allowlist": []}
_SCOPE = "Only the working tree was scanned; 3 earlier commits not examined."


def _never(*args, **kwargs):
    raise AssertionError("a credential or the network was reached before the folder was checked")


_READ = "History holds nothing this scan reports."


def _scan(*, history: bool, reads_history: bool):
    """Finish a scan of a repository, asked for its history or not, that reads history or not."""
    opts = mock.Mock(history=history)
    with mock.patch.object(scanner, "_history_scope_note", return_value=_SCOPE), \
            mock.patch.object(scanner, "history_residue_note", return_value=_READ):
        result = scanner.finalize("repo", "local", {}, [], [], [], opts, "/repo", [], [],
                                  is_repo=True)
        if reads_history:
            scanner.attach_history_note(result, "/repo", opts, [], [])
    return result


class TestAScanOfHistoryDoesNotSayItSkippedHistory(unittest.TestCase):
    def test_a_scan_that_read_history_never_says_only_the_working_tree_was_scanned(self):
        notes = _scan(history=True, reads_history=True).notes
        self.assertNotIn(_SCOPE, notes)
        self.assertIn(_READ, notes)

    def test_the_working_tree_note_stays_until_history_is_read(self):
        self.assertIn(_SCOPE, _scan(history=True, reads_history=False).notes)

    def test_a_scan_of_the_working_tree_still_says_what_it_did_not_examine(self):
        self.assertIn(_SCOPE, _scan(history=False, reads_history=True).notes)

    def test_the_line_it_removes_is_the_one_it_adds(self):
        self.assertTrue(_SCOPE.startswith(scanner._WORKING_TREE_ONLY))


class TestTheHostNoteSaysWhereYouStand(unittest.TestCase):
    def _notes(self):
        return [host_note.scan_host_note(infected=True, local_loaders=["~/work/app"]),
                host_note.scan_host_note(infected=True),
                host_note.scan_host_note(infected=False),
                host_note.fix_host_note()]

    def test_every_note_says_to_run_saw_audit_before_changing_a_password(self):
        for note in self._notes()[1:]:
            self.assertIn("Before you change any password or token, run `saw audit`", note)
        self.assertIn("Run `saw audit` now", self._notes()[0])

    def test_every_note_says_why_saw_audit_comes_first(self):
        for note in self._notes():
            self.assertIn("can set off code that deletes your files", note)

    def test_no_note_hands_down_a_verdict_on_this_machine(self):
        for note in self._notes():
            for word in ("compromised", "all-clear"):
                self.assertNotIn(word, note)

    def test_no_note_uses_incident_vocabulary(self):
        for note in self._notes():
            for word in ("daemon", "wiper", "persistence", "arm"):
                self.assertNotIn(word, note.lower().replace("harm", ""))

    def test_code_in_a_folder_here_names_the_folder_and_what_not_to_do(self):
        note = self._notes()[0]
        self.assertIn("~/work/app", note)
        self.assertIn("it may already have run", note)
        self.assertIn("Do not open, install or build that folder until it is cleaned",
                      note)


class TestNoRepositoryIsSaidWhereItWasLooked(unittest.TestCase):
    def test_it_names_the_folder_what_did_not_happen_and_the_command(self):
        line = resolution.no_repository_in([os.path.expanduser("~/lab/work")],
                                           so_nothing_was="changed", name_one="saw fix")
        self.assertEqual(line, "No git repository in ~/lab/work, so nothing was changed. "
                               "Run it inside a repository, or name one: `saw fix <folder>`.")


class TestAFolderThatIsNotARepository(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="not-a-repo-")
        self.addCleanup(shutil.rmtree, self.folder, True)

    def _said(self, call):
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(remediator, "_resolve_config", return_value=_CONFIG), \
                mock.patch.object(remediator, "load_signatures", return_value={}), \
                mock.patch.object(sweep, "_guard_config", return_value=_CONFIG), \
                mock.patch.object(remediator.auth, "resolve_token", _never), \
                mock.patch.object(sweep.auth, "resolve_token", _never), \
                mock.patch.object(sweep, "resolve_pin", _never), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = call()
        return code, " ".join((err.getvalue() + out.getvalue()).split())

    def _expect(self, said, command, done):
        self.assertIn(f"No git repository in {self.folder}", said)
        self.assertIn(f"so nothing was {done}", said)
        self.assertIn(f"`{command} <folder>`", said)
        self.assertNotIn("Host note", said, "it spoke about a machine it never looked at")

    def test_fix_says_so_and_changes_nothing(self):
        _code, said = self._said(lambda: remediator.fix(paths=[self.folder], no_stream=True))
        self._expect(said, "saw fix", "changed")

    def test_fix_with_a_pull_request_says_so_before_it_asks_for_a_credential(self):
        _code, said = self._said(lambda: remediator.fix(paths=[self.folder], pr=True,
                                                        no_stream=True))
        self._expect(said, "saw fix", "changed")

    def test_amend_says_so_before_it_asks_for_a_credential(self):
        code, said = self._said(lambda: remediator.amend(paths=[self.folder], no_stream=True))
        self._expect(said, "saw fix amend", "changed")
        self.assertNotEqual(code, 0, "an amend that examined nothing reported success")

    def test_guard_check_says_so(self):
        _code, said = self._said(lambda: sweep.check_targets(paths=[self.folder], no_stream=True))
        self._expect(said, "saw guard check", "checked")

    def test_guard_drift_says_so(self):
        _code, said = self._said(lambda: sweep.drift_targets(paths=[self.folder], no_stream=True))
        self._expect(said, "saw guard drift", "checked")

    def test_guard_setup_says_so_before_it_reaches_the_network(self):
        _code, said = self._said(lambda: sweep.setup_targets(paths=[self.folder], no_stream=True))
        self._expect(said, "saw guard setup", "changed")


if __name__ == "__main__":
    unittest.main()

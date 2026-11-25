#!/usr/bin/env python3
"""An update is checked in the form of the bytes it writes into the folder, apply writes only those
bytes, and nothing the command would run runs while it is checked."""
from __future__ import annotations

import json
import os
import unicodedata
from unittest import mock

from stayawake.bots.security import govern
from stayawake.bots.security.models import HEURISTIC, Finding, Severity
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support.long_paths import stage_blob

_MARKER = b"SAWHIDDENMARKERx"
_SPELLS_THE_MARKER_IN_UTF7 = "".join(chr(unit) for unit in (0x4805, 0x8720, 0x30C4, 0x34C0, 0x1128, 0x4471))


def _flagging_the_marker(real):
    """Wrap a scan to grade a file holding the marker suspicious. Takes the real scan. Returns the
    wrapped scan."""
    def scan(files, paths, policy):
        result = real(files, paths, policy)
        for rel in paths:
            target = files / rel
            if target.is_file() and _MARKER in target.read_bytes():
                result.findings.append(Finding("marker", "test", Severity.HIGH, rel, "a marker",
                                               confidence=HEURISTIC))
        return result
    return scan


class AnUpdateIsCheckedAsItIsWritten(_TrackingCheckout):

    def _prepare(self, *command: str) -> tuple[dict, int]:
        self.git(self.open, "fetch", "-q")
        return govern.prepare(str(self.open), str(self.into), "git", list(command) or ["merge", "origin/main"])

    def _state(self) -> dict:
        return json.loads((self.into / "state.json").read_text(encoding="utf-8"))

    def test_what_an_arriving_encoding_writes_is_what_is_scanned(self):
        stage_blob(self.upstream, ".gitattributes", "*.js working-tree-encoding=UTF-7\n")
        stage_blob(self.upstream, "run.js", f"x {_SPELLS_THE_MARKER_IN_UTF7}\n")
        self.git(self.upstream, "commit", "-qm", "encoded")
        with mock.patch.object(govern, "_scan_files", side_effect=_flagging_the_marker(govern._scan_files)):
            answer, _code = self._prepare()
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "suspicious", answer)
        self.assertFalse(self._state()["releasable"])
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertFalse((self.open / "run.js").exists())

    def test_the_folder_gets_the_bytes_the_check_read(self):
        self.write(self.upstream, ".gitattributes", "*.txt eol=crlf\n")
        self.write(self.upstream, "lines.txt", "one\ntwo\n")
        self.commit(self.upstream, "line endings")
        answer, code = self._prepare()
        self.assertEqual(code, exitcodes.CLEAN, answer)
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertTrue(applied["applied"], applied)
        self.assertEqual((self.open / "lines.txt").read_bytes(), b"one\r\ntwo\r\n")

    def test_a_file_stored_under_a_decomposed_name_lands_and_is_checked(self):
        name = unicodedata.normalize("NFD", "café.js")
        stage_blob(self.upstream, name, "module.exports = 1;\n")
        self.git(self.upstream, "commit", "-qm", "decomposed name")
        before = self.rev(self.open)
        self._prepare()
        state = self._state()
        self.assertIn(name, state["written"])
        state["written"][name] = "0" * 64
        (self.into / "state.json").write_text(json.dumps(state), encoding="utf-8")
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertEqual(self.rev(self.open), before)
        answer, code = self._prepare()
        self.assertEqual(code, exitcodes.CLEAN, answer)
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertTrue(applied["applied"], applied)
        self.assertIn(os.fsencode(name), self.git(self.open, "ls-files", "-z").encode().split(b"\0"))

    def test_a_file_that_differs_from_what_was_checked_is_not_left_in_the_folder(self):
        before = self.rev(self.open)
        answer, code = self._prepare()
        self.assertEqual(code, exitcodes.CLEAN, answer)
        state = self._state()
        state["written"]["new.txt"] = "0" * 64
        (self.into / "state.json").write_text(json.dumps(state), encoding="utf-8")
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertFalse(applied["applied"], applied)
        self.assertEqual(self.rev(self.open), before)
        self.assertFalse((self.open / "new.txt").exists())
        self.assertEqual(self.git(self.open, "status", "--porcelain"), "")


class NothingRunsWhileAnUpdateIsChecked(_TrackingCheckout):

    def test_a_command_that_runs_other_commands_is_left_to_you(self):
        self.write(self.open, "local.txt", "local\n")
        self.commit(self.open, "local work")
        self.git(self.open, "fetch", "-q")
        sentinel = self.root / "ran"
        for command in (["rebase", "-x", f"touch {sentinel}", "origin/main"],
                        ["rebase", f"--exe=touch {sentinel}", "origin/main"],
                        ["rebase", "-ix", f"touch {sentinel}", "origin/main"],
                        ["merge", "-s", "made-up", "origin/main"],
                        ["pull", f"--upload-pack=touch {sentinel}"]):
            with self.subTest(command=command):
                answer, code = govern.prepare(str(self.open), str(self.into), "git", command)
                self.assertEqual(code, exitcodes.INCOMPLETE)
                self.assertEqual(answer["reason"], "a command that runs other commands cannot be checked")
                self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
                self.assertFalse(sentinel.exists(), "a command ran while the update was checked")


if __name__ == "__main__":
    import unittest
    unittest.main()

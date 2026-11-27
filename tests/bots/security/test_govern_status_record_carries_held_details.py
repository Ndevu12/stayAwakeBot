#!/usr/bin/env python3
"""The govern status record of a held update carries what the terminal shows: the findings, the
command and the folder it ran in, the next steps, and whether `saw govern let-in` reviews it. An
update that is not held carries none of them."""
from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.bots.security import govern, govern_held, govern_status
from tests.support import samples
from tests.support.gitrepo import GitSandbox

_HELD_DETAILS = ("findings", "command", "next_steps", "let_in")


class HeldDetailsInTheStatusRecord(GitSandbox):
    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        state = mock.patch.dict(os.environ, {name: base for name in
                                             ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME")})
        state.start()
        self.addCleanup(state.stop)
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "a\n")
        self.commit(self.repo, "start")
        self.default = self.git(self.repo, "branch", "--show-current").strip()
        self.git(self.repo, "checkout", "-q", "-b", "next")
        here = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, here)

    def _arrives(self, name: str, text: str) -> None:
        self.write(self.repo, name, text)
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", self.default)

    def _prepare(self, *flags: str) -> tuple[dict, str]:
        holding = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, holding, ignore_errors=True)
        with redirect_stdout(io.StringIO()) as out:
            cli.main(["govern", "prepare", "--json", "--repo", str(self.repo), "--into", holding,
                      "--tool", "git", *flags, "--", "checkout", "next"])
        return json.loads(out.getvalue()), holding

    def _record(self) -> dict:
        return govern_status.read(str(self.repo))

    def test_an_unattended_hold_saw_kept_for_let_in_carries_its_details_and_let_in(self):
        self._arrives("loader.js", samples.loader_line())
        printed, _holding = self._prepare("--no-one-to-ask")
        self.assertIn("let_in_later", printed["decision"])
        record = self._record()
        self.assertEqual(record["phase"], "held")
        self.assertEqual(record["verdict"], "infected")
        self.assertIs(record["let_in"], True)
        self.assertEqual(record["command"], {"argv": ["git", "checkout", "next"],
                                             "folder": os.path.realpath(self.repo)})
        self.assertEqual(record["next_steps"], printed["next_steps"])
        self.assertTrue(record["findings"])
        scanned = printed["scan"]["results"][0]["findings"]
        self.assertEqual(record["findings"], [{field: finding[field] for field in govern_held.RECORDED_FINDING_FIELDS}
                                              for finding in scanned])
        self.assertIn("loader.js", {finding["path"] for finding in record["findings"]})

    def test_a_hold_saw_did_not_keep_for_let_in_carries_its_details_with_let_in_false(self):
        self._arrives("loader.js", samples.loader_line())
        printed, _holding = self._prepare()
        self.assertNotIn("let_in_later", printed["decision"])
        record = self._record()
        self.assertEqual(record["phase"], "held")
        self.assertIs(record["let_in"], False)
        self.assertTrue(record["findings"])
        self.assertEqual(record["next_steps"], printed["next_steps"])
        self.assertEqual(record["command"]["argv"], ["git", "checkout", "next"])

    def test_a_recorded_finding_carries_only_the_fields_the_terminal_names(self):
        self._arrives("loader.js", samples.loader_line())
        self._prepare("--no-one-to-ask")
        self.assertTrue(self._record()["findings"])
        for finding in self._record()["findings"]:
            self.assertEqual(tuple(finding), govern_held.RECORDED_FINDING_FIELDS)

    def test_an_update_that_is_not_held_carries_none_of_them(self):
        self._arrives("arrived.txt", "clean\n")
        _printed, holding = self._prepare("--no-one-to-ask")
        self.assertEqual(self._record()["phase"], "checking")
        self.assertFalse(set(_HELD_DETAILS) & set(self._record()))
        govern.apply(str(self.repo), holding)
        self.assertEqual(self._record()["phase"], "applied")
        self.assertFalse(set(_HELD_DETAILS) & set(self._record()))

    def test_a_record_in_another_phase_is_left_as_it_is(self):
        govern_status.write(str(self.repo), "finished", reasons=["the update could not be checked"])
        before = self._record()
        govern_status.add_held_details(str(self.repo), govern_held.details(
            {"next_steps": ["run it as typed"]}, ["git", "pull"], str(self.repo), let_in=False))
        self.assertEqual(self._record(), before)


if __name__ == "__main__":
    import unittest
    unittest.main()

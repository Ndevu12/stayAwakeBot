#!/usr/bin/env python3
"""Every file an update brings is checked by its own name: two names that differ only in case, a
path too long to open by its full name, and a copy that could not be written are each either
scanned or keep the update from reading clean."""
from __future__ import annotations

import json
import subprocess
from unittest import mock

from stayawake.bots.security import govern
from stayawake.lib.git import blob_copies
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples
from tests.support.gitrepo import GitSandbox

_PAYLOAD = "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE
_BENIGN = "module.exports = 1;\n"


class AnUpdateWithNamesThatAreHardToCopy(_TrackingCheckout):

    def _prepare(self) -> tuple[dict, int]:
        self.git(self.open, "fetch", "-q")
        return govern.prepare(str(self.open), str(self.into), "git", ["merge", "origin/main"])

    def _held(self, answer: dict, code: int) -> None:
        self.assertNotEqual(code, exitcodes.CLEAN, answer)
        state = json.loads((self.into / "state.json").read_text(encoding="utf-8"))
        self.assertFalse(state["releasable"], answer)
        before = self.rev(self.open)
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertFalse(applied["applied"], applied)
        self.assertEqual(self.rev(self.open), before)

    def test_names_that_differ_only_in_case_are_each_scanned(self):
        self.write(self.upstream, "Loader.js", _PAYLOAD)
        self.git(self.upstream, "add", "Loader.js")
        benign = subprocess.run(["git", "-C", str(self.upstream), "hash-object", "-w", "--stdin"],
                                input=_BENIGN, capture_output=True, text=True, check=True).stdout.strip()
        self.git(self.upstream, "update-index", "--add", "--cacheinfo", f"100644,{benign},loader.js")
        self.git(self.upstream, "commit", "-qm", "twins")
        answer, code = self._prepare()
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertIn("Loader.js", [f["path"] for f in answer["scan"]["results"][0]["findings"]])
        self._held(answer, code)

    def test_a_path_too_long_to_open_by_its_full_name_is_not_passed_over(self):
        target = 1024 - len(str(self.into / "work")) - 1 + 2
        parts, left = [], target
        while left > 0:
            size = min(200, left - 1 if left > 201 else left)
            parts.append("d" * size)
            left -= size + 1
        deep = "/".join(parts)[:-3] + ".js"
        self.write(self.upstream, deep, _PAYLOAD)
        self.commit(self.upstream, "deep")
        answer, code = self._prepare()
        self._held(answer, code)

    def test_a_copy_that_could_not_be_written_keeps_the_update_from_reading_clean(self):
        real = blob_copies.atomicwrite.replace

        def refuse_one(where, data, **kwargs):
            return False if where.name == "new.txt" else real(where, data, **kwargs)

        with mock.patch.object(blob_copies.atomicwrite, "replace", side_effect=refuse_one):
            answer, code = self._prepare()
        self.assertIn("new.txt", answer["scan"]["results"][0]["error"])
        self._held(answer, code)


class CopyingOutByBlob(GitSandbox):

    def test_each_name_reads_back_its_own_blob(self):
        repo = self.new_repo()
        self.write(repo, "Loader.js", _PAYLOAD)
        self.git(repo, "add", "Loader.js")
        benign = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                                input=_BENIGN, capture_output=True, text=True, check=True).stdout.strip()
        self.git(repo, "update-index", "--add", "--cacheinfo", f"100644,{benign},loader.js")
        self.git(repo, "commit", "-qm", "twins")
        copies = blob_copies.copy_out(repo, self.rev(repo), ("Loader.js", "loader.js"), "twins")
        self.assertEqual(copies.not_copied, ())
        placed = {name: (folder / name).read_text(encoding="utf-8")
                  for folder, names in copies.folders for name in names}
        self.assertEqual(placed, {"Loader.js": _PAYLOAD, "loader.js": _BENIGN})

    def test_a_name_the_commit_does_not_record_is_left_out(self):
        repo = self.new_repo()
        self.write(repo, "kept.txt", "kept\n")
        commit = self.commit(repo, "start")
        copies = blob_copies.copy_out(repo, commit, ("kept.txt", "added-later.txt"), "absent")
        self.assertEqual([names for _folder, names in copies.folders], [("kept.txt",)])
        self.assertEqual(copies.not_copied, ())


if __name__ == "__main__":
    import unittest
    unittest.main()

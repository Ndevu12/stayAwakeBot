#!/usr/bin/env python3
"""Every file an update brings is checked by its own name: two names that differ only in case are
each scanned beside the update's other files, and a path too long to open by its full name or a copy
that could not be written keeps the update from reading clean."""
from __future__ import annotations

import json
import os
import subprocess
import unittest
from unittest import mock

from stayawake.bots.security import govern
from stayawake.lib.git import blob_copies, borrowed
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples
from tests.support.gitrepo import GitSandbox
from tests.support.long_paths import POSIX_ONLY, stage_blob, too_long_by_its_full_name

_PAYLOAD = "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE
_BENIGN = "module.exports = 1;\n"
_TASKS = json.dumps({"version": "2.0.0", "tasks": [{"label": "dev", "type": "shell", "command": "npm run watch",
                                                    "runOptions": {"runOn": "folderOpen"}}]})

class AnUpdateWithNamesThatAreHardToCopy(_TrackingCheckout):

    def _prepare(self) -> tuple[dict, int]:
        self.git(self.open, "fetch", "-q")
        answer, code = govern.prepare(str(self.open), str(self.into), "git", ["merge", "origin/main"])
        self.assertIn("scan", answer, answer)
        return answer, code

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
        stage_blob(self.upstream, "loader.js", _BENIGN)
        self.git(self.upstream, "commit", "-qm", "twins")
        answer, code = self._prepare()
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertIn("Loader.js", [f["path"] for f in answer["scan"]["results"][0]["findings"]])
        self._held(answer, code)

    def test_a_finding_that_needs_two_files_fires_when_one_has_a_twin(self):
        self.write(self.upstream, ".vscode/tasks.json", _TASKS)
        self.write(self.upstream, "package.json",
                   json.dumps({"name": "app", "scripts": {"watch": f"node {samples.FONT_PAYLOAD}"}}))
        self.git(self.upstream, "add", ".vscode/tasks.json", "package.json")
        stage_blob(self.upstream, "Package.json", json.dumps({"name": "app"}))
        self.git(self.upstream, "commit", "-qm", "task and twins")
        answer, code = self._prepare()
        found = {f["signature_id"] for f in answer["scan"]["results"][0]["findings"]}
        self.assertIn("vscode-task-runs-payload-script", found, answer)
        self._held(answer, code)

    @unittest.skipIf(os.name == "nt", POSIX_ONLY)
    def test_a_path_too_long_to_open_by_its_full_name_is_not_passed_over(self):
        deep = too_long_by_its_full_name(self.into / "work")
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
        stage_blob(repo, "loader.js", _BENIGN)
        self.git(repo, "commit", "-qm", "twins")
        copies = blob_copies.copy_out(repo, self.rev(repo), ("Loader.js", "loader.js"), "twins")
        self.assertEqual(copies.not_copied, ())
        placed = {name: (folder / name).read_text(encoding="utf-8")
                  for folder, names in copies.folders for name in names}
        self.assertEqual(placed, {"Loader.js": _PAYLOAD, "loader.js": _BENIGN})

    def test_every_folder_holds_every_file_without_a_twin(self):
        repo = self.new_repo()
        self.write(repo, "Loader.js", _PAYLOAD)
        self.write(repo, "other.js", _BENIGN)
        self.git(repo, "add", "-A")
        stage_blob(repo, "loader.js", _BENIGN)
        self.git(repo, "commit", "-qm", "twins")
        copies = blob_copies.copy_out(repo, self.rev(repo), ("Loader.js", "loader.js", "other.js"), "twins")
        for folder, names in copies.folders:
            self.assertIn("other.js", names)
            self.assertEqual((folder / "other.js").read_text(encoding="utf-8"), _BENIGN)
        self.assertEqual(sorted(name for _folder, names in copies.folders for name in names
                                if name != "other.js"), ["Loader.js", "loader.js"])

    def test_each_name_reads_back_its_bytes_untranslated(self):
        repo = self.new_repo()
        for name, data in (("Loader.js", b"eval(1);\r\n"), ("loader.js", b"a\r\nb\x1ac\n"), ("other.js", b"x\n")):
            blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=data,
                                  capture_output=True, check=True).stdout.decode().strip()
            self.git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}")
        self.git(repo, "commit", "-qm", "twins")
        copies = blob_copies.copy_out(repo, self.rev(repo), ("Loader.js", "loader.js", "other.js"), "twins")
        self.assertEqual(copies.not_copied, ())
        placed = {name: (folder / name).read_bytes() for folder, names in copies.folders for name in names}
        self.assertEqual(placed, {"Loader.js": b"eval(1);\r\n", "loader.js": b"a\r\nb\x1ac\n", "other.js": b"x\n"})

    def test_on_windows_a_name_windows_cannot_hold_is_not_copied_and_the_rest_is(self):
        repo = self.new_repo()
        refused = ("aux.js", "Com1.txt", "lpt\u00b9.js", "a:b.js", "trailing.", "folder /x.js", "back\\slash.js",
                   "ask?.js", "nul")
        received_from_elsewhere = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.protectNTFS",
                                   "GIT_CONFIG_VALUE_0": "false"}
        with mock.patch.dict(os.environ, received_from_elsewhere):
            for name in (*refused, "kept.js", "con-not-reserved.js"):
                stage_blob(repo, name, _BENIGN)
            self.git(repo, "commit", "-qm", "names")
        with mock.patch.object(blob_copies, "ON_WINDOWS", True):
            copies = blob_copies.copy_out(repo, self.rev(repo), (*refused, "kept.js", "con-not-reserved.js"), "names")
        self.assertEqual(sorted(copies.not_copied), sorted(refused))
        self.assertEqual(sorted(name for _folder, names in copies.folders for name in names),
                         ["con-not-reserved.js", "kept.js"])

    def test_a_name_the_commit_does_not_record_is_left_out(self):
        repo = self.new_repo()
        self.write(repo, "kept.txt", "kept\n")
        commit = self.commit(repo, "start")
        copies = blob_copies.copy_out(repo, commit, ("kept.txt", "added-later.txt"), "absent")
        self.assertEqual([names for _folder, names in copies.folders], [("kept.txt",)])
        self.assertEqual(copies.not_copied, ())


class AHoldingCopyReadsTheFoldersObjects(GitSandbox):

    def test_a_repository_pointed_at_another_store_finds_its_commits(self):
        repo = self.new_repo()
        self.write(repo, "kept.txt", "kept\n")
        commit = self.commit(repo, "start")
        holding = self.owned(self.root / "holding.git")
        subprocess.run(["git", "init", "-q", "--bare", str(holding)], check=True, capture_output=True)
        borrowed.write_alternates(holding, [repo / ".git" / "objects"])
        listed = (holding / "objects" / "info" / "alternates").read_bytes()
        self.assertEqual(listed, os.fsencode(str(repo / ".git" / "objects")) + b"\n")
        self.assertEqual(self.git(holding, "cat-file", "-t", commit).strip(), "commit")


if __name__ == "__main__":
    import unittest
    unittest.main()

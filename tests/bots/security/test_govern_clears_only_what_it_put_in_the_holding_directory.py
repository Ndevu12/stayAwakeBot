#!/usr/bin/env python3
"""`saw govern` refuses a holding directory that is the open folder, lies inside it or holds it, and
clears only the entries it put there: no folder named as its holding directory is ever deleted."""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from unittest import TestCase

from stayawake.bots.security import govern
from stayawake.lib.git import holding_directory
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout


class AHoldingDirectoryIsNeverDeleted(_TrackingCheckout):

    def _prepare(self, into: Path, repo: "Path | None" = None) -> tuple[dict, int]:
        return govern.prepare(str(repo or self.open), str(into), "git", ["pull"])

    def _refused(self, into: Path, reason: str, repo: "Path | None" = None) -> None:
        answer, code = self._prepare(into, repo)
        self.assertEqual((answer.get("reason"), code), (reason, exitcodes.INCOMPLETE), answer)
        self.assertEqual(answer["decision"]["choices"], list(govern.DECISION_CHOICES), answer)
        self.assertTrue((self.open / ".git").is_dir())
        self.assertEqual((self.open / "kept.txt").read_text(), "kept\n")
        self.assertFalse((self.open / "new.txt").exists())

    def _checked_and_applied(self, into: Path) -> None:
        answer, code = self._prepare(into)
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(govern.apply(str(self.open), str(into))[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual((self.open / "new.txt").read_text(), "new\n")

    def test_the_open_folder_as_the_holding_directory_is_refused_and_kept(self):
        self.write(self.open, "state.json", "{\"mine\": true}\n")
        self._refused(self.open, holding_directory.OVERLAPS_THE_FOLDER)
        self.assertEqual((self.open / "state.json").read_text(), "{\"mine\": true}\n")
        applied = govern.apply(str(self.open), str(self.open))[0]
        self.assertEqual(applied, {"applied": False, "outcome": govern.HOLDING_UNUSABLE,
                                   "reason": holding_directory.OVERLAPS_THE_FOLDER})

    def test_a_folder_holding_the_open_folder_is_refused_and_its_files_kept(self):
        sibling = self.root / "notes.txt"
        sibling.write_text("notes\n", encoding="utf-8")
        self._refused(self.root, holding_directory.OVERLAPS_THE_FOLDER)
        self.assertEqual(sibling.read_text(encoding="utf-8"), "notes\n")
        self.assertTrue((self.upstream / ".git").is_dir())

    def test_a_folder_inside_the_open_folder_is_refused_and_its_files_kept(self):
        inside = self.open / "held"
        self.write(self.open, "held/notes.txt", "notes\n")
        self._refused(inside, holding_directory.OVERLAPS_THE_FOLDER)
        self.assertEqual((inside / "notes.txt").read_text(encoding="utf-8"), "notes\n")

    def test_a_folder_of_the_repository_beside_the_open_folder_is_refused_and_kept(self):
        self.write(self.open, "sub/work/user.txt", "user\n")
        self.write(self.open, "data/work/keep.txt", "keep\n")
        self.write(self.open, "data/state.json", "{\"mine\": true}\n")
        self.commit(self.open, "tracked data")
        data = self.open / "data"
        self._refused(data, holding_directory.OVERLAPS_THE_FOLDER, repo=self.open / "sub")
        self.assertEqual(sorted(os.listdir(data)), ["state.json", "work"])
        self.assertEqual((data / "state.json").read_text(encoding="utf-8"), "{\"mine\": true}\n")
        self.assertEqual(os.listdir(data / "work"), ["keep.txt"])
        self.assertEqual(self.git(self.open, "status", "--porcelain").strip(), "")
        applied = govern.apply(str(self.open / "sub"), str(data))[0]
        self.assertEqual(applied, {"applied": False, "outcome": govern.HOLDING_UNUSABLE,
                                   "reason": holding_directory.OVERLAPS_THE_FOLDER})

    def _linked(self) -> Path:
        linked = self.owned(self.root / "linked")
        self.git(self.open, "worktree", "add", "-q", "-b", "side", str(linked))
        return linked

    def test_the_git_directory_of_a_linked_work_tree_is_refused_and_kept(self):
        common = self.open / ".git"
        self._refused(common, holding_directory.OVERLAPS_THE_FOLDER, repo=self._linked())
        self.assertTrue((common / "HEAD").is_file())
        self.assertTrue((common / "config").is_file())
        for name in (holding_directory.REPOSITORY, holding_directory.WORK_TREE, holding_directory.NO_HOOKS):
            self.assertFalse((common / name).exists(), name)

    def test_a_folder_inside_the_git_directory_is_refused_and_not_made(self):
        inside = self.open / ".git" / "held"
        self._refused(inside, holding_directory.OVERLAPS_THE_FOLDER, repo=self._linked())
        self.assertFalse(inside.exists())

    def test_a_command_run_as_typed_is_answered_and_an_overlapping_holding_directory_untouched(self):
        bare = self.owned(self.root / "bare.git")
        self.git(self.root, "clone", "-q", "--bare", str(self.upstream), str(bare))
        notes = self.root / "notes.txt"
        notes.write_text("notes\n", encoding="utf-8")
        for repo, into, args in ((self.root, self.root / "holding", ["--git-dir", str(bare), "fetch", "origin"]),
                                 (bare, bare / "held", ["fetch", "origin"]), (bare, self.root, ["fetch", "origin"])):
            with self.subTest(repo=repo, into=into):
                answer, code = govern.prepare(str(repo), str(into), "git", args)
                self.assertEqual((answer.get("passthrough"), code), (True, exitcodes.CLEAN), answer)
                self.assertFalse((self.root / "holding").exists())
                self.assertFalse((bare / "held").exists())
                self.assertEqual(notes.read_text(encoding="utf-8"), "notes\n")
                self.assertTrue((bare / "HEAD").is_file())

    def test_a_link_to_the_open_folder_is_refused(self):
        link = self.root / "link"
        try:
            os.symlink(self.open, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("this system makes no symbolic links here")
        self._refused(link, holding_directory.OVERLAPS_THE_FOLDER)

    def test_a_folder_holding_files_saw_did_not_put_there_is_refused_and_kept(self):
        into = self.root / "elsewhere"
        into.mkdir()
        (into / "notes.txt").write_text("notes\n", encoding="utf-8")
        (into / "state.json").write_text("{\"mine\": true}\n", encoding="utf-8")
        (into / "work").mkdir()
        (into / "work" / "draft.txt").write_text("draft\n", encoding="utf-8")
        self._refused(into, holding_directory.HOLDS_OTHER_FILES)
        self.assertEqual(sorted(os.listdir(into)), ["notes.txt", "state.json", "work"])
        self.assertEqual((into / "state.json").read_text(encoding="utf-8"), "{\"mine\": true}\n")
        self.assertEqual((into / "work" / "draft.txt").read_text(encoding="utf-8"), "draft\n")
        self.assertFalse(govern.apply(str(self.open), str(into))[0]["applied"])

    def test_an_empty_holding_directory_is_used(self):
        self.into.mkdir()
        self._checked_and_applied(self.into)

    def test_a_missing_holding_directory_is_made(self):
        self._checked_and_applied(self.into)

    def test_a_holding_directory_an_earlier_check_filled_is_used_again(self):
        answer, code = self._prepare(self.into)
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertTrue((self.into / holding_directory.STATE).is_file())
        (self.into / holding_directory.STATE_BEING_WRITTEN).write_text("{}", encoding="utf-8")
        self._checked_and_applied(self.into)
        self.assertFalse((self.into / holding_directory.STATE_BEING_WRITTEN).exists())


class ClearingRemovesOnlySawsEntries(TestCase):

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="saw-holding-")).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.into = self.root / "holding"

    def test_every_entry_saw_puts_there_is_removed(self):
        for name in (holding_directory.REPOSITORY, holding_directory.WORK_TREE, holding_directory.NO_HOOKS):
            (self.into / name / "inner").mkdir(parents=True)
        for name in (holding_directory.STATE, holding_directory.STATE_BEING_WRITTEN):
            (self.into / name).write_text("{}", encoding="utf-8")
        self.assertEqual(holding_directory.clear(self.into), "")
        self.assertEqual(os.listdir(self.into), [])

    def test_one_other_entry_keeps_every_entry(self):
        (self.into / holding_directory.REPOSITORY).mkdir(parents=True)
        (self.into / holding_directory.STATE).write_text("{}", encoding="utf-8")
        (self.into / "notes.txt").write_text("notes\n", encoding="utf-8")
        self.assertEqual(holding_directory.clear(self.into), holding_directory.HOLDS_OTHER_FILES)
        self.assertEqual(sorted(os.listdir(self.into)),
                         sorted([holding_directory.REPOSITORY, holding_directory.STATE, "notes.txt"]))

    def test_a_linked_entry_is_removed_and_what_it_names_kept(self):
        target = self.root / "mine"
        target.mkdir()
        (target / "notes.txt").write_text("notes\n", encoding="utf-8")
        self.into.mkdir()
        try:
            os.symlink(target, self.into / holding_directory.WORK_TREE, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("this system makes no symbolic links here")
        self.assertEqual(holding_directory.clear(self.into), "")
        self.assertEqual((target / "notes.txt").read_text(encoding="utf-8"), "notes\n")

    def test_a_file_named_as_the_holding_directory_is_kept(self):
        self.into.write_text("notes\n", encoding="utf-8")
        self.assertEqual(holding_directory.clear(self.into), holding_directory.NOT_A_FOLDER)
        self.assertEqual(self.into.read_text(encoding="utf-8"), "notes\n")

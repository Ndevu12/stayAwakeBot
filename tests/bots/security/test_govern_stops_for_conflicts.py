#!/usr/bin/env python3
"""A pull, merge or rebase that stops for conflicts is checked like any other update, and apply
brings in exactly what was checked with the conflicts left for the operator to resolve."""
from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
from pathlib import Path
from unittest import mock

from stayawake import cli
from stayawake.bots.security import govern
from stayawake.utils import exitcodes
from tests.bots.security.test_govern_replays_a_tracking_checkout import _TrackingCheckout
from tests.support import samples

_SCAN = "stayawake.bots.security.govern._scan_arrived"
_PAYLOAD = "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE


def _verdict_doc(verdict: str) -> dict:
    return {"generated_at": "t", "results": [{"target": "x", "verdict": verdict,
                                               "findings": [], "advisories": [], "notes": []}]}


class _StopsForConflicts(_TrackingCheckout):
    """The upstream and the open folder each changed kept.txt, and the upstream also added new.txt."""

    def setUp(self):
        super().setUp()
        self.write(self.upstream, "kept.txt", "from upstream\n")
        self.incoming = self.commit(self.upstream, "upstream edit")
        self.write(self.open, "kept.txt", "mine\n")
        self.base = self.commit(self.open, "local edit")

    def _prepare(self, *args: str) -> tuple[dict, int]:
        return govern.prepare(str(self.open), str(self.into), "git", list(args))

    def _apply(self, accept: str | None = None) -> tuple[dict, int]:
        return govern.apply(str(self.open), str(self.into), accept)

    def _state(self) -> dict:
        return json.loads((self.into / "state.json").read_text(encoding="utf-8"))

    def _unmerged(self, repo: Path) -> str:
        return self.git(repo, "ls-files", "-s", "-u")

    def _untouched(self) -> None:
        self.assertEqual(self.rev(self.open), self.base)
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "mine\n")
        self.assertFalse((self.open / "new.txt").exists())
        self.assertFalse((self.open / ".git" / "MERGE_HEAD").exists())
        self.assertFalse((self.open / ".git" / "rebase-merge").exists())
        self.assertEqual(self.git(self.open, "status", "--porcelain"), "")


class AnUpdateThatStopsForConflicts(_StopsForConflicts):

    def test_a_conflicting_merge_is_checked_and_says_it_stops_for_conflicts(self):
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("merge", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean")
        self.assertEqual(answer["conflicts"], ["kept.txt"])
        self.assertTrue(any("stops for conflicts in kept.txt" in step for step in answer["next_steps"]))
        self.assertNotIn("decision", answer)
        state = self._state()
        self.assertEqual((state["mode"], state["commit"], state["base"]), ("conflicts", self.incoming, self.base))
        self.assertIsNone(state["clean_mark"])
        self.assertIsNone(state["applied_mark"])
        self._untouched()

    def test_both_the_files_that_land_and_the_incoming_versions_are_scanned(self):
        self.git(self.open, "fetch", "-q")
        scanned: list[str] = []
        real = govern._scan_files

        def recording(files, paths, policy):
            scanned.extend((Path(files) / p).read_text(encoding="utf-8") for p in paths
                           if p == "kept.txt" and (Path(files) / p).is_file())
            return real(files, paths, policy)

        with mock.patch.object(govern, "_scan_files", side_effect=recording):
            self._prepare("merge", "origin/main")
        self.assertIn("from upstream\n", scanned)
        self.assertTrue(any(text.startswith("<<<<<<<") for text in scanned), scanned)

    def test_apply_leaves_the_merge_in_progress_on_the_checked_commit(self):
        self.git(self.open, "fetch", "-q")
        self._prepare("merge", "origin/main")
        answer, code = self._apply()
        self.assertEqual(code, exitcodes.INCOMPLETE, answer)
        self.assertTrue(answer["applied"])
        self.assertEqual(answer["conflicts"], ["kept.txt"])
        self.assertIn("git commit", answer["next_steps"][0])
        self.assertEqual((self.open / ".git" / "MERGE_HEAD").read_text(encoding="utf-8").strip(), self.incoming)
        self.assertEqual(self._unmerged(self.open), self._unmerged(self.into / "work"))
        status = self.git(self.open, "status", "--porcelain").splitlines()
        self.assertIn("UU kept.txt", status)
        self.assertIn("A  new.txt", status)
        self.assertIn("<<<<<<<", (self.open / "kept.txt").read_text(encoding="utf-8"))
        self.assertEqual(self.rev(self.open), self.base)
        self.write(self.open, "kept.txt", "resolved\n")
        self.git(self.open, "add", "kept.txt")
        self.git(self.open, "commit", "-q", "--no-edit")
        parents = self.git(self.open, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:]
        self.assertEqual(parents, [self.base, self.incoming])
        self.assertEqual(self.git(self.open, "status", "--porcelain"), "")

    def test_apply_leaves_the_rebase_in_progress_onto_the_checked_commit(self):
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("rebase", "origin/main")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(answer["conflicts"], ["kept.txt"])
        self._untouched()
        answer, code = self._apply()
        self.assertEqual(code, exitcodes.INCOMPLETE, answer)
        self.assertIn("git rebase --continue", answer["next_steps"][0])
        rebasing = self.open / ".git" / "rebase-merge"
        self.assertEqual((rebasing / "onto").read_text(encoding="utf-8").strip(), self.incoming)
        self.assertEqual(self.rev(self.open), self.incoming)
        self.assertEqual(self._unmerged(self.open), self._unmerged(self.into / "work"))
        self.assertIn("UU kept.txt", self.git(self.open, "status", "--porcelain").splitlines())
        self.assertIn("rebase", self.git(self.open, "status"))
        self.write(self.open, "kept.txt", "resolved\n")
        self.git(self.open, "add", "kept.txt")
        finished = subprocess.run(["git", "-C", str(self.open), "rebase", "--continue"], capture_output=True,
                                  text=True, env={**os.environ, "GIT_EDITOR": "true"})
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertEqual(self.git(self.open, "symbolic-ref", "HEAD").strip(), "refs/heads/main")
        self.assertEqual(self.rev(self.open, "HEAD~1"), self.incoming)
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "resolved\n")

    def test_a_pull_brings_only_the_commit_it_checked(self):
        answer, code = self._prepare("pull")
        self.assertEqual(code, exitcodes.CLEAN, answer)
        self.assertEqual(answer["conflicts"], ["kept.txt"])
        self.write(self.upstream, "later.txt", "never checked\n")
        later = self.commit(self.upstream, "after the check")
        answer, code = self._apply()
        self.assertTrue(answer["applied"], answer)
        self.assertEqual((self.open / ".git" / "MERGE_HEAD").read_text(encoding="utf-8").strip(), self.incoming)
        self.assertFalse((self.open / "later.txt").exists())
        missing = subprocess.run(["git", "-C", str(self.open), "cat-file", "-e", later], capture_output=True)
        self.assertNotEqual(missing.returncode, 0, "the commit made after the check reached the folder")

    def test_a_pull_that_rebases_is_left_in_progress(self):
        self._prepare("pull", "--rebase")
        answer, code = self._apply()
        self.assertTrue(answer["applied"], answer)
        self.assertEqual((self.open / ".git" / "rebase-merge" / "onto").read_text(encoding="utf-8").strip(),
                         self.incoming)

    def test_a_suspicious_conflicted_update_is_held_until_it_is_let_in(self):
        self.git(self.open, "fetch", "-q")
        with mock.patch(_SCAN, return_value=(_verdict_doc("suspicious"), exitcodes.CLEAN, [])):
            answer, _code = self._prepare("merge", "origin/main")
        self.assertIn("let-in", answer["decision"]["choices"])
        self.assertEqual(answer["conflicts"], ["kept.txt"])
        self._untouched()
        with mock.patch.dict(os.environ, {"SAW_GOVERN_DECISION": "run-as-typed"}):
            refused, code = self._apply()
        self.assertFalse(refused["applied"], refused)
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self._untouched()
        answer, code = self._apply(accept=self.incoming)
        self.assertTrue(answer["applied"], answer)
        self.assertEqual((self.open / ".git" / "MERGE_HEAD").read_text(encoding="utf-8").strip(), self.incoming)
        self.assertIn("UU kept.txt", self.git(self.open, "status", "--porcelain").splitlines())

    def test_uncommitted_work_on_a_conflicted_file_stops_the_update(self):
        self.git(self.open, "fetch", "-q")
        self._prepare("merge", "origin/main")
        self.write(self.open, "kept.txt", "mine, and more\n")
        answer, _code = self._apply()
        self.assertFalse(answer["applied"], answer)
        self.assertEqual(answer["reason"], "uncommitted work would be overwritten, so the folder was not changed")
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "mine, and more\n")
        self.assertFalse((self.open / ".git" / "MERGE_HEAD").exists())

    def test_a_failure_that_is_not_a_conflict_answers_as_before(self):
        answer, code = self._prepare("merge", "no-such-branch")
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertEqual(answer["reason"], "the update did not finish cleanly")
        self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
        self.assertNotIn("scan", answer)
        self._untouched()

    def test_the_terminal_shows_what_to_do_and_the_command_does_not_succeed(self):
        self.git(self.open, "fetch", "-q")
        self._prepare("merge", "origin/main")
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = cli.main(["govern", "apply", "--json", "--repo", str(self.open), "--into", str(self.into)])
        self.assertNotEqual(code, exitcodes.CLEAN)
        self.assertIn("stops for conflicts in kept.txt", err.getvalue())
        self.assertIn("git commit", err.getvalue())
        self.assertTrue(json.loads(out.getvalue())["applied"])


class WhatTheCheckPins(_StopsForConflicts):

    def test_a_state_file_changed_after_the_check_is_not_carried(self):
        self.git(self.open, "config", "pull.rebase", "true")
        answer, _code = self._prepare("pull")
        self.assertEqual(answer["conflicts"], ["kept.txt"], answer)
        todo = self.into / "repo.git" / "rebase-merge" / "git-rebase-todo"
        todo.write_bytes(todo.read_bytes() + b"pick %s # added after the check\n" % self.incoming.encode())
        refused, _code = self._apply()
        self.assertFalse(refused["applied"], refused)
        self.assertEqual(refused["reason"], "the checked update is no longer in the holding directory; check it again")
        self._untouched()


class WhatIsWrittenIsWhatWasChecked(_StopsForConflicts):

    def test_a_conflicted_file_unlike_the_one_checked_is_not_left_in_the_folder(self):
        self.git(self.open, "fetch", "-q")
        self._prepare("merge", "origin/main")
        state = self._state()
        state["written"]["kept.txt"] = "0" * 64
        (self.into / "state.json").write_text(json.dumps(state), encoding="utf-8")
        refused, _code = self._apply()
        self.assertFalse(refused["applied"], refused)
        self._untouched()


class APullWhoseConflictsStayOut(_TrackingCheckout):
    """Both sides changed where a symbolic link points, which saw does not carry into the folder."""

    def test_it_offers_only_to_leave_the_folder_and_names_the_command_for_the_checked_commit(self):
        os.symlink("a", self.upstream / "link")
        self.commit(self.upstream, "link")
        self.git(self.open, "pull", "-q", "--ff-only")
        os.remove(self.upstream / "link")
        os.symlink("c", self.upstream / "link")
        incoming = self.commit(self.upstream, "theirs")
        os.remove(self.open / "link")
        os.symlink("b", self.open / "link")
        self.commit(self.open, "mine")
        answer, code = govern.prepare(str(self.open), str(self.into), "git", ["pull"])
        self.assertEqual(code, exitcodes.INCOMPLETE, answer)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean", answer)
        self.assertEqual(answer["decision"]["choices"], ["leave-unchanged"])
        self.assertIn(f"run `git merge {incoming}`", answer["next_steps"][0])


class ConflictsThatCannotBeBroughtIn(_StopsForConflicts):
    """The rebase runs on git's patch-applying backend, whose stopped state saw does not carry."""

    def _not_brought_in(self, code: int) -> None:
        self.assertNotEqual(code, exitcodes.CLEAN)
        refused, _code = self._apply(accept=self.incoming)
        self.assertFalse(refused["applied"], refused)
        self.assertEqual(refused["reason"], "the update stops for conflicts that cannot be brought into the folder")
        self._untouched()

    def test_a_clean_one_is_checked_then_left_to_you(self):
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("rebase", "--apply", "origin/main")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean", answer)
        self.assertEqual(answer["reason"], "the update stops for conflicts that cannot be brought into the folder")
        self.assertEqual(answer["decision"]["choices"], ["run-as-typed", "leave-unchanged"])
        self._not_brought_in(code)

    def test_one_that_brings_a_payload_is_held_with_no_way_to_run_it(self):
        self.write(self.upstream, "loader.js", _PAYLOAD)
        self.incoming = self.commit(self.upstream, "payload")
        self.git(self.open, "fetch", "-q")
        answer, code = self._prepare("rebase", "--apply", "origin/main")
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected", answer)
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertNotIn("decision", answer)
        self.assertIn("cannot be brought into the folder", answer["next_steps"][-1])
        self._not_brought_in(code)

    def test_a_suspicious_one_is_held_with_no_way_to_run_it(self):
        self.git(self.open, "fetch", "-q")
        with mock.patch(_SCAN, return_value=(_verdict_doc("suspicious"), exitcodes.CLEAN, [])):
            answer, code = self._prepare("rebase", "--apply", "origin/main")
        self.assertNotIn("decision", answer)
        self.assertFalse(any("let" in step and "in;" in step for step in answer["next_steps"]), answer)
        self._not_brought_in(code)


class AConflictTheUpdateDeletes(_TrackingCheckout):
    """The upstream deleted kept.txt, which the open folder changed."""

    def setUp(self):
        super().setUp()
        self.git(self.upstream, "rm", "-q", "kept.txt")
        self.commit(self.upstream, "upstream delete")
        self.write(self.open, "kept.txt", "mine\n")
        self.base = self.commit(self.open, "local edit")
        self.git(self.open, "fetch", "-q")

    def test_it_is_brought_in_with_the_file_left_to_resolve(self):
        answer, _code = govern.prepare(str(self.open), str(self.into), "git", ["merge", "origin/main"])
        self.assertEqual(answer.get("conflicts"), ["kept.txt"], answer)
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertTrue(applied["applied"], applied)
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "mine\n")
        self.assertIn("UD kept.txt", self.git(self.open, "status", "--porcelain").splitlines())

    def test_uncommitted_work_on_a_file_left_as_it_was_stops_the_update(self):
        answer, _code = govern.prepare(str(self.open), str(self.into), "git", ["merge", "origin/main"])
        self.assertEqual(answer.get("conflicts"), ["kept.txt"], answer)
        self.write(self.open, "kept.txt", "mine, not committed\n")
        applied, _code = govern.apply(str(self.open), str(self.into))
        self.assertFalse(applied["applied"], applied)
        self.assertEqual((self.open / "kept.txt").read_text(encoding="utf-8"), "mine, not committed\n")
        self.assertFalse((self.open / ".git" / "MERGE_HEAD").exists())


if __name__ == "__main__":
    import unittest
    unittest.main()

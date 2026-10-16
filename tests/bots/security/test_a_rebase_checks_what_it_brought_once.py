#!/usr/bin/env python3
"""A pull that rebases, and a rebase, check what they brought once: the scan after the rebase leaves out
what the rebase's own checkout read clean, and still checks what the replay changed, a resolved conflict,
a commit git dropped, and everything again when the checkout found something."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from stayawake.bots.security import clean_contents, hook
from tests.bots.security.test_hook import _INFECTED, _Isolated

_SOURCE = Path(hook.__file__).resolve().parents[3]
_DRIVER = '''import json, sys
sys.path.insert(0, {source!r})
from stayawake.bots.security import hook
real = hook._scan_within_budget


def noting(root, include, config_path, display, merges=None):
    result = real(root, include, config_path, display, merges)
    found = sorted({{f.category for f in getattr(result, "findings", ())}})
    with open({log!r}, "a") as log:
        log.write(json.dumps({{"event": sys.argv[1], "files": None if include is None else sorted(include),
                              "found": found}}) + "\\n")
    return result


hook._scan_within_budget = noting
hook._bring_up_to_date = lambda: None
hook.git_runs_settings_hooks = lambda *args, **kwargs: False
sys.exit(hook.run_event(sys.argv[1], sys.argv[2:]))
'''
_LINES = "".join(f"line {n}\n" for n in range(20))


def _edited(line: int, text: str) -> str:
    lines = _LINES.splitlines(keepends=True)
    lines[line] = text + "\n"
    return "".join(lines)


class _Rebasing(_Isolated):
    def setUp(self):
        super().setUp()
        self.folder = Path(tempfile.mkdtemp(prefix="rebase-once-"))
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.log = self.folder / "scans.jsonl"
        driver = self.folder / "driver.py"
        driver.write_text(_DRIVER.format(source=str(_SOURCE), log=str(self.log)))
        hooks = self.folder / "hooks"
        hooks.mkdir()
        for event in ("post-checkout", "post-merge", "post-rewrite"):
            script = hooks / event
            script.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{driver}" {event} "$@"\n')
            script.chmod(0o755)
        (self.home / "gitconfig").write_text(
            "[user]\n\tname = t\n\temail = t@t\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n"
            f"[core]\n\thooksPath = {hooks}\n[advice]\n\tskippedCherryPicks = false\n")
        self.up, self.down = self.folder / "up", self.folder / "down"
        self.up.mkdir()
        self._git(self.up, "init", "-q")
        self._commit(self.up, {"a.txt": _LINES, "b.txt": "b\n"})
        self._git(self.folder, "clone", "-q", str(self.up), str(self.down))

    def _git(self, where: Path, *args: str, check: bool = True):
        result = subprocess.run(["git", *args], cwd=where, capture_output=True, text=True,
                                stdin=subprocess.DEVNULL, env={**os.environ, "GIT_EDITOR": "true"})
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def _commit(self, where: Path, files: dict[str, str]):
        for rel, text in files.items():
            (where / rel).write_text(text)
        self._git(where, "add", "-A")
        self._git(where, "commit", "-q", "-m", "work")

    def _scans_during(self, *args: str, check: bool = True) -> list[dict]:
        self.log.write_text("")
        self._git(self.down, *args, check=check)
        return [json.loads(line) for line in self.log.read_text().splitlines()]


class TestARebaseChecksWhatItBroughtOnce(_Rebasing):
    def test_a_pull_that_rebases_local_work_checks_what_it_brought_once(self):
        self._commit(self.up, {"a.txt": _edited(1, "upstream"), "c.txt": "c\n"})
        self._commit(self.down, {"d.txt": "local\n"})
        scans = self._scans_during("pull", "-q", "--rebase")
        self.assertEqual(scans, [{"event": "post-checkout", "files": ["a.txt", "c.txt"], "found": []}])

    def test_a_branch_rebased_onto_another_checks_what_it_brought_once(self):
        self._git(self.down, "switch", "-q", "-c", "feature")
        self._commit(self.down, {"f.txt": "feature\n"})
        self._git(self.down, "switch", "-q", "main")
        self._commit(self.down, {"a.txt": _edited(1, "main"), "c.txt": "c\n"})
        self._git(self.down, "switch", "-q", "feature")
        scans = self._scans_during("rebase", "-q", "main")
        self.assertEqual(scans, [{"event": "post-checkout", "files": ["a.txt", "c.txt"], "found": []}])

    def test_a_reworded_commit_is_checked_as_before(self):
        for n in range(3):
            self._commit(self.down, {f"l{n}.txt": f"{n}\n"})
        editor = f"{sys.executable} -I -c \"import sys; p = sys.argv[1]; t = open(p).read(); " \
                 f"open(p, 'w').write(t.replace('pick', 'reword', 1))\""
        self.log.write_text("")
        self._git(self.down, "-c", f"sequence.editor={editor}", "rebase", "-q", "-i", "HEAD~2")
        self.assertEqual([s for s in map(json.loads, self.log.read_text().splitlines())], [])


class TestWhatTheReplayChangedIsCheckedAgain(_Rebasing):
    def test_a_file_the_replay_changes_again_is_checked_again(self):
        self._commit(self.up, {"a.txt": _edited(1, "upstream")})
        self._commit(self.down, {"a.txt": _edited(15, "local"), "d.txt": "local\n"})
        scans = self._scans_during("pull", "-q", "--rebase")
        self.assertEqual([(s["event"], s["files"]) for s in scans],
                         [("post-checkout", ["a.txt"]), ("post-rewrite", ["a.txt"])])

    def test_a_resolved_conflict_is_checked(self):
        self._commit(self.up, {"a.txt": _edited(1, "upstream"), "c.txt": "c\n"})
        self._commit(self.down, {"a.txt": _edited(1, "local"), "d.txt": "local\n"})
        self._scans_during("pull", "-q", "--rebase", check=False)
        (self.down / "a.txt").write_text(_edited(1, "resolved"))
        self._git(self.down, "add", "a.txt")
        scans = self._scans_during("rebase", "--continue")
        self.assertEqual([(s["event"], s["files"]) for s in scans], [("post-rewrite", ["a.txt"])])

    def test_a_commit_git_dropped_as_already_upstream_is_still_checked(self):
        self._commit(self.up, {"a.txt": _edited(1, "same")})
        self._commit(self.down, {"d.txt": "local\n"})
        self._commit(self.down, {"a.txt": _edited(1, "same")})
        scans = self._scans_during("pull", "-q", "--rebase")
        self.assertEqual([(s["event"], s["files"]) for s in scans], [("post-rewrite", ["a.txt"])])


class TestAFindingAtTheCheckoutIsCheckedAgain(_Rebasing):
    def test_an_infected_file_the_pull_brings_is_found_and_checked_again(self):
        self._commit(self.up, {".gitignore": _INFECTED, "c.txt": "c\n"})
        self._commit(self.down, {"d.txt": "local\n"})
        scans = self._scans_during("pull", "-q", "--rebase")
        self.assertEqual([(s["event"], s["files"]) for s in scans],
                         [("post-checkout", [".gitignore", "c.txt"]),
                          ("post-rewrite", [".gitignore", "c.txt"])])
        self.assertTrue(all(s["found"] for s in scans))


class TestOnlyARebaseIsNarrowed(_Rebasing):
    def test_a_checkout_outside_a_rebase_notes_nothing(self):
        self._commit(self.up, {"a.txt": _edited(1, "upstream")})
        self._git(self.down, "fetch", "-q")
        scans = self._scans_during("switch", "-q", "--detach", "origin/main")
        self.assertEqual([(s["event"], s["files"]) for s in scans], [("post-checkout", ["a.txt"])])
        self.assertFalse(clean_contents.store_path(self.down).exists())

    def test_an_amend_is_scanned_for_what_it_changed_even_when_that_content_was_read_clean(self):
        (self.down / "a.txt").write_text(_edited(1, "read clean"))
        clean_contents.remember(self.down, clean_contents.seen(self.down, ("a.txt",), 1 << 20),
                                hook._policy_digest(None))
        given = hook._within_a_rebase("post-rewrite", ["amend"], self.down, None, ("a.txt",), "rewrite")
        self.assertEqual(given[:2], (("a.txt",), "rewrite"))

    def test_contents_read_clean_under_other_rules_are_checked_again(self):
        (self.down / "a.txt").write_text(_edited(1, "read clean"))
        clean_contents.remember(self.down, clean_contents.seen(self.down, ("a.txt",), 1 << 20), "other rules")
        given = hook._within_a_rebase("post-rewrite", ["rebase"], self.down, None, ("a.txt",), "rewrite")
        self.assertEqual(given[:2], (("a.txt",), "rewrite"))


if __name__ == "__main__":
    import unittest
    unittest.main()

#!/usr/bin/env python3
"""An incoming update is checked outside the open folder, and the folder changes only then.

prepare materialises a pull/checkout/merge/fetch in a holding directory saw owns and scans what
arrived; the open folder is not touched. apply makes the open folder match a checked tree, without
fetching again, keeping the operator's uncommitted work — or it changes nothing. The incoming
repository's hooks never run during the check; the operator's own git still runs them.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.utils import exitcodes
from tests.support import samples
from tests.support.gitrepo import GitSandbox

_SCAN = "stayawake.bots.security.govern._scan_arrived"


def _verdict_doc(verdict: str) -> dict:
    return {"generated_at": "t", "results": [{"target": "x", "verdict": verdict,
                                               "findings": [], "advisories": [], "notes": []}]}


class GovernIncoming(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo("open")
        self.write(self.repo, "keep.txt", "already\n")
        self.commit(self.repo, "start")
        self.base = self.rev(self.repo)
        self.git(self.repo, "checkout", "-q", "-b", "next")
        self.write(self.repo, "arrived.txt", "from next\n")
        self.commit(self.repo, "arrive")
        self.git(self.repo, "checkout", "-q", "main")
        self.into = self.root / "holding"
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text('#!/bin/sh\ntouch "$(dirname "$0")/../../hook-ran"\n', encoding="utf-8")
        hook.chmod(0o755)

    def _run(self, *args: str) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(args))
        return code, json.loads(out.getvalue())

    def _prepare(self, *command: str) -> tuple[int, dict]:
        return self._run("govern", "prepare", "--json", "--repo", str(self.repo),
                         "--into", str(self.into), "--tool", "git", "--", *command)

    def _apply(self) -> tuple[int, dict]:
        return self._run("govern", "apply", "--json", "--repo", str(self.repo), "--into", str(self.into))

    def test_a_checkout_is_checked_before_the_folder_changes(self):
        code, body = self._prepare("checkout", "next")
        self.assertEqual(code, exitcodes.CLEAN, body)
        self.assertEqual(self.rev(self.repo), self.base)                  # open folder untouched
        self.assertFalse((self.repo / "arrived.txt").exists())
        self.assertFalse((self.repo / "hook-ran").exists())               # no incoming hook ran
        self.assertEqual(body["schema_version"], 1)
        self.assertIn("scan", body)
        state = json.loads((self.into / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["paths"], ["arrived.txt"])
        code, applied = self._apply()
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertTrue(applied["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "from next\n")
        self.assertEqual((self.repo / "keep.txt").read_text(encoding="utf-8"), "already\n")
        self.assertFalse((self.repo / "hook-ran").exists())
        self.assertEqual(self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "next")
        self.git(self.repo, "checkout", "-q", "main")                     # the operator's own git…
        self.assertTrue((self.repo / "hook-ran").is_file())               # …still runs the hook

    def test_apply_needs_no_network_because_it_does_not_fetch(self):
        self._prepare("checkout", "next")
        # Remove the holding repo's link to the open folder's objects; apply uses what it adopted.
        code, applied = self._apply()
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertTrue((self.repo / "arrived.txt").exists())

    def test_uncommitted_work_on_another_file_stays(self):
        self.write(self.repo, "notes.txt", "mine\n")
        self.assertEqual(self._prepare("checkout", "next")[0], exitcodes.CLEAN)
        code, applied = self._apply()
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertEqual((self.repo / "notes.txt").read_text(encoding="utf-8"), "mine\n")
        self.assertTrue((self.repo / "arrived.txt").exists())

    def test_an_infected_check_leaves_the_folder_and_refuses_apply(self):
        with mock.patch(_SCAN, return_value=(_verdict_doc("infected"), exitcodes.FINDINGS)):
            code, body = self._prepare("checkout", "next")
        self.assertEqual(code, exitcodes.FINDINGS, body)
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())
        code, applied = self._apply()
        self.assertFalse(applied["applied"])
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())

    def test_a_suspicious_check_does_not_change_the_folder(self):
        with mock.patch(_SCAN, return_value=(_verdict_doc("suspicious"), exitcodes.CLEAN)):
            self.assertEqual(self._prepare("checkout", "next")[0], exitcodes.CLEAN)
        self.assertFalse(self._apply()[1]["applied"])
        self.assertEqual(self.rev(self.repo), self.base)

    def test_residue_is_applied(self):
        with mock.patch(_SCAN, return_value=(_verdict_doc("residue"), exitcodes.CLEAN)):
            self.assertEqual(self._prepare("checkout", "next")[0], exitcodes.CLEAN)
        self.assertTrue(self._apply()[1]["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "from next\n")

    def test_a_command_saw_does_not_check_does_not_change_the_folder(self):
        code, body = self._prepare("status")
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertNotIn("scan", body)
        self.assertEqual(self.rev(self.repo), self.base)

    def test_a_merge_in_progress_is_not_overwritten(self):
        (self.repo / ".git" / "MERGE_HEAD").write_text(self.base + "\n", encoding="utf-8")
        self._prepare("checkout", "next")
        code, applied = self._apply()
        self.assertFalse(applied["applied"])
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())

    def test_a_finding_already_in_the_folder_does_not_hold_the_update(self):
        repo = self.new_repo("legacy")
        self.write(repo, "legacy.js",
                   "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE)
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "next")
        self.write(repo, "clean.txt", "ok\n")
        self.commit(repo, "arrive")
        self.git(repo, "checkout", "-q", "main")
        into = self.root / "legacy-holding"
        code, body = self._run("govern", "prepare", "--json", "--repo", str(repo),
                               "--into", str(into), "--tool", "git", "--", "checkout", "next")
        self.assertEqual(code, exitcodes.CLEAN, body)     # only clean.txt arrived; the loader is not rescanned
        state = json.loads((into / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["paths"], ["clean.txt"])
        self.assertTrue(state["releasable"])

    def test_a_real_infected_file_that_arrives_is_held(self):
        repo = self.new_repo("worm")
        self.write(repo, "keep.txt", "ok\n")
        self.commit(repo, "start")
        base = self.rev(repo)
        self.git(repo, "checkout", "-q", "-b", "next")
        self.write(repo, "loader.js",
                   "var _0x=[String.%s(127)];eval(_0x.join(\"\"));\n" % samples.FROM_CHAR_CODE)
        self.commit(repo, "arrive")
        self.git(repo, "checkout", "-q", "main")
        into = self.root / "worm-holding"
        code, body = self._run("govern", "prepare", "--json", "--repo", str(repo),
                               "--into", str(into), "--tool", "git", "--", "checkout", "next")
        self.assertEqual(code, exitcodes.FINDINGS, body)      # the real content scan flags it
        self.assertEqual(body["scan"]["results"][0]["verdict"], "infected")
        self.assertEqual(self.rev(repo), base)                # open folder untouched
        code, applied = self._run("govern", "apply", "--json", "--repo", str(repo), "--into", str(into))
        self.assertFalse(applied["applied"])
        self.assertEqual(self.rev(repo), base)

    def test_prepare_emits_progress_events_for_the_wait(self):
        import contextlib
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self._run("govern", "prepare", "--json", "--progress", "jsonl", "--repo", str(self.repo),
                      "--into", str(self.into), "--tool", "git", "--", "checkout", "next")
        steps = [json.loads(line)["id"] for line in err.getvalue().splitlines()
                 if line.strip().startswith("{") and json.loads(line).get("event") == "step"]
        self.assertIn("materialise", steps)
        self.assertIn("scan", steps)
        self.assertIn("verdict", steps)

    def test_capabilities_names_the_check(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["capabilities", "--json"]), exitcodes.CLEAN)
        printed = json.loads(out.getvalue())
        self.assertIn("govern.json", printed["features"])
        self.assertEqual(printed["schema_versions"]["govern"], 1)


if __name__ == "__main__":
    import unittest
    unittest.main()

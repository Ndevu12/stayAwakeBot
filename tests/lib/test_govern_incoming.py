#!/usr/bin/env python3
"""An incoming update is checked outside the open folder, and the folder changes only then."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.utils import exitcodes
from tests.support.gitrepo import GitSandbox


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
        hook.write_text("#!/bin/sh\ntouch \"$(dirname \"$0\")/../../hook-ran\"\n", encoding="utf-8")
        hook.chmod(0o755)

    def _run(self, args: list[str]) -> tuple[int, dict]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(args)
        return code, json.loads(out.getvalue())

    def test_a_checkout_is_checked_before_the_folder_changes(self):
        code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.CLEAN, body)
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())
        self.assertFalse((self.repo / "hook-ran").exists())
        self.assertEqual(body["schema_version"], 1)
        self.assertIn("scan", body)
        state = json.loads((self.into / "state.json").read_text(encoding="utf-8"))
        self.assertEqual(state["paths"], ["arrived.txt"])
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertTrue(applied["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "from next\n")
        self.assertEqual((self.repo / "keep.txt").read_text(encoding="utf-8"), "already\n")
        self.assertFalse((self.repo / "hook-ran").exists())
        self.assertEqual(self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "next")
        self.git(self.repo, "checkout", "-q", "main")
        self.assertTrue((self.repo / "hook-ran").is_file())

    def test_uncommitted_work_on_another_file_stays(self):
        self.write(self.repo, "notes.txt", "mine\n")
        code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.CLEAN, body)
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertEqual((self.repo / "notes.txt").read_text(encoding="utf-8"), "mine\n")
        self.assertTrue((self.repo / "arrived.txt").exists())

    def test_uncommitted_work_on_an_arriving_file_stays(self):
        self.write(self.repo, "arrived.txt", "mine\n")
        self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                   "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertEqual(code, exitcodes.CLEAN, applied)
        self.assertTrue(applied["applied"])
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "mine\n")
        self.assertEqual(self.git(self.repo, "rev-parse", "--abbrev-ref", "HEAD").strip(), "next")

    def test_a_merge_in_progress_is_not_overwritten(self):
        (self.repo / ".git" / "MERGE_HEAD").write_text(self.base + "\n", encoding="utf-8")
        self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                   "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertFalse(applied["applied"])
        self.assertNotEqual(code, exitcodes.CLEAN)
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())
        self.assertTrue((self.repo / ".git" / "MERGE_HEAD").is_file())

    def test_a_check_that_is_not_clean_does_not_change_the_folder(self):
        infected = {"generated_at": "t", "results": [{"target": "x", "verdict": "infected",
                                                      "findings": [], "advisories": [], "notes": []}]}
        with mock.patch("stayawake.cli.commands.govern.scan_arrived", return_value=(infected, exitcodes.FINDINGS)):
            code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                    "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.FINDINGS, body)
        self.assertEqual(self.rev(self.repo), self.base)
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertFalse(applied["applied"])
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())

    def test_a_suspicious_check_does_not_change_the_folder(self):
        suspicious = {"generated_at": "t", "results": [{"target": "x", "verdict": "suspicious",
                                                        "findings": [], "advisories": [], "notes": []}]}
        with mock.patch("stayawake.cli.commands.govern.scan_arrived",
                        return_value=(suspicious, exitcodes.CLEAN)):
            code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                    "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.CLEAN, body)
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertFalse(applied["applied"])
        self.assertEqual(self.rev(self.repo), self.base)
        self.assertFalse((self.repo / "arrived.txt").exists())

    def test_residue_is_applied(self):
        residue = {"generated_at": "t", "results": [{"target": "x", "verdict": "residue",
                                                     "findings": [], "advisories": [], "notes": []}]}
        with mock.patch("stayawake.cli.commands.govern.scan_arrived",
                        return_value=(residue, exitcodes.CLEAN)):
            code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                    "--into", str(self.into), "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.CLEAN, body)
        code, applied = self._run(["govern", "apply", "--json", "--repo", str(self.repo),
                                   "--into", str(self.into)])
        self.assertTrue(applied["applied"], applied)
        self.assertEqual((self.repo / "arrived.txt").read_text(encoding="utf-8"), "from next\n")

    def test_a_command_saw_does_not_check_does_not_change_the_folder(self):
        code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                "--into", str(self.into), "--tool", "git", "--", "status"])
        self.assertEqual(code, exitcodes.INCOMPLETE)
        self.assertNotIn("scan", body)
        self.assertEqual(self.rev(self.repo), self.base)

    def test_the_check_reads_the_operator_config(self):
        config = self.root / "operator.yml"
        config.write_text("allowlist: []\n", encoding="utf-8")
        from stayawake.bots.security import incoming as incoming_scan
        seen: list[str | None] = []
        real = incoming_scan.operator_policy

        def wrapped(path):
            seen.append(path)
            return real(path)

        with mock.patch.object(incoming_scan, "operator_policy", wrapped):
            code, body = self._run(["govern", "prepare", "--json", "--repo", str(self.repo),
                                    "--into", str(self.into), "-c", str(config),
                                    "--tool", "git", "--", "checkout", "next"])
        self.assertEqual(code, exitcodes.CLEAN, body)
        self.assertEqual(seen, [str(config)])
        self.assertEqual(self.rev(self.repo), self.base)

    def test_capabilities_names_the_check(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(["capabilities", "--json"]), exitcodes.CLEAN)
        printed = json.loads(out.getvalue())
        self.assertIn("govern.json", printed["features"])
        self.assertEqual(printed["schema_versions"]["govern"], 1)

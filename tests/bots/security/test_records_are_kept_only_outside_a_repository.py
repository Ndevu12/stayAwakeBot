#!/usr/bin/env python3
"""saw reads and writes the records in its cache folder only while that folder lies outside every git
repository, and says it keeps none once per run on a skipped write and in `saw doctor` and
`saw govern status`."""
from __future__ import annotations

import io
import json
import os
import re
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake import cli
from stayawake.bots.security import (clean_contents, clean_ledger, hook, hookscript, push_record,
                                     records)
from tests.support.gitrepo import GitSandbox

_SOURCE = Path(__file__).resolve().parents[3] / "src" / "stayawake"
_FINDING = SimpleNamespace(signature_id="s", path="a.js", line=1, commit_sha="", confidence="confirmed")


class _Records(GitSandbox):
    """A checkout and a record folder holding a record of every kind saw keeps, written as saw writes
    them."""

    def cache(self) -> Path:
        return self.root / "cache-elsewhere"

    def setUp(self):
        super().setUp()
        records._told.clear()
        records._inside_a_repository.cache_clear()
        self.addCleanup(records._inside_a_repository.cache_clear)
        self.repo = self.new_repo("checkout")
        self.write(self.repo, "a.txt", "a\n")
        self.head = self.commit(self.repo, "start")
        moved = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.cache())})
        moved.start()
        self.addCleanup(moved.stop)
        self.root_key = os.path.realpath(self.repo)
        self.key = clean_ledger.clean_key(self.head, None)
        self.policy = clean_ledger.policy_digest(None)
        self.store = clean_contents.store_path(self.repo)
        self.pushed = push_record.record_path(self.repo / ".git")
        forged = {
            hookscript.cache_path(): {self.root_key: self.key},
            hookscript.settings_scan_path(): {self.root_key: self.key},
            clean_ledger.applied_path(): {self.root_key: self.key},
            clean_ledger.accepted_path(): {self.root_key: {"commit": self.head, "verdict": "infected"}},
            clean_ledger.let_in_blobs_path(): {self.root_key: {"policy": self.policy,
                                                                "blobs": [["a.txt", "100644", "0" * 40]]}},
            hookscript.history_checked_path(): {self.root_key: self.key},
            hookscript.warnings_shown_path(): {self.root_key: {"operation": "pull", "at": 0, "shown": ["x"]}},
            hookscript.checks_made_path(): {self.root_key: {"operation": "pull", "at": 0, "outcome": 0}},
            self.store: {"version": 1, "policy": self.policy, "clean": {"a.txt": "digest"}},
            self.pushed: {"policy": self.policy, "verified": ["v"], "pending": [], "unlisted": []},
        }
        for where, body in forged.items():
            where.parent.mkdir(parents=True, exist_ok=True)
            where.write_text(json.dumps(body), encoding="utf-8")
        self.folder = records.folder()

    def listing(self) -> dict:
        return {str(path.relative_to(self.folder)): path.read_bytes()
                for path in sorted(self.folder.rglob("*")) if path.is_file()}

    def read_by_saw(self) -> dict:
        return {
            "hook-scan-cache": (clean_ledger.scanned_clean(self.repo, self.key), hookscript.seeded_repositories()),
            "hook-settings-scans": clean_ledger.settings_scans(),
            "govern-applied": clean_ledger.let_in_commit(self.repo, None),
            "govern-accepted": clean_ledger.accepted_verdict(self.repo, self.head),
            "govern-let-in-blobs": clean_ledger.blobs_let_in(self.repo, None),
            "hook-history-checked": hook._history_checked(self.repo, None),
            "hook-warnings-shown": hook._warnings_shown(),
            "hook-checks-made": hook._checks_made(),
            "hook-clean-contents": clean_contents.held(self.repo, self.policy),
            "push-record": push_record.load(self.repo / ".git", self.policy).verified,
        }

    def write_by_saw(self) -> None:
        clean_ledger.remember(self.repo, self.key)
        hook._remember_repositories([self.repo])
        clean_ledger.remember_settings_scan(self.repo, self.key)
        clean_ledger.remember_applied(self.repo, self.key)
        clean_ledger.remember_accepted(self.repo, self.head, "clean")
        clean_ledger.remember_blobs(self.repo, [["b.txt", "100644", "1" * 40]], self.policy)
        hook._remember_history(self.repo, self.head, None)
        hook._warn_once(self.repo, "fetch", [_FINDING], lambda _new: None)
        hook._record_outcome(self.repo, "fetch", 0)
        clean_contents.remember(self.repo, clean_contents.Checked({}), self.policy)
        record = push_record.load(self.repo / ".git", self.policy)
        record.mark_verified("b.txt", "1" * 40)
        record.save()


class EveryRecordIsReadAndWrittenOutsideARepository(_Records):

    def test_saw_reads_each_record_it_keeps(self):
        read = self.read_by_saw()
        self.assertEqual([name for name, found in read.items() if not found or found == (False, [])], [])

    def test_saw_writes_each_record_it_keeps(self):
        kept = sorted(self.listing())
        shutil.rmtree(self.folder)
        self.write_by_saw()
        self.assertEqual(sorted(self.listing()), kept)

    def test_forgetting_saws_hooks_removes_the_list_of_repositories(self):
        hookscript.forget()
        self.assertFalse(hookscript.cache_path().exists())


class NoRecordIsReadOrWrittenInsideARepository(_Records):

    def cache(self) -> Path:
        return self.root / "checkout" / "cache"

    def said(self) -> str:
        return (f"saw keeps no records: its cache folder {self.folder} is inside a git repository. Set "
                "XDG_CACHE_HOME to a folder outside it.")

    def test_saw_reads_no_record_it_keeps(self):
        read = self.read_by_saw()
        self.assertEqual({name: found for name, found in read.items() if found and found != (False, [])}, {})

    def test_saw_writes_no_record_and_says_so_once(self):
        before = self.listing()
        err = io.StringIO()
        with redirect_stderr(err):
            self.write_by_saw()
            hookscript.forget()
            self.assertEqual(self.listing(), before)
            shutil.rmtree(self.folder)
            self.write_by_saw()
        self.assertFalse(self.folder.exists())
        said = " ".join(err.getvalue().split())
        self.assertEqual(said.count("saw keeps no records"), 1, said)
        self.assertIn(self.said(), said)

    def test_saw_doctor_says_saw_keeps_no_records(self):
        with mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                cli.main(["doctor", "--json"])
            self.assertFalse(json.loads(out.getvalue())["records_kept"])
            for argv in (["doctor", "--no-stream"], ["doctor", "-q", "--no-stream"]):
                out = io.StringIO()
                with self.subTest(argv=argv), redirect_stdout(out), redirect_stderr(io.StringIO()):
                    cli.main(argv)
                self.assertIn(self.said(), " ".join(out.getvalue().split()))

    def test_saw_govern_status_says_saw_keeps_no_records(self):
        out = io.StringIO()
        with mock.patch("stayawake.cli.commands.govern.standin_binary", return_value=None), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            cli.main(["govern", "status"])
        self.assertIn(self.said(), " ".join(out.getvalue().split()))


class EveryRecordPathComesFromTheRecordFolder(GitSandbox):

    def test_only_the_record_folder_names_the_cache_folder(self):
        naming = sorted(str(path.relative_to(_SOURCE)) for path in _SOURCE.rglob("*.py")
                        if re.search(r"\bxdg_cache_home\(", path.read_text(encoding="utf-8")))
        self.assertEqual(naming, ["bots/security/records.py", "utils/env.py"])

    def test_saw_doctor_and_govern_status_say_nothing_while_records_are_kept(self):
        with mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                cli.main(["doctor", "--json"])
        self.assertTrue(json.loads(out.getvalue())["records_kept"])
        out = io.StringIO()
        with mock.patch("stayawake.cli.commands.govern.standin_binary", return_value=None), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            cli.main(["govern", "status"])
        self.assertNotIn("saw keeps no records", out.getvalue())


if __name__ == "__main__":
    import unittest
    unittest.main()

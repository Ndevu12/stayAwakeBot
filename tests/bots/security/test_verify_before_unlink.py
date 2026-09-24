#!/usr/bin/env python3
"""A file is read again, at the moment of the act, before it is unlinked."""
from __future__ import annotations

import unittest
from pathlib import Path

from stayawake.bots.security.remediation import changes as ch
from stayawake.bots.security.remediation.oracle import (ABSENT, CARRIES, CHANGED, REFUSED,
                                                        UNREADABLE,
                                                        still_condemned)
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.scratchroot import OwnTempRoot

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
GENUINE_FONT = b"wOFF\x00\x01\x00\x00genuine third-party font bytes\n"


class _Tree(OwnTempRoot):
    def setUp(self):
        super().setUp()
        self.root = (self.tmp / "tree").resolve()
        self.rollback = (self.tmp / "rollback").resolve()
        self.root.mkdir()
        self.rollback.mkdir()

    def _check(self):
        return still_condemned(self.root, load_signatures(), [], ScanOptions())

    def _write(self, rel, body):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body)
        return path


class TestWhatTheVerifierSays(_Tree):
    def test_it_answers_carries_for_a_payload(self):
        self._write("public/fonts/text.woff", LOADER)
        self.assertEqual(CARRIES, self._check()("public/fonts/text.woff"))

    def test_it_answers_changed_for_a_clean_file(self):
        self._write("public/fonts/text.woff", GENUINE_FONT)
        self.assertEqual(CHANGED, self._check()("public/fonts/text.woff"))

    def test_it_answers_absent_when_the_path_is_gone(self):
        self.assertEqual(ABSENT, self._check()("gone.js"))

    def test_it_answers_unreadable_when_it_cannot_read(self):
        self._write("locked/payload.js", LOADER)
        (self.root / "locked").chmod(0o000)
        self.addCleanup((self.root / "locked").chmod, 0o700)
        self.assertEqual(UNREADABLE, self._check()("locked/payload.js"))


class TestApplyAsksAgain(_Tree):
    """Check what is removed and what is left."""

    def test_a_payload_is_removed(self):
        target = self._write("public/fonts/text.woff", LOADER)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                        self.rollback, condemned=self._check())
        self.assertFalse(target.exists())
        self.assertEqual(1, len(done))

    def test_only_what_the_plan_names_is_removed(self):
        self._write("public/fonts/text.woff", LOADER)
        beside = self._write("public/fonts/real.woff", GENUINE_FONT)
        ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                 self.rollback, condemned=self._check())
        self.assertTrue(beside.exists())
        self.assertEqual(GENUINE_FONT, beside.read_bytes())

    def test_a_path_rewritten_after_the_scan_is_still_removed(self):
        target = self._write("public/fonts/text.woff", GENUINE_FONT)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                        self.rollback, condemned=self._check())
        self.assertFalse(target.exists())
        self.assertEqual(1, len(done))

    def test_a_run_over_an_unreadable_file_removes_nothing(self):
        self._write("public/fonts/text.woff", LOADER)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                        self.rollback, condemned=lambda _p: UNREADABLE)
        self.assertTrue((self.root / "public/fonts/text.woff").exists())
        self.assertEqual([], done)

    def test_it_removes_without_a_check(self):
        target = self._write("public/fonts/text.woff", GENUINE_FONT)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")], self.rollback)
        self.assertFalse(target.exists())
        self.assertEqual(1, len(done))


class TestARepairThatChangedNothingIsNotDone(_Tree):
    """Check what `apply` says when a repair leaves the file as it was."""

    def _run(self, body: str):
        self._write(".gitignore", body)
        skips = []
        done = ch.apply(self.root, [ch.Change("strip-gitignore", ".gitignore")],
                        self.rollback, condemned=self._check(),
                        on_skip=lambda path, reason: skips.append((path, reason)))
        return done, skips

    def test_it_is_not_counted_as_applied(self):
        done, _ = self._run("node_modules/\n.env\n")
        self.assertEqual([], done)

    def test_the_caller_is_told(self):
        _, skips = self._run("node_modules/\n.env\n")
        self.assertEqual([(".gitignore", REFUSED)], skips)

    def test_a_file_that_is_gone_is_told_apart(self):
        skips = []
        ch.apply(self.root, [ch.Change("strip-gitignore", ".gitignore")], self.rollback,
                 condemned=self._check(), on_skip=lambda path, reason: skips.append((path, reason)))
        self.assertEqual([(".gitignore", ABSENT)], skips)


if __name__ == "__main__":
    unittest.main()

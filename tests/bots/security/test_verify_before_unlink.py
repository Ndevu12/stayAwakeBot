#!/usr/bin/env python3
"""A file is read again, at the moment of the act, before it is unlinked."""
from __future__ import annotations

import unittest
from pathlib import Path

from stayawake.bots.security.remediation import changes as ch
from stayawake.bots.security.remediation.oracle import (CARRIES, CHANGED, UNREADABLE,
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

    def test_it_answers_unreadable_when_it_cannot_read(self):
        self.assertEqual(UNREADABLE, self._check()("gone.js"))


class TestApplyAsksAgain(_Tree):
    """Check what is removed and what is left."""

    def test_a_payload_is_removed(self):
        target = self._write("public/fonts/text.woff", LOADER)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                        self.rollback, condemned=self._check())
        self.assertFalse(target.exists())
        self.assertEqual(1, len(done))

    def test_only_a_payload_is_removed(self):
        target = self._write("public/fonts/text.woff", GENUINE_FONT)
        done = ch.apply(self.root, [ch.Change("remove", "public/fonts/text.woff")],
                        self.rollback, condemned=self._check())
        self.assertTrue(target.exists())
        self.assertEqual(GENUINE_FONT, target.read_bytes())
        self.assertEqual([], done)

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


if __name__ == "__main__":
    unittest.main()

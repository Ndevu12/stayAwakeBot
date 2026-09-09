#!/usr/bin/env python3
"""The record of what this machine has seen running.

It exists so a run can tell a thing it has seen before from a thing it has not. It must never be
able to tell a run that something is fine."""
from __future__ import annotations

import ast
import json
import os
import pathlib
import tempfile
import unittest

from stayawake.bots.security import liveledger as ledger
from stayawake.bots.security.livecode import LiveCode
from stayawake.utils.procsnap import Process


def _seen(code="payload", confirmed=True, reason="identified"):
    return [LiveCode(Process(pid=1, argv=("node", "-e", code)), code, reason, confirmed)]


class TestNothingHereCanLaunderAnything(unittest.TestCase):
    """The load-bearing property. Every other test in this file is about convenience; this one is
    about whether an attacker who can write the state directory can buy silence."""

    def test_the_detection_path_does_not_consult_the_record(self):
        root = pathlib.Path(__file__).resolve().parents[3] / "src/stayawake"
        for rel in ("bots/security/livecode.py", "bots/security/harden/live.py"):
            tree = ast.parse((root / rel).read_text(encoding="utf-8"))
            names = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.ImportFrom):
                    names.add(n.module or "")
                    names |= {a.name for a in n.names}     # `from <pkg> import liveledger`
                elif isinstance(n, ast.Import):
                    names |= {a.name for a in n.names}
            with self.subTest(module=rel):
                self.assertFalse(any("liveledger" in n for n in names),
                                 f"{rel} must decide from the machine, never from the record")

    def test_an_edited_record_claims_no_history(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            ledger.save(ledger.record(ledger.load(p), _seen()), p)
            key = list(ledger.load(p).entries)[0]
            p.write_text(p.read_text().replace('"times": 1', '"times": 99'))
            edited = ledger.load(p)
            self.assertEqual(edited.status, ledger.EDITED)
            self.assertFalse(edited.trusted)
            self.assertEqual(edited.returning(key), 0)

    def test_a_corrupt_record_claims_no_history(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            p.write_text("{not json")
            self.assertEqual(ledger.load(p).status, ledger.CORRUPT)
            self.assertFalse(ledger.load(p).trusted)

    def test_a_record_that_cannot_be_READ_claims_no_history(self):
        # A different branch from malformed JSON, and the one an attacker reaches by making the
        # file unreadable rather than by editing it.
        with tempfile.TemporaryDirectory() as d:
            not_a_file = pathlib.Path(d) / "live.json"
            not_a_file.mkdir()
            self.assertEqual(ledger.load(not_a_file).status, ledger.CORRUPT)
            self.assertFalse(ledger.load(not_a_file).trusted)

    def test_an_absent_record_claims_no_history(self):
        with tempfile.TemporaryDirectory() as d:
            absent = ledger.load(pathlib.Path(d) / "nothing.json")
            self.assertEqual(absent.status, ledger.ABSENT)
            self.assertEqual(absent.returning("anything"), 0)


class TestItNeverKeepsThePayload(unittest.TestCase):
    def test_the_code_itself_is_not_written(self):
        secret = "const TOKEN='ghp_" + "notarealtoken" + "';run(TOKEN)"
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            ledger.save(ledger.record(ledger.load(p), _seen(code=secret)), p)
            written = p.read_text()
            self.assertNotIn("ghp_", written)
            self.assertNotIn("TOKEN", written)

    def test_the_record_itself_never_holds_the_code(self):
        # Asked of the structure, not of the file: if `record` ever kept the code, `save` would
        # have something to write and the test above would be the only thing standing in the way.
        import dataclasses
        secret = "const TOKEN='ghp_" + "notarealtoken" + "'"
        led = ledger.record(ledger.Ledger(), _seen(code=secret))
        for entry in led.entries.values():
            for f in dataclasses.fields(entry):
                self.assertNotIn(secret, str(getattr(entry, f.name)))

    def test_the_file_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            ledger.save(ledger.record(ledger.load(p), _seen()), p)
            self.assertEqual(os.stat(p).st_mode & 0o077, 0)

    def test_a_symlinked_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            elsewhere = pathlib.Path(d) / "elsewhere"
            elsewhere.write_text("untouched")
            p = pathlib.Path(d) / "live.json"
            p.symlink_to(elsewhere)
            self.assertFalse(ledger.save(ledger.record(ledger.load(p), _seen()), p))
            self.assertEqual(elsewhere.read_text(), "untouched")


class TestItAnswersWhetherSomethingCameBack(unittest.TestCase):
    def test_a_second_sighting_counts(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            ledger.save(ledger.record(ledger.load(p), _seen()), p)
            first = ledger.load(p)
            key = list(first.entries)[0]
            self.assertEqual(first.returning(key), 1)
            ledger.save(ledger.record(first, _seen()), p)
            self.assertEqual(ledger.load(p).returning(key), 2)

    def test_what_was_ended_is_remembered_apart_from_what_was_seen(self):
        from stayawake.bots.security.livecode import fingerprint
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            key = fingerprint("payload")
            ledger.save(ledger.record(ledger.load(p), _seen(), ended_keys={key}), p)
            self.assertEqual(ledger.load(p).entries[key].ended, 1)

    def test_it_does_not_grow_without_limit(self):
        # Someone who can start processes chooses how many distinct payloads this machine sees.
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "live.json"
            many = [LiveCode(Process(pid=i, argv=("node", "-e", f"p{i}")), f"p{i}", "shape", False)
                    for i in range(ledger._MAX_ENTRIES + 200)]
            ledger.save(ledger.record(ledger.load(p), many), p)
            self.assertLessEqual(len(ledger.load(p).entries), ledger._MAX_ENTRIES)


if __name__ == "__main__":
    unittest.main()

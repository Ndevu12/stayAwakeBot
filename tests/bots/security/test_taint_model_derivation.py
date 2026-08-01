#!/usr/bin/env python3
"""Pin that `taint.flow`'s call-name regexes stay DERIVED from `taint.model`'s frozensets — one
source of truth for the decode→exec taxonomy — and that the derivation matches exactly the shapes
the hand-written literals used to (no coverage drift when the fold made `model` authoritative).

If someone edits `model.DECODE_CALLS` / `model.CP_RUNNERS`, the derived regexes change with them;
these tests fix the *contract* of that derivation (call context + boundary + near-miss rejection),
so a genuine taxonomy change is deliberate and a typo in `_name_alt` is caught.
"""
from __future__ import annotations

import re
import unittest

from stayawake.bots.security.taint import flow, model


class TestNameAltDerivation(unittest.TestCase):
    def test_decode_matches_model_calls_in_call_context(self):
        rx = re.compile(flow._DECODE, re.IGNORECASE)
        # every DECODE_CALL, as it appears in source (dotted parts, optional whitespace), matches
        for name in model.DECODE_CALLS:
            spaced = " . ".join(name.split(".")) if "." in name else name
            self.assertTrue(rx.match(f"{name}(x)"), name)
            self.assertTrue(rx.match(f"{spaced} ( x )"), spaced)
        # near-misses must NOT match at position 0
        for bad in ("atobX(", "Buffered.from(", "Buffer.fromCharCode(", "decode("):
            self.assertIsNone(rx.match(bad), bad)

    def test_cp_runners_is_model_minus_bare_exec(self):
        rx = re.compile(flow._CP_RUNNERS + r"\s*\(", re.IGNORECASE)
        for name in model.CP_RUNNERS - {"exec"}:
            self.assertTrue(rx.match(f"{name}("), name)
        # bare `exec(` is deliberately excluded (regex.exec collision), so it must NOT match
        self.assertIsNone(rx.match("exec("))
        # a longer name is never masked by a prefix (execFileSync, not execFile+`Sync`)
        m = rx.match("execFileSync(")
        self.assertEqual(m.group(0), "execFileSync(")

    def test_cp_method_is_full_model_set(self):
        rx = re.compile(flow._CP_METHOD + r"\s*\(", re.IGNORECASE)
        for name in model.CP_RUNNERS:
            self.assertTrue(rx.match(f"{name}("), name)
        # prefix safety: spawnSync wins over spawn; execFileSync over execFile/exec
        self.assertEqual(rx.match("spawnSync(").group(0), "spawnSync(")
        self.assertEqual(rx.match("execFileSync(").group(0), "execFileSync(")

    def test_longest_first_ordering(self):
        # _name_alt must emit longest-first so a prefix never shadows a longer name.
        alt = flow._name_alt({"exec", "execSync", "execFileSync", "execFile"})
        names = alt[3:-1].split("|")  # strip "(?:" ... ")"
        self.assertEqual(names, sorted(names, key=len, reverse=True))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A file whose bytes contradict its extension is confirmed malware on three independent grounds:
its content is a loader fingerprint, its name claims a known asset it cannot be, or something in
the scan runs it. A weak text shape under a generic name that nothing runs is reported as
suspicious, never asserted as malware — the shape a genuine binary can share by coincidence."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.matchers.base import executed_font_paths
from stayawake.bots.security.models import CONFIRMED, HEURISTIC
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

LOADER_FINGERPRINT = "global['_V'] = function(x){ return x };\n" + ("// body " * 40)
TEXT_NO_FINGERPRINT = "var a = 1;\n" + ("function noop(){ return a; }\n" * 30)
GENUINE = b"wOF2\x00\x01\x00\x00" + bytes(400)


def _scan(fname: str, content, *, runs: str | None = None):
    root = Path(tempfile.mkdtemp())
    (root / "public" / "fonts").mkdir(parents=True)
    f = root / "public" / "fonts" / fname
    f.write_text(content) if isinstance(content, str) else f.write_bytes(content)
    if runs is not None:
        (root / ".vscode").mkdir()
        (root / ".vscode" / "tasks.json").write_text(json.dumps(
            {"version": "2.0.0", "tasks": [{"label": "t", "type": "shell",
             "command": runs, "runOptions": {"runOn": "folderOpen"}}]}))
    res = scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures())
    return {x.path: x for x in res.findings}


def _font(fname):
    return f"public/fonts/{fname}"


class ADisguisedFileIsConfirmedOnThreeGrounds(unittest.TestCase):
    def test_content_that_is_a_loader_fingerprint_confirms_with_no_caller(self):
        f = _scan("misc.woff2", LOADER_FINGERPRINT)[_font("misc.woff2")]
        self.assertEqual(f.confidence, CONFIRMED)

    def test_a_name_claiming_a_known_asset_confirms_with_no_caller(self):
        f = _scan("fa-solid-500.woff2", TEXT_NO_FINGERPRINT)[_font("fa-solid-500.woff2")]
        self.assertEqual(f.confidence, CONFIRMED)

    def test_a_generic_disguise_that_something_runs_confirms(self):
        f = _scan("misc.woff2", TEXT_NO_FINGERPRINT,
                  runs="node ./public/fonts/misc.woff2")[_font("misc.woff2")]
        self.assertEqual(f.confidence, CONFIRMED)

    def test_a_generic_disguise_that_nothing_corroborates_is_only_heuristic(self):
        f = _scan("misc.woff2", TEXT_NO_FINGERPRINT)[_font("misc.woff2")]
        self.assertEqual(f.signature_id, "fake-font-text-woff")
        self.assertEqual(f.confidence, HEURISTIC)

    def test_it_is_still_reported_either_way(self):
        self.assertIn(_font("misc.woff2"), _scan("misc.woff2", TEXT_NO_FINGERPRINT))

    def test_a_genuine_font_is_never_flagged(self):
        self.assertNotIn(_font("real.woff2"), _scan("real.woff2", GENUINE))

    def test_a_name_alone_does_not_confirm_binary_that_only_coincidentally_trips(self):
        # A real font mis-named as a known asset (magic mismatch, binary body) must not be confirmed
        # by the name: the naming leg requires the body to read as text.
        binary_with_token = b"\x00\x01\x02\x03" + b"=>" + bytes(range(4, 200))
        got = _scan("fa-brands-400.otf", binary_with_token).get(_font("fa-brands-400.otf"))
        if got is not None:
            self.assertEqual(got.confidence, HEURISTIC)

    def test_a_generic_exec_sink_dropper_confirms_with_no_caller_or_known_name(self):
        dropper = ("const x = new Function(atob('cmV0dXJuIDE='));\n"
                   "require('child_process').exec('id');\n" + "// pad " * 40)
        f = _scan("webfont.woff2", dropper)[_font("webfont.woff2")]
        self.assertEqual(f.confidence, CONFIRMED)

    def test_an_oversized_disguised_payload_is_still_read_and_confirmed(self):
        # A fingerprint past the general size cap must still be read via the confirmed-tier reader,
        # not silently fail open to heuristic.
        payload = "String.fromCharCode(127)\n" + "// pad " * 20 + "x" * 2_000_050
        f = _scan("big.woff2", payload)[_font("big.woff2")]
        self.assertEqual(f.confidence, CONFIRMED)

    def test_the_compound_command_resolves_the_executed_path(self):
        self.assertEqual(
            executed_font_paths("(command -v node && node ./public/fonts/misc.woff2) || echo ''"),
            ("public/fonts/misc.woff2",))
        self.assertEqual(executed_font_paths("eslint . --fix"), ())


if __name__ == "__main__":
    unittest.main()

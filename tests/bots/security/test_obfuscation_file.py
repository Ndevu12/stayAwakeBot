#!/usr/bin/env python3
"""G4 regression: line-AGNOSTIC whole-file obfuscation detection.

A payload SPLIT/WRAPPED across many <2000-char lines, or living in a non-.js
extension (.jsx/.tsx/.vue/.svelte), defeats the formatting-keyed long-line rule.
The `obfuscation` matcher / `analyze_file` must still catch it on RAW content, while
context-scoping keeps vendored/minified/generated paths and legit dense source clean.
"""
from __future__ import annotations

import random
import tempfile
import textwrap
import unittest
from pathlib import Path

from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.bots.security.obfuscation import (
    analyze_file, is_generated_context, _GENERATED_PATH,
)

SIGS = load_signatures()
OBF = "obfuscated-source-file"


def _scan(files: dict[str, str]) -> set[str]:
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    t = LocalRepoTarget(d, "t", ScanOptions())
    return {f.signature_id for f in scan_target(t, SIGS, []).findings}


class TestWholeFileObfuscation(unittest.TestCase):
    # ── True positives: the split-line / non-.js payloads G4 named ──────────────
    def test_split_charcode_array_in_ts(self):
        arr = "[" + ",".join(["0x68"] * 40) + "]"
        wrapped = "\n".join(textwrap.wrap("const d=String.fromCharCode.apply(0," + arr + ");", 60))
        self.assertIn(OBF, _scan({"x.ts": "const a=1;\n" + wrapped}))

    def test_wrapped_loader_in_jsx(self):
        packed = "\n".join("var p" + str(i) + "=" + ("z" * 110) + ";" for i in range(40))
        body = "import React from 'react'\nvar _$_1e42='seed';\n" + packed
        self.assertIn(OBF, _scan({"C.jsx": body}))

    def test_split_base64_blob_in_vue_without_fingerprint(self):
        random.seed(1)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(8000))
        chunks = "\n".join(blob[i:i + 150] for i in range(0, len(blob), 150))
        self.assertIn(OBF, _scan({"App.vue": "<script>\nconst x=`\n" + chunks + "\n`\n</script>"}))

    def test_eval_atob_in_svelte(self):
        body = "<script>\n" + "const y=" + ("q" * 450) + ";\n" * 6 + "eval(atob(y));\n</script>"
        self.assertIn(OBF, _scan({"P.svelte": body}))

    def test_loader_line_just_under_long_line_threshold(self):
        # <2000 chars on every line, so the formatting-keyed rule never fires.
        line = "export default {plugins:[" + "0," * 900 + "]};var _$_ab='x';function sfL(w){return w}"
        self.assertLess(max(len(l) for l in line.splitlines()), 2000)
        self.assertIn(OBF, _scan({"postcss.config.mjs": line}))

    # ── False positives: legit dense source / vendored context stays clean ──────
    def test_normal_big_component_clean(self):
        body = "import React from 'react';\n" + "\n".join(
            f"export function C{i}(p){{return <div className='w-{i}'>Hi {{p.n}} item {i} ok</div>;}}"
            for i in range(200))
        self.assertNotIn(OBF, _scan({"Big.jsx": body}))

    def test_long_prose_template_constant_clean(self):
        words = " ".join(["the quick brown fox jumps over the lazy dog"] * 300)
        self.assertNotIn(OBF, _scan({"text.js": "export const T = `" + words + "`;\n"}))

    def test_inlined_data_uri_asset_clean(self):
        uri = "export const logo='data:image/png;base64," + ("AB" * 400) + "';\n"
        self.assertNotIn(OBF, _scan({"assets.ts": uri}))

    def test_low_entropy_long_array_clean(self):
        self.assertNotIn(OBF, _scan({"postcss.config.mjs": "export default {p:[" + "0," * 900 + "]};\n"}))

    def test_vendored_and_generated_paths_suppressed(self):
        arr = "var a=[" + ",".join(["0x68"] * 40) + "];String.fromCharCode(127)"
        for path in ("lib/app.min.js", ".pnp.cjs", ".yarn/releases/yarn.cjs",
                     "dist/main.js", "src/gql.generated.ts", "proto/__generated__/x.pb.js"):
            self.assertNotIn(OBF, _scan({path: arr}), f"{path} should be suppressed (generated context)")

    # ── The shared context predicate (regression for the mid-path anchor bug) ───
    def test_generated_context_matches_mid_path_filename_tokens(self):
        for p in ("src/gql.generated.ts", "a/app.min.js", "x/y.pb.js", "z/q.graphql.ts", "out/b.map"):
            self.assertTrue(is_generated_context(p), p)
        for p in ("src/index.ts", "postcss.config.mjs", "components/App.jsx"):
            self.assertFalse(is_generated_context(p), p)

    # ── analyze_file is line-agnostic (no single long line needed) ──────────────
    def test_analyze_file_catches_wrapped_exec_sink(self):
        self.assertTrue(analyze_file("const a=1\neval(\n  atob('x')\n)\n", ".js"))

    def test_analyze_file_clean_on_ordinary_code(self):
        code = "function add(a, b) {\n    return a + b;\n}\nexport default add;\n"
        self.assertFalse(analyze_file(code, ".js"))


if __name__ == "__main__":
    unittest.main()

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

    def test_mutated_loader_caught_via_constructor_exec(self):
        # #1053 durability: a re-obfuscated variant renames EVERY literal fingerprint
        # (no _$_, no sfL, no global['!'], no fromCharCode, no numeric array) and keeps
        # every line short + low-density, so neither a loader content signature nor the
        # packed/entropy heuristic can fire. The ONLY thing left to catch it is the
        # structural exec-via-constructor sink — the name-agnostic Function-constructor
        # smuggling (`dec['constructor'](...)`) the worm family cannot rename away.
        variant = "\n".join([
            "const cfg = { plugins: ['@tailwindcss/postcss'] };",
            "export default cfg;",
            "const seed = 'inert';",
            "const dec = function (w) { return w; };",
            "const run = dec['constructor']('return 1');",
            "run();",
        ])
        self.assertLess(max(len(l) for l in variant.splitlines()), 400)
        self.assertIn(OBF, _scan({"postcss.config.mjs": variant}))

    def test_wrapped_constructor_exec_caught(self):
        # The exec sink wrapped across a line break is still caught.
        self.assertTrue(
            analyze_file("var q=function(){};\nq['constructor']\n('return 3')();\n", ".js"))

    def test_chunked_base64_blob_reassembled(self):
        # #1053 Tier-2 (signal A): a base64 payload split into short quoted chunks joined
        # by `+` and WRAPPED to <400-char lines dodges the long-line + unbroken-run blob
        # detectors. De-chunking the concat seams reassembles the blob and catches it.
        random.seed(11)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(900))
        chunks = " +\n  ".join('"%s"' % blob[i:i + 60] for i in range(0, len(blob), 60))
        src = "const cfg = {};\nexport default cfg;\nconst b =\n  " + chunks + ";\n"
        self.assertLess(max(len(l) for l in src.splitlines()), 400)  # evades old Tier-2
        self.assertIn(OBF, _scan({"postcss.config.mjs": src}))

    def test_escape_encoded_payload_flagged(self):
        # #1053 Tier-2 (signal B): a payload written as a dense run of \xNN escapes carries
        # no base64/charcode-array tell, but a long contiguous run of high-entropy BYTE
        # escapes is an encoded blob. 64 bytes spread over 0-255 clears the 48-run length
        # bar AND the byte-range + entropy gate.
        esc = "".join("\\x%02x" % ((i * 7 + 3) % 256) for i in range(64))
        src = 'const s = "' + esc + '";\nexport default s;\n'
        self.assertLess(max(len(l) for l in src.splitlines()), 400)
        self.assertIn(OBF, _scan({"x.js": src}))

    def test_chunked_escape_payload_reassembled(self):
        # A+B together: escapes split across concat chunks must be reassembled past the
        # 48-run threshold before the byte/entropy gate sees them.
        a = "".join("\\x%02x" % ((i * 5 + 1) % 256) for i in range(30))
        b = "".join("\\x%02x" % ((i * 5 + 1) % 256) for i in range(30, 64))
        src = 'const s = "' + a + '" +\n  "' + b + '";\nexport default s;\n'
        self.assertIn(OBF, _scan({"x.mjs": src}))

    def test_join_array_reassembly_caught(self):
        # Signal A, the canonical obfuscator primitive: a base64 payload stored as a string
        # ARRAY rejoined with .join("") — comma-quote seams, not `+`. _dechunk must collapse
        # those too, else the most common off-the-shelf obfuscator output walks straight past.
        random.seed(13)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(900))
        arr = ",\n  ".join('"%s"' % blob[i:i + 50] for i in range(0, len(blob), 50))
        src = "const p = [\n  " + arr + "\n].join('');\nexport default p;\n"
        self.assertLess(max(len(l) for l in src.splitlines()), 400)
        self.assertIn(OBF, _scan({"x.mjs": src}))

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

    def test_short_literal_concat_clean(self):
        # A's de-chunk must not manufacture a blob from ordinary short string concatenation
        # — `"foo" + "bar"` reassembles to a short, low-entropy run that misses the blob gate.
        code = ("export const url = 'https://' + 'api.' + 'example' + '.com' + '/v1';\n"
                "export const msg = 'hello, ' + 'world' + '!';\n")
        self.assertNotIn(OBF, _scan({"config.ts": code}))
        self.assertFalse(analyze_file(code, ".ts"))

    def test_few_escapes_clean(self):
        # B requires a long contiguous escape RUN; a regex character class or a couple of
        # unicode escapes (handfuls, not a payload) must stay clean.
        code = ("export const re = /[\\x00-\\x1f\\u2028\\u2029]/g;\n"
                "export const bullet = '\\u2022 item';\n")
        self.assertNotIn(OBF, _scan({"util.js": code}))
        self.assertFalse(analyze_file(code, ".js"))

    def test_emoji_surrogate_escape_run_clean(self):
        # FP guard (signal B): emoji written as \uXXXX surrogate pairs decode to codepoints
        # >255 clustered in a narrow block — long enough to clear 48, but the byte-range gate
        # keeps it clean. ASCII-only-source lint rules push devs toward exactly this form.
        emoji = "".join("\\u%04x\\u%04x" % (0xD83D, 0xDE00 + (i % 60)) for i in range(40))
        code = 'export const SMILEYS = "' + emoji + '";\n'
        self.assertNotIn(OBF, _scan({"emojiData.ts": code}))
        self.assertFalse(analyze_file(code, ".ts"))

    def test_magic_byte_fixture_clean(self):
        # FP guard (signal B): a structured file-header/magic-byte test fixture is short and
        # low-entropy — below the 48-run bar and the entropy gate.
        png = "\\x89\\x50\\x4e\\x47\\x0d\\x0a\\x1a\\x0a\\x49\\x48\\x44\\x52\\x00\\x00\\x00\\x10"
        code = 'export const PNG_HEADER = Buffer.from("' + png + '", "binary");\n'
        self.assertNotIn(OBF, _scan({"sniffer.test.js": code}))
        self.assertFalse(analyze_file(code, ".js"))

    def test_combining_marks_escape_run_clean(self):
        # FP guard (signal B): a combining-diacritical block (U+0300..U+036F) is a contiguous
        # \u run but a narrow >255 codepoint block — byte-range gate keeps it clean.
        marks = "".join("\\u%04x" % (0x0300 + (i % 0x70)) for i in range(60))
        code = 'export const COMBINING = "' + marks + '";\n'
        self.assertNotIn(OBF, _scan({"normalize.test.ts": code}))
        self.assertFalse(analyze_file(code, ".ts"))

    def test_legit_string_array_clean(self):
        # FP guard (signal A): de-chunking comma seams must not manufacture a blob from an
        # ordinary string array — low-entropy words, and SRI/hex lists whose -/=/# separators
        # break the base64 run, both reassemble to nothing that clears the 120/4.5 gate.
        words = "export const C = [" + ",".join("'%s'" % w for w in
                 ["apple", "banana", "cherry", "date", "fig", "grape"] * 30) + "];\n"
        sri = "export const H = [" + ",".join("'sha384-%s'" % ("AbC9+/" * 14) for _ in range(8)) + "];\n"
        self.assertNotIn(OBF, _scan({"data.ts": words}))
        self.assertNotIn(OBF, _scan({"sri.ts": sri}))

    def test_constructor_member_access_without_call_is_clean(self):
        # Plain ['constructor'] access (no call) is ordinary reflection — the exec-sink
        # arm requires the bracket-string *call* form (`]` then `(`), so `.name` access
        # must NOT trip it. Guards the false-positive boundary of the #1053 change.
        code = "const n = obj['constructor'].name;\nexport default n;\n"
        self.assertNotIn(OBF, _scan({"util.ts": code}))
        self.assertFalse(analyze_file(code, ".ts"))

    def test_polymorphic_clone_new_constructor_is_clean(self):
        # FP carve-out: `new <expr>['constructor'](...)` is the same-type clone idiom
        # (value objects / ORM entities / immutable records and their tests). The worm
        # never prefixes its exec with `new`, so this benign family must stay clean even
        # though it contains the bracket-string constructor call.
        for code in (
            "export class Shape{constructor(p){this.p=p}\n"
            "  clone(){return new this['constructor'](this.p)}}\n",
            "export function clone(o){return new o['constructor'](o)}\n",
            "const copy = new doc['constructor'](doc.toObject());\nexport default copy;\n",
        ):
            self.assertNotIn(OBF, _scan({"model.ts": code}), code)
            self.assertFalse(analyze_file(code, ".ts"), code)

    def test_constructor_exec_without_new_still_flagged(self):
        # The carve-out is ONLY for a directly `new`-prefixed reflective constructor.
        # A plain (non-new) call, and a comma/whitespace splice that tries to borrow a
        # nearby `new`, must still flag (the worm's actual exec shape).
        self.assertTrue(analyze_file("var f=q['constructor']('return 1');\n", ".js"))
        self.assertTrue(analyze_file("new Date(), x['constructor'](decoded);\n", ".js"))

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

    def test_analyze_file_catches_constructor_exec_sink(self):
        # Renamed decoder reaching the Function constructor via X['constructor'](...).
        self.assertTrue(analyze_file("var q=function(){};q['constructor']('return 2')();\n", ".js"))

    def test_analyze_file_clean_on_ordinary_code(self):
        code = "function add(a, b) {\n    return a + b;\n}\nexport default add;\n"
        self.assertFalse(analyze_file(code, ".js"))


if __name__ == "__main__":
    unittest.main()

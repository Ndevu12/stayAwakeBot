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
from stayawake.bots.security.obfuscation import analyze_file, analyze_delta, is_generated_context
from stayawake.bots.security.obfuscation.heuristics import _GENERATED_PATH
from stayawake.bots.security.obfuscation.execsink import (
    _has_exec_sink, _has_exec_sink_beyond_decoding)
from stayawake.bots.security.remediation.gates import _carries_payload

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

    def test_vm_runinnewcontext_dropper_caught(self):
        # #1212 follow-through: a base64 blob decoded and run via `vm.runInNewContext` is a
        # dropper. The blob alone is data, but runInNewContext is dynamic CODE execution — the
        # exec-sink arm now covers vm's runInThisContext/runInNewContext and vm-qualified
        # runInContext, so the loader is caught by its exec step regardless of base64 contiguity.
        random.seed(1)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(300))
        src = ("const vm = require('vm');\n"
               "const p = '" + blob + "';\n"
               "vm.runInNewContext(Buffer.from(p, 'base64').toString());\n")
        self.assertIn(OBF, _scan({"loader.js": src}))
        # FP guard: lodash's `_.runInContext()` is NOT vm code-exec — the bare form must not fire.
        self.assertNotIn(OBF, _scan(
            {"util.js": "const _ = require('lodash');\nexport const ld = _.runInContext();\n"}))

    def test_decode_then_exec_dropper_caught(self):
        # #1266: a base64/hex DECODE fed straight into a command / dynamic-module sink is a
        # dropper — the decode->exec FLOW, not the encoded bytes (#1212 dropped the bytes-alone
        # signal). Statically matched (nothing is decoded or executed). Covers the sinks the
        # exec-sink arm does not: child_process runners, dynamic import(), new Worker.
        random.seed(3)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(300))
        for name, src in {
            "cp.mjs": "import {execSync} from 'child_process';\n"
                      f"execSync(Buffer.from('{blob}', 'base64').toString());\n",
            "spawn.js": f"spawn(Buffer.from('{blob}', 'base64').toString(), []);\n",
            "worker.js": f"new Worker(Buffer.from('{blob}', 'base64').toString());\n",
            "dynimport.mjs": f"import(atob('{blob}')).then(m => m.run());\n",
            "hexfile.js": f"execFile(Buffer.from('{blob}', 'hex').toString());\n",
            "bytearr.js": "execSync(Buffer.from([0x6c, 0x73]).toString());\n",  # byte-array command
        }.items():
            self.assertIn(OBF, _scan({name: src}), name)

    def test_decode_then_exec_false_positive_boundaries_clean(self):
        # #1266 FP guards: neither half alone, nor a non-command `.exec`, is a signal.
        random.seed(4)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(300))
        for name, src in {
            # a JWT util: base64-decode THEN regex-match — `.exec` is a regexp method, not a command.
            "jwt.ts": "const p = Buffer.from(tok.split('.')[1], 'base64').toString();\n"
                      "const claims = /\"exp\":(\\d+)/.exec(p);\n",
            # a build script that spawns a process AND (unrelatedly) holds a base64 asset.
            "build.js": f"const LOGO = '{blob}';\n"
                        "import {execSync} from 'child_process';\nexecSync('npm run build');\n",
            # ordinary dynamic import / worker of a real module path.
            "router.mjs": "const m = await import('./routes/' + name + '.js');\n",
            "spawnw.js": "const w = new Worker(new URL('./w.js', import.meta.url));\n",
            # Buffer.from base64 decode with NO exec sink (decoding a token) — data, not a dropper.
            "token.ts": "const payload = JSON.parse(Buffer.from(tok, 'base64').toString());\n",
        }.items():
            self.assertNotIn(OBF, _scan({name: src}), name)

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

    def test_split_base64_payload_caught_via_its_decoder(self):
        # #1212 posture: a base64 blob split into `+`-joined chunks is NOT flagged on the
        # encoded bytes alone (that shape is indistinguishable from a benign wrapped token /
        # key array). A REAL split-base64 loader is caught by its DECODE→EXEC step — here the
        # reassembled blob is fed to `eval(atob(...))`, so the exec-sink arm fires.
        random.seed(11)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(900))
        chunks = " +\n  ".join('"%s"' % blob[i:i + 60] for i in range(0, len(blob), 60))
        bare = "const cfg = {};\nexport default cfg;\nconst b =\n  " + chunks + ";\n"
        self.assertLess(max(len(l) for l in bare.splitlines()), 400)
        self.assertNotIn(OBF, _scan({"postcss.config.mjs": bare}))          # bytes alone: clean
        loader = bare + "eval(atob(b));\n"
        self.assertIn(OBF, _scan({"loader.mjs": loader}))                   # decode→exec: caught

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

    def test_base64_string_array_is_clean_data(self):
        # #1212: a base64 string ARRAY — whether `.join("")`-reassembled or used element-wise —
        # is NOT flagged on the bytes alone. Comma-quote seams of an ordinary base64 array (a
        # JWKS `n`-value table, a cert-pin allowlist, a KAT-vector corpus) are indistinguishable
        # from a `.join("")` reassembly without runtime data flow, so both stay CLEAN. Kept on
        # <400-char lines so the density arm does not fire either.
        random.seed(13)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(900))
        arr = ",\n  ".join('"%s"' % blob[i:i + 50] for i in range(0, len(blob), 50))
        joined = "const p = [\n  " + arr + "\n].join('');\nexport default p;\n"
        used = "const KEYS = [\n  " + arr + "\n];\nexport const has = (k) => KEYS.includes(k);\n"
        self.assertLess(max(len(l) for l in joined.splitlines()), 400)
        self.assertNotIn(OBF, _scan({"reassembled.mjs": joined}))
        self.assertNotIn(OBF, _scan({"keys.mjs": used}))

    # ── Variable-indirected decode→exec dropper: restores the #1212 base64 capability,
    #    TIGHTENED — a blob is a signal ONLY when its decode result flows into a sink (#1289). ──
    @staticmethod
    def _blob(seed: int, n: int = 200) -> str:
        random.seed(seed)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "".join(random.choice(alph) for _ in range(n))

    def test_var_indirected_decode_exec_dropper_caught(self):
        # The #1212 blind spot + #1266 residual: a hardcoded blob decoded through a VARIABLE and
        # then run. The nested `execSync(Buffer.from(...))` was already caught (#1266); the one-hop
        # variable form was NOT. All three sink families (child_process / import() / Worker).
        b = self._blob(1)
        self.assertIn(OBF, _scan({
            "cp.js": f"const p = '{b}';\nconst d = Buffer.from(p, 'base64');\nexecSync(d);\n"}))
        self.assertIn(OBF, _scan({
            "inline.mjs": f"const d = Buffer.from('{b}', 'base64');\nimport(d).then(m => m.run());\n"}))
        self.assertIn(OBF, _scan({
            "worker.js": f"const s = '{b}';\nconst w = Buffer.from(s, 'base64');\nnew Worker(w);\n"}))
        self.assertIn(OBF, _scan({
            "tostr.js": f"const c = Buffer.from('{b}', 'base64').toString();\nexecFileSync(c);\n"}))

    def test_var_indirected_dropper_caught_as_evil_merge_delta(self):
        # The G4 evil-merge hunk case the #1212 removal opened: the dropper introduced in a merge.
        b = self._blob(2)
        hunk = f"const p = '{b}';\nconst d = Buffer.from(p, 'base64');\nexecSync(d);\n"
        self.assertTrue(analyze_delta(hunk))
        self.assertTrue(analyze_delta(hunk, baseline="export const version = '1.2.3';\n"))

    def test_hex_var_indirected_dropper_caught(self):
        # FN-hunt: a HEX-encoded payload decoded through a variable and run. `_has_encoded_payload`
        # corroborates hex (a >=200-char hex run) even though its ~4.0 entropy is below the base64
        # 4.5 gate — otherwise `Buffer.from(p,'hex'); execSync(d)` slips (the code claims hex support).
        hexblob = ("".join("%02x" % ((i * 37 + 11) % 256) for i in range(140)))  # 280 hex chars
        self.assertIn(OBF, _scan({
            "hex.js": f"const p = '{hexblob}';\nconst d = Buffer.from(p, 'hex');\nexecSync(d);\n"}))

    def test_cross_scope_var_name_collision_stays_clean(self):
        # FP-hunt (the strongest FP): a decode into `p` in ONE function and an unrelated `import(p)`
        # param in ANOTHER — a pure name collision, not a data flow. The brace-depth scope check
        # (the decode's `const p` is dead once its `}` passes) keeps this clean despite an embedded
        # base64 key elsewhere in the file.
        key = self._blob(4)
        code = (
            f"export const RELEASE_PUBKEY = '{key}';\n"
            "export function decodeThumb(b64) {\n"
            "  const p = Buffer.from(b64, 'base64');\n"
            "  return sharp(p).resize(64).toBuffer();\n"
            "}\n"
            "export async function loadPage(p) {\n"
            "  return import(p);\n"
            "}\n"
        )
        self.assertNotIn(OBF, _scan({"mod.js": code}))

    def test_module_level_decode_var_collision_stays_clean(self):
        # FP-hunt round 2: a MODULE-LEVEL `const data = Buffer.from(...)` (benign binary handling)
        # collides by NAME with a same-named param in a LATER function whose sink reads a PROPERTY of
        # it (`spawn(data.cmd, data.args)`), while an embedded base64 root CA satisfies the blob
        # corroborator. A module binding has no `}` to close, so the brace-depth check alone missed
        # it — the property-access-sink guard and the re-bind guard keep it clean.
        ca = self._blob(5)
        cases = {
            "spawn_prop.js": (
                "const { spawn } = require('child_process');\n"
                f"const ROOT_CA = '{ca}';\npinRootCert(ROOT_CA);\n"
                "const data = Buffer.from(headerBytes);\nfs.writeFileSync(cachePath, data);\n"
                "function run(data) { return spawn(data.cmd, data.args, { stdio: 'inherit' }); }\n"),
            "import_prop.js": (
                f"const KEY = '{ca}';\nconst mod = Buffer.from(raw);\nsave(mod);\n"
                "function load(mod) { return import(mod.entry); }\n"),
            "import_param.mjs": (
                f"const K = '{ca}';\nconst config = Buffer.from(bytes);\ncache(config);\n"
                "export const loadPage = (config) => import(config);\n"),
        }
        for name, code in cases.items():
            self.assertNotIn(OBF, _scan({name: code}), name)

    def test_real_dropper_variants_still_caught_after_scope_guards(self):
        # The accuracy guards must NOT drop the real dropper: bare var, `.toString()` at the sink,
        # a decoded command with args, an intervening unrelated arrow callback (whose param is a
        # DIFFERENT name), and a CHAINED string-method decode idiom (`.toString('utf8').trim()`).
        b = self._blob(6)
        self.assertIn(OBF, _scan({
            "bare.js": f"const d = Buffer.from('{b}', 'base64');\nexecSync(d);\n"}))
        self.assertIn(OBF, _scan({
            "tostr.js": f"const d = Buffer.from('{b}', 'base64');\nexecSync(d.toString('utf8'));\n"}))
        self.assertIn(OBF, _scan({
            "chain.js": f"const d = Buffer.from('{b}', 'base64');\nexecSync(d.toString('utf8').trim());\n"}))
        self.assertIn(OBF, _scan({
            "args.js": f"const c = Buffer.from('{b}', 'base64').toString();\nspawn(c, ['-e']);\n"}))
        self.assertIn(OBF, _scan({
            "arrow.js": f"const d = Buffer.from('{b}', 'base64');\nitems.forEach(x => log(x));\nexecSync(d);\n"}))

    def test_es6_param_name_collisions_stay_clean(self):
        # FP-hunt round 3: a module-level decode var colliding with a same-named param in an ES6
        # METHOD-SHORTHAND, a CLASS METHOD, or a `catch` binding — none of which use the `function`
        # keyword or an arrow, so an earlier param-detector missed them and the FP still fired.
        key = self._blob(7)
        cases = {
            "method_shorthand.js": (
                f"const K = '{key}';\nconst src = Buffer.from(raw, 'base64');\ncache(src);\n"
                "export const registry = {\n"
                "  spawnWorker(src) { return new Worker(src, { type: 'module' }); }\n};\n"),
            "class_method.js": (
                f"const K = '{key}';\nconst data = Buffer.from(raw);\nsave(data);\n"
                "class Runner {\n  run(data) { return spawn(data); }\n}\n"),
            "catch_param.js": (
                f"const K = '{key}';\nconst data = Buffer.from(raw);\nsave(data);\n"
                "try { risky(); } catch (data) { execSync(data); }\n"),
        }
        for name, code in cases.items():
            self.assertNotIn(OBF, _scan({name: code}), name)

    def test_lone_blob_and_benign_decode_stay_clean(self):
        # The #1212 FP class stays fixed: a blob is NEVER a signal without the decode→sink flow.
        b = self._blob(3)
        cases = {
            # a mock JWT / API token constant — used as-is, never decoded.
            "jwt.ts": f"const token = '{b}';\nexport default token;\n",
            # a JWT-parsing util: the KEY blob is not the thing decoded; the token is, with NO exec.
            "verify.ts": f"const KEY = '{b}';\nconst h = JSON.parse(Buffer.from(tok, 'base64').toString());\n",
            # decode a hardcoded asset blob but NO exec sink — an inlined resource.
            "asset.ts": f"const png = Buffer.from('{b}', 'base64');\nreturn png;\n",
            # THE case a naive 'blob decoded AND file can exec' rule (Option A) would FP on:
            # a build script that runs a command AND separately embeds a base64 asset. The decode
            # result never reaches the sink, so the flow-based check correctly stays clean.
            "build.js": f"execSync('webpack --mode production');\nconst logo = Buffer.from('{b}', 'base64');\n",
        }
        for name, code in cases.items():
            self.assertNotIn(OBF, _scan({name: code}), name)

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

    def test_mock_jwt_in_test_file_clean(self):
        # #1212 regression: a hardcoded mock JWT (`header.payload.signature`) in a test
        # fixture is a >120-char high-entropy base64url run — but it is DATA, not packed
        # code, and carries no exec sink / charcode array / concat-splitting. It must NOT
        # be flagged, not even at heuristic confidence (the real-world false positive that
        # surfaced a clean test file as a "packed payload").
        jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
               "eyJpZCI6ImMzZDg5ZTJkLTNiZDQtNDEyYi1hYzEzLWYzNTM4Y2Q2YjZlNSIsImZpcnN0TmFtZSI6"
               "IkpvaG4iLCJsYXN0TmFtZSI6IkRvZSIsImVtYWlsIjoidmVuZG9yQGdtYWlsLmNvbSIsInJvbGUi"
               "OiJWRU5ET1IiLCJpYXQiOjE3MTk3NjIwNjAsImV4cCI6MTcxOTg0ODQ2MH0."
               "NSCYBuYzhhMgNbbMn2s7sc0r333YZaQHHnlhMcYRyCc")
        code = ("import { describe, it } from 'vitest';\n"
                "describe('auth', () => {\n"
                "  const mockedToken = JSON.stringify({ token: '" + jwt + "' });\n"
                "  it('renders', () => {});\n});\n")
        self.assertNotIn(OBF, _scan({"src/__test__/Navbar.test.tsx": code}))
        self.assertFalse(analyze_file(code, ".tsx"))

    def test_contiguous_base64_blob_without_tell_clean(self):
        # #1212: a raw CONTIGUOUS base64 literal (an API token, an inlined asset stored
        # without a data-URI prefix, a crypto test vector) embedded in ordinary source is
        # DATA, not packed code. Only a blob emerging from reassembled SPLIT chunks — or one
        # with an exec sink — is the obfuscation tell. The token sits on a <400-char line in
        # a normal multi-line module, so neither the base64 arm nor the density arm fires.
        random.seed(7)
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        blob = "".join(random.choice(alph) for _ in range(300))
        src = ("import { api } from './client';\n"
               "const API_KEY = '" + blob + "';\n"
               "export function auth() { return api.withKey(API_KEY); }\n")
        self.assertNotIn(OBF, _scan({"asset.ts": src}))
        self.assertFalse(analyze_file(src, ".ts"))

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

    # ── Reflective / dynamic exec sinks the classic set missed (adversarial-verification
    #    follow-up): high-signal, rare-in-legit forms, surfaced as HEURISTIC (SUSPICIOUS). ──
    def test_dot_form_double_constructor_flagged(self):
        # The Function constructor reached through the prototype CHAIN (dot form or any dot/bracket
        # mix) — the gap the single bracket-constructor arm missed. A DOUBLE access is always Function.
        self.assertTrue(analyze_file("const f=[].constructor.constructor('return process')();\n", ".js"))
        self.assertTrue(analyze_file("var g=x.constructor['constructor']('code')();\n", ".js"))
        self.assertTrue(analyze_file("y['constructor'].constructor(payload)();\n", ".js"))

    def test_computed_key_dangerous_global_flagged(self):
        # A dangerous global reached through a computed string key AND CALLED hides WHICH global
        # runs. A CALL is required, so a bare registry lookup (see the FP test) stays clean.
        self.assertTrue(analyze_file("window['eval'](p);\n", ".js"))
        self.assertTrue(analyze_file("globalThis['Function']('return 1')();\n", ".js"))

    def test_string_body_timer_flagged(self):
        # A GLOBAL setTimeout/setInterval with a STRING/template body is the deprecated eval-form
        # (a member `.setTimeout('30s')` duration setter is excluded — see the FP test).
        self.assertTrue(analyze_file("setTimeout('runEvil()', 0);\n", ".js"))
        self.assertTrue(analyze_file("setInterval(`tick()`, 100);\n", ".js"))

    def test_reflect_and_vm_exec_flagged(self):
        self.assertTrue(analyze_file("Reflect.apply(eval, null, [s]);\n", ".js"))
        self.assertTrue(analyze_file("Reflect.construct(Function, [body]);\n", ".js"))
        # `runInThisContext` (run in the current global) is vm-specific; bare `runInContext` is NOT
        # matched — lodash ships a public `_.runInContext()`, so it would false-positive.
        self.assertTrue(analyze_file("require('vm').runInThisContext(code);\n", ".js"))

    def test_renamed_loader_via_dot_constructor_surfaces(self):
        # End-to-end: a renamed loader whose ONLY tell is a dot-form Function-constructor reach
        # (no literal fingerprint, short lines) now surfaces as an obfuscation finding.
        variant = ("const cfg={plugins:['@tailwindcss/postcss']};\nexport default cfg;\n"
                   "const run=[].constructor.constructor(seed);\nrun();\n")
        self.assertIn(OBF, _scan({"postcss.config.mjs": variant}))

    def test_reflective_exec_false_positive_boundaries_clean(self):
        # The FP boundaries the case-sensitivity + call-required + global-only + carve-out design
        # protects — including the realistic collisions an adversarial FP pass surfaced:
        for code in (
            "const n = obj.constructor.name;\n",       # single .constructor access, no call
            "export default El.constructor;\n",        # single .constructor reference
            "const h = handlers['function'];\n",       # lowercase 'function' DATA key, not the global
            "const f = registry['Function'];\n",       # bare registry LOOKUP of 'Function' (no call)
            "const g = visitors['eval'];\n",           # bare AST-visitor lookup of 'eval' (no call)
            "setTimeout(() => tick(), 100);\n",        # timer with a function, not a string
            "client.setTimeout('30s');\n",             # MEMBER timer with a string DURATION, not code
            "job.setInterval('*/5 * * * *', run);\n",  # MEMBER setInterval with a cron string
            "const _ = require('lodash').runInContext();\n",   # lodash's runInContext, not vm
            "Reflect.apply(myFunc, ctx, args);\n",     # Reflect.apply on a normal function
            "const vm = require('vm');\n",             # vm imported but no exec call
            "return new o['constructor'](o.props);\n", # polymorphic same-type clone (new-prefixed)
        ):
            self.assertFalse(analyze_file(code, ".ts"), code)

    # ── #1208 residual, TIGHTENED per #1289. The BROAD arms (any non-literal import / any
    #    constructed child_process command) were FP-prone at scan time (every lazy-import / build
    #    script fired), so they no longer raise a SCAN finding — only the precise, no-benign-analogue
    #    shapes do: a data:-URI executable import and a require-receiver runner fed a decode.
    #    (`require('vm').runInContext` and `import(atob(x))` fire via _EXEC_SINK / #1266.) The broad
    #    arms are RETAINED as the conservative remediation gate — see
    #    test_remediation_gate_stays_conservative below (tighten, not downgrade). ──
    def test_data_uri_executable_import_flagged(self):
        # An inline JS-MIME AND base64-ENCODED data: URI imported as a MODULE — the concealed
        # stage-2 loader. Literal, concat-appended payload, and template forms.
        self.assertTrue(analyze_file("import('data:text/javascript;base64,ZXZpbA==');\n", ".mjs"))
        self.assertTrue(analyze_file("import('data:application/javascript;base64,' + p);\n", ".mjs"))
        self.assertTrue(analyze_file("import(`data:text/ecmascript;base64,${p}`);\n", ".mjs"))
        self.assertTrue(analyze_file(
            "import('data:text/javascript;charset=utf-8;base64,ZQ==');\n", ".mjs"))
        # decode form is #1266's _DECODE_INTO_EXEC — still fires.
        self.assertTrue(analyze_file("import(atob(payload));\n", ".js"))

    def test_plaintext_data_uri_import_clean(self):
        # FP-hunt: a PLAINTEXT `data:text/javascript,<code>` import is a documented, standards-blessed
        # inline-module idiom (module-loader tests, REPL/playground tools, Deno) — the code is
        # READABLE, i.e. not obfuscation. Only the base64-ENCODED form is a concealed payload.
        self.assertFalse(analyze_file(
            "const m = await import('data:text/javascript,export const answer = 42');\n", ".mjs"))
        self.assertFalse(analyze_file("import('data:text/javascript,globalThis.x=1');\n", ".js"))

    def test_require_receiver_runner_decode_flagged(self):
        # A require-RECEIVER command runner fed a DECODE — the form #1266's bare-name set misses.
        self.assertTrue(analyze_file("require('child_process').exec(atob(cmd));\n", ".js"))
        self.assertTrue(analyze_file(
            "require('child_process').execSync(Buffer.from(c, 'base64').toString());\n", ".js"))
        self.assertTrue(analyze_file("require('node:child_process').spawn(atob(cmd));\n", ".js"))
        self.assertTrue(analyze_file("require('shelljs').exec(atob(cmd));\n", ".js"))

    def test_require_receiver_non_command_exec_decode_clean(self):
        # FP-hunt: `.exec` on a NON-command module fed a decode is benign — RegExp.exec on decoded
        # text, or a sqlite `.exec` of a base64-packed migration. The module gate (child_process /
        # shelljs) keeps these clean.
        self.assertFalse(analyze_file(
            "const m = require('./patterns/token').exec(Buffer.from(rec, 'base64').toString());\n", ".js"))
        self.assertFalse(analyze_file(
            "require('./db').exec(Buffer.from(sql, 'base64').toString('utf8'));\n", ".js"))

    def test_require_vm_runInContext_flagged(self):
        self.assertTrue(analyze_file("require('vm').runInContext(code, ctx);\n", ".js"))
        self.assertTrue(analyze_file('require("vm").runInContext(decoded);\n', ".js"))
        self.assertTrue(analyze_file("require('vm')?.runInContext(code);\n", ".js"))
        self.assertTrue(analyze_file("require(/*c*/'vm').runInContext(code);\n", ".js"))

    def test_dynamic_exec_false_positive_boundaries_clean(self):
        for code in (
            "const _ = require('lodash').runInContext();\n",
            "const m = await import('lodash');\n",
            "const m = await import(\"./routes/\" + name + '.js');\n",
            "import(/* webpackChunkName: \"x\" */ './mod.js');\n",
            "import(`./locales/${locale}.js`);\n",
            "System.import(env + '.js');\n",
            "loader.import(`./widgets/${id}`);\n",
            "const x = require('fs');\n",
            "const p = require(path.join(__dirname, 'x'));\n",
            "const messages = require('./locales/' + locale + '.json');\n",
            "execSync('npm run build');\n",
            "execSync(cmd);\n",                                    # bare ident — Ops default
            "spawn(process.execPath, args);\n",
            "const {execSync} = require('child_process');\n",
            "const vm = require('vm');\n",
            "/\"exp\":(\\d+)/.exec(buf);\n",
            "// Example: load via import(pluginUrl) at runtime\nexport const ok = 1;\n",
            "'import(url)';\n",
            "\"execSync(cmd + x)\";\n",
            # a data: URI import whose MIME is NOT javascript is an inert data module (JSON), not
            # executable — must stay clean (the MIME gate, not a bare `;base64,` match).
            "const cfg = await import('data:application/json;base64,eyJhIjoxfQ==');\n",
            "import('data:text/css,body{color:red}');\n",
            # #1289 — the BROAD arms are no longer a scan finding (indistinguishable from legit):
            "const m = await import(componentPath);\n",           # React.lazy-style dynamic import
            "import(decodedModule).then(m => m.run());\n",        # bare-ident import
            "import(`${attackerUrl}`);\n",                        # bare-template import
            "import(`https://${host}/p.js`);\n",                  # remote-template import
            "execSync(cmd + ' --force');\n",                      # constructed command
            "spawnSync(`sh -c ${payload}`);\n",                   # constructed template command
            "fork(bin + ext);\n",
            "require('child_process').execSync(`run ${x}`);\n",   # constructed require-cp command
            "require('child_process').exec(cmd + flags);\n",
            # a data: URI merely MENTIONED in a comment must stay clean (comment scrub).
            "// import('data:text/javascript;base64,AAAA') is the attack\nexport const y = 2;\n",
        ):
            self.assertFalse(analyze_file(code, ".ts"), code)

    def test_remediation_gate_stays_conservative(self):
        # tighten-not-downgrade proof: the BROAD #1208 arms no longer raise a scan finding
        # (asserted clean above), but the remediation "safe to auto-clean?" gate (strict=True)
        # STILL treats them as a possible dynamic-exec sink → refuses (an over-refusal is the safe
        # direction there). A miss here could auto-clean past an injected RCE, so it must not regress.
        for code in (
            "import(componentPath);\n",
            "import(`${attackerUrl}`);\n",
            "execSync(cmd + ' --force');\n",
            "require('child_process').execSync(`run ${x}`);\n",
        ):
            self.assertTrue(_has_exec_sink(code, strict=True), f"gate must refuse: {code}")
            self.assertFalse(_has_exec_sink(code, strict=False), f"scan must be clean: {code}")

    # ── saw#232. `$` is a legal JS identifier character and a regex word character is not, so
    #    `\beval` matched inside `page.$eval` — a different name, and not the builtin. ──
    def test_the_scan_excuses_a_framework_member_but_nothing_else_does(self):
        driver = 'const n = await page.$eval("#root", (el) => el.innerHTML);\n'
        self.assertNotIn(OBF, _scan({"driver.mjs": driver}))
        # Every other consumer keeps the full arm, and each is here because a round used it:
        # the corroborator for a confirmed signature, and both remediation entry points.
        self.assertTrue(_has_exec_sink_beyond_decoding(driver))
        self.assertTrue(_has_exec_sink(driver, strict=True))
        self.assertTrue(_carries_payload(driver, lambda _t: None))

    def test_an_eval_rebinding_is_caught_at_the_binding_whatever_the_call_looks_like(self):
        """The call spelling stopped mattering, which is what makes excusing one safe.

        Three of these are past the alias arm on main, and the spread form defeats any boundary
        keyed on the characters before `eval` — `...` ends in a dot too."""
        pad = "\n".join(f"const p{i} = {i};" for i in range(60))
        for name, src in {
            "member.js": "const h = {};\nh.$eval = globalThis['ev' + 'al'];\nh.$eval(p);\n",
            "destructured.js": "const { eval: $eval } = globalThis;\n$eval(await r.text());\n",
            "computed.js": "const q = globalThis['ev' + 'al'];\nq(await r.text());\n",
            "farapart.js": f"var zz = eval;\n{pad}\nzz(src);\n",
            "spread.js": "const { eval: $eval } = globalThis;\n[...$eval(src)];\n",
            "memberspread.js": "const h = {};\nh.$eval = globalThis['ev'+'al'];\n[...h.$eval(s)];\n",
        }.items():
            self.assertIn(OBF, _scan({name: src}), name)

    def test_a_confirmed_signature_still_reports_where_it_is_the_only_tier(self):
        """In a vendored or minified path the confirmed tier is the only one that reports, so a
        corroborator that quietly narrowed turned a real worm from infected into clean."""
        worm = ("const parts = data.split(String.fromCharCode(127));\n"
                "const { eval: $eval } = globalThis;\n[...$eval(parts[1])];\n")
        for rel in ("loader.js", "vendor/left-pad/index.js", "assets/app.min.js"):
            self.assertIn("loader-fromcharcode-127", _scan({rel: worm}), rel)

    def test_the_exclusions_name_an_idiom_not_a_whole_category(self):
        """Both narrowings first excluded a category and lost real detections with it.

        `Function.prototype.call.bind(x)` borrows a FOREIGN method; `Function.prototype.constructor`
        and `eval.bind(g)` are the built-in and they run. A regular-expression receiver is what a
        token reader has before `.exec(`; `cp.exec(...)` is a command, and a dropper that hides the
        module name behind a decode leaves no literal for the module arm to find."""
        for name, src in {
            "ctor.js": "const Ctor = Function.prototype.constructor;\n"
                       "export async function boot(u){ return Ctor(await (await fetch(u)).text())(); }\n",
            "bind.js": "const e = eval.bind(globalThis);\ne(await res.text());\n",
            "evalctor.js": "const F = eval.constructor;\nF('return 2+3')();\n",
            "concealed.js": "const M = atob('Y2hpbGRfcHJvY2Vzcw==');\n"
                            "const cp = require(M);\ncp.exec(atob(P));\n",
            "optional.js": "const cp = require(M);\ncp?.exec(atob(P));\n",
        }.items():
            self.assertIn(OBF, _scan({name: src}), name)

    def test_a_rename_is_caught_however_it_is_bound_and_however_it_is_called(self):
        """A class field and an object-literal property bind it too, and an alias reached as a
        property is still that alias — main misses all three."""
        for name, src in {
            "field.js": "export class Sandbox {\n  $eval = eval;\n"
                        "  async run(u){ return this.$eval(await (await fetch(u)).text()); }\n}\n",
            "literal.js": "const h = { $eval: eval };\nh.$eval(src);\n",
            "property.js": "const evl = eval;\nexport const runtime = { evl };\n"
                           "runtime.evl(await res.text());\n",
        }.items():
            self.assertIn(OBF, _scan({name: src}), name)

    def test_a_regex_exec_beside_a_decode_is_not_a_dropper(self):
        """`.exec` is `RegExp.prototype.exec`. The guard above this one only passed because it
        picked the Node spelling — `Buffer.from`; the browser spelling of the same reader fired."""
        for name, src in {
            "jwt.js": "const p = atob(tok.split('.')[1]);\n"
                      "const claims = /\"exp\":(\\d+)/.exec(p);\n",
            "keypad.js": "const ch = String.fromCharCode(e.which);\n"
                         "export const ok = /^[\\w]$/.exec(ch) ? ch : '';\n",
        }.items():
            self.assertNotIn(OBF, _scan({name: src}), name)
        # …while a real decode fed to a runner still is one.
        self.assertIn(OBF, _scan(
            {"drop.js": "const {execSync} = require('child_process');\nexecSync(atob(blob));\n"}))

    def test_uncurry_this_is_not_an_eval_alias(self):
        """`Function.prototype.call.bind(...)` binds `hasOwnProperty`, not `Function`. The alias
        arm required the right-hand side only to START with the token."""
        for name, src in {
            "object.js": "const hasOwn = Function.prototype.call.bind(Object.prototype.hasOwnProperty);\n"
                         "export function pick(s, k) { return hasOwn(s, k); }\n",
            "uncurry.js": "const uncurryThis = Function.prototype.bind.bind(Function.prototype.call);\n"
                          "export const push = uncurryThis(Array.prototype.push);\n",
        }.items():
            self.assertNotIn(OBF, _scan({name: src}), name)

    # ── #1207 residual (after #1206; orthogonal to #1208/#1266): split-token via
    #    concat-fold, indirect comma-call, light alias / runtime-key — heuristic. ──
    def test_split_token_exec_flagged(self):
        self.assertTrue(analyze_file("['ev'+'al'](payload);\n", ".js"))
        self.assertTrue(analyze_file("global['ev'+'al'](code);\n", ".js"))
        self.assertTrue(analyze_file('window["ev"+"al"](x);\n', ".js"))
        self.assertTrue(analyze_file("['Fun'+'ction']('return 1')();\n", ".js"))
        self.assertTrue(analyze_file("obj['con'+'structor']('return 1')();\n", ".js"))
        self.assertTrue(analyze_file(
            "x['con'+'structor']['con'+'structor']('return 1')();\n", ".js"))
        # multi-chunk fold
        self.assertTrue(analyze_file("global['e'+'v'+'a'+'l'](x);\n", ".js"))

    def test_indirect_comma_eval_flagged(self):
        self.assertTrue(analyze_file("(0, eval)(payload);\n", ".js"))
        self.assertTrue(analyze_file("(0,eval)(x);\n", ".js"))
        self.assertTrue(analyze_file("(void 0, Function)('return 1')();\n", ".js"))
        self.assertTrue(analyze_file("(null, eval)(code);\n", ".js"))
        self.assertTrue(analyze_file("(!0, Function)(body)();\n", ".js"))

    def test_aliased_eval_flagged(self):
        self.assertTrue(analyze_file("const e = eval; e(payload);\n", ".js"))
        self.assertTrue(analyze_file("let F = Function; F('return 1')();\n", ".js"))
        self.assertTrue(analyze_file("var run = eval;\nrun(code);\n", ".js"))

    def test_runtime_built_key_flagged(self):
        self.assertTrue(analyze_file("const k = 'ev' + 'al'; g[k](x);\n", ".js"))
        self.assertTrue(analyze_file("let k = 'eval'; global[k](payload);\n", ".js"))
        self.assertTrue(analyze_file(
            "const k = 'con' + 'structor'; obj[k](decoded);\n", ".js"))

    def test_obfuscated_exec_false_positive_boundaries_clean(self):
        for code in (
            # Babel / tslib interop — must NOT fire on non-eval RHS
            "var x = (0, _mod.default)(arg);\n",
            "(0, Object.assign)(a, b);\n",
            "(0, require('tslib').__exportStar)(m, exports);\n",
            "(0, fn)(x);\n",
            # benign concat / non-dangerous keys
            "const msg = 'hello' + 'world';\nexport const x = msg;\n",
            "['hel'+'lo'](x);\n",
            "const k = 'push'; arr[k](x);\n",
            "const k = 'eval';\nconsole.log(k);\n",           # binding, no call via [k](
            "const e = evaluate; e(x);\n",                    # not the eval global
            "const F = Functional; F(x);\n",
            "handlers['eval'];\n",                           # lookup, no call
            "registry['Function'];\n",
            # polymorphic clone via runtime key — same carve-out as literal form
            "const k = 'constructor';\nreturn new obj[k](props);\n",
            # alias without a call
            "const e = eval;\nmodule.exports = e;\n",
            "const F = Function;\nif (!(x instanceof F)) throw 0;\n",
        ):
            self.assertFalse(analyze_file(code, ".ts"), code)

    def test_vendored_and_generated_paths_suppressed(self):
        arr = "var a=[" + ",".join(["0x68"] * 40) + "];String.fromCharCode(127)"
        for path in ("lib/app.min.js", ".pnp.cjs", ".yarn/releases/yarn.cjs",
                     "dist/main.js", "src/gql.generated.ts", "proto/__generated__/x.pb.js",
                     ".venv/lib/python3.11/site-packages/pkg/mod.py"):   # a Python venv (third-party code)
            self.assertNotIn(OBF, _scan({path: arr}), f"{path} should be suppressed (generated context)")

    def test_site_packages_suppresses_density_but_not_the_confirmed_loader(self):
        # THE no-blind-spot guarantee: marking a venv's site-packages generated context suppresses only
        # the FP-prone density heuristic — the CONFIRMED loader tier is ungated and STILL scans there, so
        # a novel / off-manifest malicious file in a venv is caught. (A dense construct is NOT flagged;
        # a real loader fingerprint IS.)
        sp = ".venv/lib/python3.11/site-packages/evilpkg/"
        self.assertNotIn(OBF, _scan({sp + "dense.py": self._OBF_ONLY}))            # density suppressed
        self.assertIn("loader-seed-var", _scan({sp + "loader.py": "var _$_1e42 = sfL(0);\n"}))  # still caught

    # ── Build-artifact blind spot (#1095): both suppression layers, documented ──
    # An obfuscation-ONLY payload: a numeric array fed to fromCharCode.apply — trips the density/
    # exec-sink heuristic but carries NO known loader content literal (no fromCharCode(127), _$_,
    # sfL, …), so it isolates the OBFUSCATION path from the content signatures.
    _OBF_ONLY = "const d = String.fromCharCode.apply(0, [" + ",".join(["0x68"] * 40) + "]);\n"

    def test_build_payload_flags_in_hand_authored_source(self):
        # Sanity: the detector DOES catch this payload in ordinary source — the suppression below
        # is about WHERE it runs, not whether it works.
        self.assertIn(OBF, _scan({"src/loader.js": self._OBF_ONLY}))

    def test_layer1_traversal_prune_drops_dist_and_build(self):
        # Layer 1: dist/ and build/ are pruned from os.walk before any matcher runs (default opts),
        # so a payload there is never even yielded → no finding. (docs: "Provenance is not trust".)
        self.assertNotIn(OBF, _scan({"dist/main.js": self._OBF_ONLY}))
        self.assertNotIn(OBF, _scan({"build/bundle.js": self._OBF_ONLY}))

    def test_layer2_generated_context_suppresses_when_not_pruned(self):
        # Layer 2 (independent of layer 1): even with dist/build NOT pruned, is_generated_context
        # suppresses the obfuscation heuristic on build/minified outputs. A *.min.js at repo root
        # (a path traversal never prunes) exercises this layer on its own.
        def _scan_no_prune(files):
            d = Path(tempfile.mkdtemp())
            for rel, content in files.items():
                p = d / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            opts = ScanOptions(exclude_dirs={".git"})     # deliberately keep dist/build in scope
            return {f.signature_id for f in scan_target(LocalRepoTarget(d, "t", opts), SIGS, []).findings}

        self.assertNotIn(OBF, _scan_no_prune({"dist/main.js": self._OBF_ONLY}))   # dir arm
        self.assertNotIn(OBF, _scan_no_prune({"app.min.js": self._OBF_ONLY}))     # filename arm, root
        # Contrast: the SAME payload in a hand-authored file under the same (un-pruned) scan flags,
        # proving the suppression is context-specific, not a dead detector.
        self.assertIn(OBF, _scan_no_prune({"src/loader.js": self._OBF_ONLY}))

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


class TestOptInBuildScan(unittest.TestCase):
    """Opt-in `scan_build_outputs` (#1095b): the self-evident obfuscation constructs surface in
    build/minified artifacts as a heuristic `obfuscated-build-artifact` (SUSPICIOUS, never
    confirmed), while the whole-file density heuristic stays suppressed there (density is expected
    in bundles)."""
    _CONSTRUCT = "const d = String.fromCharCode.apply(0, [" + ",".join(["0x68"] * 40) + "]);\n"

    def _scan(self, files, scan_build_outputs, exclude=(".git",)):
        d = Path(tempfile.mkdtemp())
        for rel, content in files.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        opts = ScanOptions(exclude_dirs=set(exclude), scan_build_outputs=scan_build_outputs)
        return scan_target(LocalRepoTarget(d, "t", opts), SIGS, []).findings

    def test_optin_surfaces_obfuscation_construct_as_heuristic(self):
        for path in ("dist/main.js", "build/bundle.js", "app.min.js"):
            fs = self._scan({path: self._CONSTRUCT}, scan_build_outputs=True)
            ids = {f.signature_id for f in fs}
            self.assertIn("obfuscated-build-artifact", ids, path)
            self.assertNotIn("obfuscated-source-file", ids, path)      # build sig, not the source one
            self.assertTrue(all(f.confidence == "heuristic" for f in fs), path)   # never confirmed

    def test_optin_dense_bundle_without_construct_stays_clean(self):
        # A dense/minified bundle with NO self-evident obfuscation construct: the whole-file density
        # heuristic is suppressed in build-output mode, so it stays clean — the key FP guard.
        dense = "var a=" + "+".join("f%d()" % i for i in range(500)) + ";\n"
        self.assertEqual(self._scan({"dist/vendor.min.js": dense}, scan_build_outputs=True), [])

    def test_flag_off_suppresses_build_outputs_even_if_traversed(self):
        fs = self._scan({"dist/main.js": self._CONSTRUCT, "x.min.js": self._CONSTRUCT},
                        scan_build_outputs=False)
        self.assertEqual([f.signature_id for f in fs], [])

    def test_hand_authored_source_unaffected_by_flag(self):
        ids = {f.signature_id for f in
               self._scan({"src/loader.js": self._CONSTRUCT}, scan_build_outputs=True)}
        self.assertIn("obfuscated-source-file", ids)
        self.assertNotIn("obfuscated-build-artifact", ids)

    def test_options_unprunes_build_dirs_only_when_enabled(self):
        from stayawake.bots.security.service.config import _options
        on = _options({"scan_build_outputs": True})
        self.assertTrue(on.scan_build_outputs)
        self.assertNotIn("dist", on.exclude_dirs)
        self.assertNotIn("build", on.exclude_dirs)
        self.assertIn("node_modules", on.exclude_dirs)     # third-party stays pruned
        off = _options({})
        self.assertFalse(off.scan_build_outputs)
        self.assertIn("dist", off.exclude_dirs)            # FP-safe default unchanged


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""The decode→exec dropper detector (taint/): the shell code-argument forms the leading-argument arms
miss, plus the model predicates. The leading-argument forms are covered by test_obfuscation_file
(reused verbatim); this file focuses on the NEW capability — a decoded baked payload run through a
shell `-c` argument — and its false-positive boundaries.
"""
from __future__ import annotations

import random
import unittest

from stayawake.bots.security.obfuscation import analyze_file, analyze_delta
from stayawake.bots.security.taint import model
from stayawake.bots.security.taint.analyzer import detect_dropper


def _blob(seed: int, n: int = 200) -> str:
    random.seed(seed)
    alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choice(alph) for _ in range(n))


def _hexblob(n: int = 280) -> str:
    return "".join("%02x" % ((i * 37 + 11) % 256) for i in range(n // 2))


class TestShellDecodeExec(unittest.TestCase):
    # ── MUST-CATCH: a baked payload decoded and run as a shell command ──────────────
    def test_argv_nested_decode(self):
        b = _blob(1)
        self.assertTrue(analyze_file(f"spawn('sh', ['-c', Buffer.from('{b}', 'base64').toString()]);\n", ".js"))
        self.assertTrue(analyze_file(f"execFileSync('/bin/bash', ['-c', atob('{b}')]);\n", ".js"))

    def test_argv_variable_decode(self):
        b = _blob(2)
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{b}', 'base64').toString();\nspawn('sh', ['-c', d]);\n", ".js"))
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{b}', 'base64');\nexecFileSync('bash', ['-c', d.toString('utf8')]);\n", ".js"))

    def test_inline_constructed_shell_command(self):
        b = _blob(3)
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{b}', 'base64').toString();\nexecSync('sh -c ' + d);\n", ".js"))
        self.assertTrue(analyze_file(
            f"const d = atob('{b}');\nexecSync(`sh -c ${{d}}`);\n", ".js"))

    def test_interpreter_eval_flags(self):
        b = _blob(4)
        self.assertTrue(analyze_file(f"execFileSync('node', ['-e', atob('{b}')]);\n", ".js"))
        self.assertTrue(analyze_file(f"spawnSync('powershell', ['-Command', atob('{b}')]);\n", ".js"))

    def test_script_interpreters(self):
        # python -c / ruby -e / perl -e / php -r — classic real-worm code interpreters (nested form
        # is self-evident, no blob corroborator needed).
        b = _blob(8)
        self.assertTrue(analyze_file(f"spawn('python', ['-c', Buffer.from('{b}', 'base64')]);\n", ".js"))
        self.assertTrue(analyze_file(f"execFileSync('python3', ['-c', atob('{b}')]);\n", ".js"))
        self.assertTrue(analyze_file(f"spawn('ruby', ['-e', atob('{b}')]);\n", ".js"))
        self.assertTrue(analyze_file(f"execFileSync('perl', ['-e', Buffer.from('{b}', 'base64')]);\n", ".js"))
        self.assertTrue(analyze_file(f"execSync('php -r ' + Buffer.from('{b}', 'base64').toString());\n", ".js"))

    def test_env_wrapper(self):
        # `env <interp> -c <decoded>` — the real interpreter sits in argv[0] after env.
        b = _blob(9)
        self.assertTrue(analyze_file(f"spawn('/usr/bin/env', ['bash', '-c', Buffer.from('{b}', 'base64')]);\n", ".js"))
        self.assertTrue(analyze_file(
            f"const d = atob('{b}');\nspawn('env', ['python', '-c', d]);\n", ".js"))
        self.assertTrue(analyze_file(f"const d = atob('{b}');\nexecSync('env bash -c ' + d);\n", ".js"))

    def test_absolute_path_interpreters(self):
        # Basename-aware: an absolute/relative path to a known interpreter still matches.
        b = _blob(10)
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{b}', 'base64').toString();\nspawn('/opt/homebrew/bin/bash', ['-c', d]);\n", ".js"))
        self.assertTrue(analyze_file(f"execFileSync('/usr/bin/python3', ['-c', atob('{b}')]);\n", ".js"))

    def test_array_join_form(self):
        # `['sh','-c',<decoded>].join(' ')` — the shell command built by joining an array.
        b = _blob(11)
        self.assertTrue(analyze_file(f"execSync(['sh', '-c', Buffer.from('{b}', 'base64').toString()].join(' '));\n", ".js"))
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{b}', 'base64').toString();\nexecSync(['bash', '-c', d].join(' '));\n", ".js"))

    def test_cmd_slash_k(self):
        b = _blob(12)
        self.assertTrue(analyze_file(f"spawn('cmd', ['/k', Buffer.from('{b}', 'base64')]);\n", ".js"))

    def test_hex_payload_via_shell(self):
        h = _hexblob()
        self.assertTrue(analyze_file(
            f"const d = Buffer.from('{h}', 'hex').toString();\nspawn('sh', ['-c', d]);\n", ".js"))

    def test_shell_dropper_as_evil_merge_delta(self):
        b = _blob(5)
        hunk = f"const d = Buffer.from('{b}', 'base64').toString();\nspawn('sh', ['-c', d]);\n"
        self.assertTrue(analyze_delta(hunk))
        self.assertTrue(analyze_delta(hunk, baseline="export const v = '1.0.0';\n"))

    # ── MUST-CLEAR: benign shell / decode usage stays clean ─────────────────────────
    def test_false_positive_boundaries_clean(self):
        b = _blob(6)
        cases = {
            # a decoded value in a NON-code args[] slot (image bytes to imagemagick) is benign.
            "img.js": f"const K = '{b}';\nspawn('convert', ['in.png', Buffer.from(img, 'base64'), 'out.png']);\n",
            # a constant shell command (no decode, no concat).
            "const.js": "execSync('sh -c \"npm run build\"');\n",
            # a shell command built from a NON-decoded variable (config), even with a blob present.
            "cfg.js": f"const K = '{b}';\nconst cmd = cfg.command;\nexecSync('sh -c ' + cmd);\n",
            # a literal-only shell payload.
            "lit.js": f"const K = '{b}';\nspawn('sh', ['-c', 'echo done']);\n",
            # cross-scope name collision: decode `d` in one fn, an unrelated `d` param + shell in another.
            "collide.js": (f"const K = '{b}';\n"
                           "function enc(x) { const d = Buffer.from(x, 'base64'); return d; }\n"
                           "function run(d) { spawn('sh', ['-c', d]); }\n"),
            # ES6 method-shorthand param collision.
            "method.js": (f"const K = '{b}';\nconst d = Buffer.from(raw, 'base64');\ncache(d);\n"
                          "export const api = { run(d) { spawn('sh', ['-c', d]); } };\n"),
            # lone blob, no exec at all.
            "lone.ts": f"const token = '{b}';\nexport default token;\n",
            # an absolute path to a NON-interpreter with a decoded value — basename `convert` is not a
            # shell, so the path-aware matcher must not flag it.
            "abspath.js": f"const d = Buffer.from(x, 'base64');\nspawn('/usr/bin/convert', ['-c', d]);\n",
            # an array joined into a NON-shell command (`git log`) with a decoded value.
            "arrjoin.js": f"const K = '{b}';\nconst d = Buffer.from(x, 'base64');\nexecSync(['git', 'log', d].join(' '));\n",
            # `env` running a program with NO code-flag (a normal env invocation).
            "env.js": f"const K = '{b}';\nspawn('env', ['NODE_ENV=prod', 'node', 'app.js']);\n",
        }
        for name, code in cases.items():
            self.assertFalse(analyze_file(code, ".js" if name.endswith(".js") else ".ts"), name)

    # ── model predicates ────────────────────────────────────────────────────────────
    def test_model_shell_interpreter(self):
        self.assertTrue(model.is_shell_interpreter("sh"))
        self.assertTrue(model.is_shell_interpreter("/bin/bash"))
        self.assertTrue(model.is_shell_interpreter("/opt/homebrew/bin/bash"))   # basename tail
        self.assertTrue(model.is_shell_interpreter("PowerShell"))               # case-insensitive
        self.assertFalse(model.is_shell_interpreter("convert"))
        self.assertFalse(model.is_shell_interpreter("git"))

    def test_model_decode_encoding(self):
        self.assertTrue(model.is_decode_encoding("base64"))
        self.assertTrue(model.is_decode_encoding("hex"))
        self.assertFalse(model.is_decode_encoding("utf8"))
        self.assertFalse(model.is_decode_encoding("ascii"))

    def test_detect_dropper_returns_reason_or_none(self):
        b = _blob(7)
        self.assertIsInstance(
            detect_dropper(f"spawn('sh', ['-c', atob('{b}')]);\n"), str)
        self.assertIsNone(detect_dropper("spawn('sh', ['-c', 'echo hi']);\n"))
        self.assertIsNone(detect_dropper(""))


if __name__ == "__main__":
    unittest.main()

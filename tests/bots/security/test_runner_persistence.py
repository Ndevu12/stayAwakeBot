#!/usr/bin/env python3
"""Committed self-hosted-runner-persistence artifacts (#1092).

The repo scanner side, two-tier to stay honest about confidence: a *file named* `.runner` /
`.credentials` is a heuristic review signal (SUSPICIOUS — the file could be empty/unrelated),
while a `.runner` whose CONTENT is a real registration (a live serverUrl/gitHubUrl endpoint) is
confirmed → INFECTED. Basename patterns match at any depth and must not fire on near-miss names.
All against inert fixture files.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import INFECTED, SUSPICIOUS, CLEAN
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _scan(files, allow=None):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, allow or [])


# A realistic .runner registration config — carries the live registration endpoint.
_RUNNER_CONFIG = ('{"agentId":42,"agentName":"SHA1HULUD","poolId":1,'
                  '"serverUrl":"https://pipelines.actions.githubusercontent.com/abc",'
                  '"gitHubUrl":"https://github.com/acme/app","workFolder":"_work"}')


class TestRunnerPersistence(unittest.TestCase):
    def test_committed_runner_registration_is_infected(self):
        # A registered runner's .runner carries its endpoint — the confirmed, decisive signal.
        r = _scan({"actions-runner/.runner": _RUNNER_CONFIG,
                   "actions-runner/.credentials": '{"scheme":"OAuth"}'})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("runner-registration-content", ids)
        self.assertEqual(r.verdict, INFECTED)          # content is confirmed

    def test_bare_runner_filename_is_suspicious_not_infected(self):
        # A file merely NAMED .runner (empty / not an actual registration) must NOT flip the repo
        # to INFECTED on the basename alone — it is a heuristic review signal only.
        r = _scan({".runner": "{}"})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("runner-registration-config", ids)          # filename heuristic fires
        self.assertNotIn("runner-registration-content", ids)      # but no registration content
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_runner_filename_matches_at_repo_root(self):
        # Basename match must fire regardless of depth — including a root-level .runner.
        r = _scan({".runner": _RUNNER_CONFIG})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("runner-registration-config", ids)
        self.assertIn("runner-registration-content", ids)
        self.assertEqual(r.verdict, INFECTED)

    def test_lone_credentials_is_suspicious_not_infected(self):
        r = _scan({".credentials": "{}"})
        ids = {f.signature_id for f in r.findings}
        self.assertIn("runner-credentials-committed", ids)
        self.assertNotIn("runner-registration-config", ids)
        self.assertEqual(r.verdict, SUSPICIOUS)        # heuristic corroborator only

    def test_clean_repo_has_no_runner_finding(self):
        r = _scan({"src/index.js": "export const x = 1;\n", "README.md": "# hi\n"})
        self.assertEqual([f.signature_id for f in r.findings], [])
        self.assertEqual(r.verdict, CLEAN)

    def test_near_miss_filenames_do_not_fire(self):
        # `aws.credentials` / `my.runner` are not the exact runner artifacts — no false positive.
        r = _scan({"aws.credentials": "x", "my.runner": "x", "runner.txt": "x"})
        self.assertEqual([f.signature_id for f in r.findings], [])

    def test_allowlist_suppresses_by_signature(self):
        # A real install lives at actions-runner/.runner, so the recursive **/.runner glob has a
        # slash to match (note: **/.runner would NOT match a *root-level* .runner — fnmatch's `*`
        # needs the separator — but a runner dir always nests it).
        r = _scan({"actions-runner/.runner": "{}"},
                  allow=[{"signature": "runner-registration-config", "path_glob": "**/.runner"}])
        self.assertNotIn("runner-registration-config", {f.signature_id for f in r.findings})


if __name__ == "__main__":
    unittest.main()

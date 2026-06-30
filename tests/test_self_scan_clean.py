#!/usr/bin/env python3
"""Self-scan guard: this repo must scan CLEAN under its OWN committed allowlist.

The repo deliberately ships infected fixtures and detector tests that embed inert IoC
literals; `config/security.yml` allowlists each by signature, scoped to `tests/**`. If a
new IoC lands under `tests/` without a matching signature-scoped allowlist entry, the
security gate (security-sentinel.yml) goes red — this test makes that fail FAST, locally
and in `CI — install & test`, naming the fix instead of surfacing as an opaque CI failure.

It also pins the invariant the CI gate relies on: a bare `path_glob` does NOT suppress
(the scanner ignores rules without a `signature`), so the allowlist must stay
signature-scoped — the exact bug that broke the gate (a path-only inline allowlist).
"""
from __future__ import annotations

import io
import unittest
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

from stayawake.bots.security import service

REPO = Path(__file__).resolve().parents[1]


class TestSelfScanClean(unittest.TestCase):
    def test_repo_scans_clean_under_committed_allowlist(self):
        cfg = REPO / "config" / "security.yml"
        self.assertTrue(cfg.exists(), f"missing committed config: {cfg}")
        # Positional path overrides the config's local globs → scan THIS repo, using the
        # committed (signature-scoped) allowlist. Exit code is the verdict: 1 if infected.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = service.scan(str(cfg), paths=[str(REPO)], no_stream=True)
        self.assertEqual(
            rc, 0,
            "this repo flagged INFECTED under its own committed allowlist. A new IoC under "
            "tests/ likely needs a signature-scoped entry "
            "({signature: <id>, path_glob: \"tests/**\"}) in config/security.yml.")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Self-scan guard: this repo's COMMITTED files must scan CLEAN under its OWN committed allowlist.

The repo deliberately ships infected fixtures and detector tests that embed inert IoC literals;
`config/security.yml` allowlists each by signature, scoped to `tests/**`. If a new IoC lands under
`tests/` (or anywhere tracked) without a matching signature-scoped allowlist entry, the security gate
(security-sentinel.yml) goes red — this test makes that fail FAST, locally and in `CI — install & test`,
naming the fix instead of surfacing as an opaque CI failure.

It scans only git-**tracked** files — what actually ships / what the gate certifies. An untracked or
gitignored artifact in a developer's working tree (a local `venv/`, `__pycache__/` bytecode, gitignored
incident notes) is NOT part of the committed repo and must never make the tool flag ITSELF as infected:
for a security tool, a spurious self-INFECTED is a real trust problem, and it is exactly the local-vs-CI
split that made this test pass in CI (clean checkout) but fail on a working machine. A real IoC still
has to be COMMITTED to matter, and every tracked file is scanned in full.

It also pins the invariant the CI gate relies on: a bare `path_glob` does NOT suppress (the scanner
ignores rules without a `signature`), so the allowlist must stay signature-scoped — the exact bug that
broke the gate (a path-only inline allowlist).
"""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.service.config import _read_config, _options
from stayawake.bots.security.targets import LocalRepoTarget

REPO = Path(__file__).resolve().parents[1]


def _tracked_files() -> tuple[str, ...]:
    """Repo-relative paths of git-TRACKED files that exist on disk — the committed repo (what ships),
    excluding any untracked/gitignored working-tree artifact (`venv/`, `__pycache__/`, local docs).
    Empty tuple if this is not a git checkout (a source tarball) — the gate then skips."""
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    return tuple(p for p in out.split("\0") if p and (REPO / p).is_file())


class TestSelfScanClean(unittest.TestCase):
    def test_committed_repo_scans_clean_under_committed_allowlist(self):
        tracked = _tracked_files()
        if not tracked:
            self.skipTest("not a git checkout — nothing tracked to self-scan")
        cfg = REPO / "config" / "security.yml"
        self.assertTrue(cfg.exists(), f"missing committed config: {cfg}")
        conf = _read_config(str(cfg))
        settings = conf.get("settings", {})
        opts = _options(settings)
        sigs = load_signatures(settings.get("signatures_path"))
        allowlist = conf.get("allowlist") or []
        # Scan the TRACKED files with the committed allowlist. include_only restricts the per-file
        # matchers to exactly the committed set (#1325); a CONFIRMED finding here = INFECTED verdict.
        with LocalRepoTarget(str(REPO), "self", opts, include_only=tracked) as target:
            result = scan_target(target, sigs, allowlist)
        self.assertFalse(
            result.infected,
            "this repo's COMMITTED files flagged INFECTED under its own committed allowlist. A new IoC "
            "under tests/ likely needs a signature-scoped entry "
            "({signature: <id>, path_glob: \"tests/**\"}) in config/security.yml. Offending: "
            + "; ".join(f"{f.signature_id}@{f.path}"
                        for f in result.findings if f.confidence == "confirmed")[:400])


if __name__ == "__main__":
    unittest.main()

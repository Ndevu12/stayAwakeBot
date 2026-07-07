#!/usr/bin/env python3
"""osv-scanner adapter (#1125).

osv-scanner is Google's cross-ecosystem OSV auditor — it reads every lockfile type `saw` resolves
(and more) and reports OSV advisories, so it's the natural baseline external adapter. Its results
overlap our offline corpus (same OSV data), but it can be fresher than a cached `saw db update` and
covers ranges/ecosystems we defer, and the orchestrator de-dups the overlap.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from stayawake.bots.security.dependencies.ecosystems import canonical_ecosystem
from stayawake.bots.security.dependencies.external.base import (
    ExternalAuditor, ExternalFinding, run_tool)


def _severity(vuln: dict) -> str:
    ds = vuln.get("database_specific") or {}
    sev = str(ds.get("severity", "")).lower()
    return sev if sev in ("low", "moderate", "medium", "high", "critical") else "medium"


class OsvScannerAdapter(ExternalAuditor):
    name = "osv-scanner"

    def audit(self, root: str | Path,
              run: Callable[..., str | None] = run_tool) -> list[ExternalFinding]:
        out = run([self.name, "--format", "json", "--recursive", "."], root)
        if not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        findings: list[ExternalFinding] = []
        for result in (data.get("results", []) or []):
            src = str((result.get("source") or {}).get("path", "")).rsplit("/", 1)[-1]
            for pkg in (result.get("packages", []) or []):
                info = pkg.get("package") or {}
                name = str(info.get("name", ""))
                version = str(info.get("version", ""))
                eco = canonical_ecosystem(str(info.get("ecosystem", "")))
                if not (name and version):
                    continue
                for vuln in (pkg.get("vulnerabilities", []) or []):
                    vid = str(vuln.get("id", ""))
                    if vid:
                        findings.append(ExternalFinding(
                            eco, name, version, vid, _severity(vuln), self.name, src))
        return findings

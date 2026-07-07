#!/usr/bin/env python3
"""External-auditor adapter interface (#1125).

`saw` is offline and never executes scanned code — but a user can *opt in* (`saw scan --external`)
to having it run **installed** vulnerability auditors (osv-scanner, pip-audit, …) over the target
and fold their results into the advisory tier, so they don't have to run the tools by hand. This
module is the seam; concrete adapters are one small class each.

Guardrails (this crosses the offline default deliberately, so they matter):
  * OFF by default — nothing here runs unless the user passes the flag.
  * A tool that isn't installed is skipped silently (never fails the scan).
  * Tool output is read as **data** (parsed as JSON), NEVER executed; subprocesses are spawned with
    an argv list (no shell), a timeout, and the target as cwd. `saw` itself sends nothing over the
    network — a tool's own registry/API calls are the tool's behaviour, which the user opted into.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ExternalFinding:
    """A vulnerability reported by an external tool, normalized to the advisory tier."""

    ecosystem: str            # canonical PURL type (npm, pypi, …)
    package: str
    version: str
    advisory_id: str          # GHSA / CVE / OSV id
    severity: str             # low | medium | high | critical (best-effort)
    source_tool: str          # "osv-scanner", …
    source_path: str = ""     # the lockfile the tool attributed it to (basename), if any

    @property
    def key(self) -> tuple[str, str]:
        """Dedup key vs. offline-corpus advisories: (advisory id, name@version)."""
        return (self.advisory_id, f"{self.package}@{self.version}")


def run_tool(argv: list[str], cwd: str | Path, *, timeout: int = 120) -> str | None:
    """Run an external auditor and return its stdout, or None on any failure (not installed, timeout,
    crash). Auditors conventionally exit non-zero when they FIND vulnerabilities, so a non-zero exit
    is not treated as failure — the JSON on stdout is what matters. Never `shell=True`."""
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout or None


class ExternalAuditor:
    """Base adapter: is the tool installed, and what does it report for a target directory."""

    name: str = ""            # the executable to look for / invoke

    def available(self) -> bool:
        return bool(self.name) and shutil.which(self.name) is not None

    def audit(self, root: str | Path,
              run: Callable[..., str | None] = run_tool) -> list[ExternalFinding]:
        raise NotImplementedError

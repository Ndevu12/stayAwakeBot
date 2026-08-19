#!/usr/bin/env python3
"""External-auditor adapter interface."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ExternalFinding:
    """A vulnerability reported by an external tool, normalized to the advisory tier."""

    ecosystem: str
    package: str
    version: str
    advisory_id: str
    severity: str
    source_tool: str
    source_path: str = ""

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

    name: str = ""

    def available(self) -> bool:
        return bool(self.name) and shutil.which(self.name) is not None

    def audit(self, root: str | Path,
              run: Callable[..., str | None] = run_tool) -> list[ExternalFinding]:
        raise NotImplementedError

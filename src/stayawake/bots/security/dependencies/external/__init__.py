#!/usr/bin/env python3
"""External-auditor orchestration (#1125).

Runs each *installed* opted-in auditor over the target and returns their findings, de-duped —
within the external set, and against the offline-corpus advisories already emitted (`seen`). Adding
an auditor (pip-audit, cargo-audit, bundler-audit, govulncheck, npm audit, …) is one class + one
entry in ADAPTERS; the orchestrator and the matcher don't change.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from stayawake.bots.security.dependencies.external.base import (
    ExternalAuditor, ExternalFinding, run_tool)
from stayawake.bots.security.dependencies.external.osv_scanner import OsvScannerAdapter

ADAPTERS: tuple[ExternalAuditor, ...] = (OsvScannerAdapter(),)

__all__ = ["ExternalAuditor", "ExternalFinding", "run_tool", "ADAPTERS", "run_external_audit"]


def run_external_audit(root: str | Path, *, seen: Iterable[tuple[str, str]] = (),
                       adapters: tuple[ExternalAuditor, ...] = ADAPTERS,
                       run: Callable[..., str | None] = run_tool) -> list[ExternalFinding]:
    """Every installed adapter's findings for `root`, de-duped by `(advisory id, name@version)` —
    both across tools and against the already-emitted offline-corpus advisories in `seen`."""
    emitted: set[tuple[str, str]] = set(seen)
    out: list[ExternalFinding] = []
    for adapter in adapters:
        if not adapter.available():
            continue
        for finding in adapter.audit(root, run=run):
            if finding.key in emitted:
                continue
            emitted.add(finding.key)
            out.append(finding)
    return out

#!/usr/bin/env python3
"""The Sink strategy interface.

A sink is a delivery strategy for one `ScanReport`: terminal, json, sarif, file, github
issue, slack. Sinks are side-effect-only consumers — `emit()` is the whole contract, and
the exit-code verdict stays owned by `service.scan()`, never a sink. This mirrors the
`matchers/` and `targets/` strategy packages: one technique per sibling module.
"""
from __future__ import annotations

from stayawake.bots.security.models import ScanReport


class Sink:
    def emit(self, report: ScanReport) -> None:  # pragma: no cover - interface
        raise NotImplementedError

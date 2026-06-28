#!/usr/bin/env python3
"""SarifSink — write a SARIF 2.1.0 report to a file for GitHub code-scanning upload.

A file sink, so evidence is redacted: `sarif._message` fingerprints the snippet rather
than quoting it, so an uploaded SARIF never re-ships the payload. The file is meant to be
uploaded with `github/codeql-action/upload-sarif`, not committed into the tree.
"""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.bots.security import sarif
from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink


class SarifSink(Sink):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit(self, report: ScanReport) -> None:
        sarif.write_sarif(report.to_payload(), self.path)
        print(f"SARIF written to {self.path}", file=sys.stderr)

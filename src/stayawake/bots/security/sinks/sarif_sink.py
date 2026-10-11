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
from stayawake.utils import pathsafe, scratch


class SarifSink(Sink):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit(self, report: ScanReport) -> None:
        try:
            sarif.write_sarif(report.to_payload(), self.path)
        except pathsafe.RedirectedPath:
            kept = scratch.kept_dir("the SARIF log") / self.path.name
            sarif.write_sarif(report.to_payload(), kept)
            print(f"warning: SARIF path {self.path} is reached through a link saw does not follow; "
                  f"writing it to {kept} instead", file=sys.stderr)
            return
        print(f"SARIF written to {self.path}", file=sys.stderr)

#!/usr/bin/env python3
"""FileSink — the opt-in (`-d`) report bundle: latest.json + latest.md.

Off by default (the scanner persists nothing unless asked). Evidence is REDACTED here:
a kept-on-disk report must not re-distribute the live payload it detected. The terminal
sink remains the place to see full evidence.
"""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.redaction import redact_payload
from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.render import render_markdown
from stayawake.core.io import write_json


class FileSink(Sink):
    def __init__(self, reports_dir: str | Path) -> None:
        # The dir is already resolved/validated writable by service.scan before construction.
        self.dir = Path(reports_dir)

    def emit(self, report: ScanReport) -> None:
        payload = redact_payload(report.to_payload())
        write_json(self.dir / "latest.json", payload)
        (self.dir / "latest.md").write_text(render_markdown(payload), encoding="utf-8")
        print(f"Reports written to {self.dir}", file=sys.stderr)

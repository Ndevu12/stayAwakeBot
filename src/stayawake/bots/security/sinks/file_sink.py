#!/usr/bin/env python3
"""FileSink — the opt-in (`-d`) report bundle: latest.json + latest.md.

Off by default (the scanner persists nothing unless asked). Evidence is REDACTED here:
a kept-on-disk report must not re-distribute the live payload it detected. The terminal
sink remains the place to see full evidence.
"""
from __future__ import annotations

from pathlib import Path

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.redaction import redact_payload
from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.render import render_markdown
from stayawake.utils import atomicwrite
from stayawake.utils.io import write_json


class FileSink(Sink):
    def __init__(self, reports_dir: str | Path) -> None:
        self.dir = Path(reports_dir)

    def emit(self, report: ScanReport) -> None:
        payload = redact_payload(report.to_payload())
        write_json(self.dir / "latest.json", payload)
        with atomicwrite.staged(self.dir / "latest.md", mode=atomicwrite.AS_A_PLAIN_WRITE, at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK) as fh:
            fh.write(render_markdown(payload))
        # The report PATH is surfaced by the orchestrator (service.scan), which alone knows the full
        # context — a spilled sweep vs. a plain -d copy vs. a remote run — so the message is uniform

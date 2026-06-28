#!/usr/bin/env python3
"""JsonSink — machine-readable scan payload to stdout.

For piping/automation. stdout carries ONLY the JSON (scan progress goes to stderr), so
`saw scan --json | jq …` stays clean. Evidence is full: stdout is terminal-class and
ephemeral; if a user redirects it to a file that is their own persistence act.
"""
from __future__ import annotations

import json
import sys

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink


class JsonSink(Sink):
    def emit(self, report: ScanReport) -> None:
        json.dump(report.to_payload(), sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()

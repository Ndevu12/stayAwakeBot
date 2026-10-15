#!/usr/bin/env python3
"""JsonSink — machine-readable scan payload to stdout.

For piping/automation. stdout carries ONLY the JSON (scan progress goes to stderr), so
`saw scan --json | jq …` stays clean. Evidence is full: stdout is terminal-class and
ephemeral; if a user redirects it to a file that is their own persistence act.
"""
from __future__ import annotations

import json
import sys

from stayawake.bots.security.found import described
from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink


def _in_plain_words(payload: dict) -> dict:
    """Describe every finding and advisory of a payload in its own words. Takes the payload.
    Returns it."""
    for result in payload.get("results", []):
        for item in (*result.get("findings", []), *result.get("advisories", [])):
            item["description"] = described(item.get("signature_id", ""), item.get("category", ""),
                                            item.get("description"))
    return payload


class JsonSink(Sink):
    def emit(self, report: ScanReport) -> None:
        json.dump(_in_plain_words(report.to_payload()), sys.stdout, indent=2)
        sys.stdout.write("\n")
        sys.stdout.flush()

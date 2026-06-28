#!/usr/bin/env python3
"""TerminalSink — the default surface: the full human report to stdout, FULL evidence.

This is ephemeral output for the human at the keyboard, so it carries the raw evidence
snippets (never redacted). Persisting it is the user's own act (a shell redirect); the
sanctioned, redacting persistence is the file/sarif sinks.
"""
from __future__ import annotations

import os
import sys

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.render import render_terminal
from stayawake.core.streaming import Streamer


def _color_enabled() -> bool:
    """Colour only on a real stdout TTY, honouring the NO_COLOR convention. Off when
    piped/redirected/CI (isatty False) so captured output and tests stay plain text."""
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


class TerminalSink(Sink):
    def __init__(self, *, enabled: bool | None = None) -> None:
        # Results go to stdout (the convention); progress lives on stderr in service.scan.
        self._stream = Streamer(enabled=enabled, out=sys.stdout)
        self._color = _color_enabled()

    def emit(self, report: ScanReport) -> None:
        # An aligned, attention-only table for the terminal — clean targets are summarised,
        # not listed (the -d markdown bundle keeps the full inventory). Colour on a TTY.
        self._stream.write(render_terminal(report.to_payload(), color=self._color))

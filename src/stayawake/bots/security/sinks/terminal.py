#!/usr/bin/env python3
"""TerminalSink — the default surface: the full human report to stdout, FULL evidence.

This is ephemeral output for the human at the keyboard, so it carries the raw evidence
snippets (never redacted). Persisting it is the user's own act (a shell redirect); the
sanctioned, redacting persistence is the file/sarif sinks.
"""
from __future__ import annotations

import sys

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.render import render_terminal
from stayawake.core.pager import page
from stayawake.core.streaming import Streamer
from stayawake.core.terminal import supports_color

# Fleets bigger than this collapse their CLEAN rows to a count in the terminal table (the
# full inventory still ships in the --json / -d artifact). Keeps a 200-repo sweep readable.
COLLAPSE_CLEAN_OVER = 40


class TerminalSink(Sink):
    def __init__(self, *, enabled: bool | None = None, pager: bool = False,
                 detail: bool = True) -> None:
        # Results go to stdout (the convention); progress lives on stderr in service.scan.
        self._stream = Streamer(enabled=enabled, out=sys.stdout)
        # One shared decision (core.terminal): colour only on a real stdout TTY, honouring
        # NO_COLOR / CLICOLOR_FORCE / CI / TERM=dumb. Off when piped/captured so tests stay plain.
        self._color = supports_color(sys.stdout)
        self._pager = pager
        self._detail = detail

    def emit(self, report: ScanReport) -> None:
        # Aligned table (clean rows collapse to a count on a large fleet; the -d/json bundle
        # keeps the full inventory). On a large fleet `detail=False` keeps the per-finding
        # evidence out of the terminal (it lives in the written report) so the dashboard stays
        # readable. When paging is allowed, hand a long report to $PAGER so a big sweep is
        # never lost to terminal scrollback; otherwise write inline as before.
        text = render_terminal(report.to_payload(), color=self._color,
                               collapse_clean_over=COLLAPSE_CLEAN_OVER, detail=self._detail)
        if self._pager:
            page(text, enabled=True)
        else:
            self._stream.write(text)

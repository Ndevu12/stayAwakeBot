#!/usr/bin/env python3
"""TerminalSink — the default surface: the full human report to stdout, evidence in full where saw composed it, fingerprinted where it is
file content.

This is ephemeral output for the human at the keyboard, so it carries the raw evidence
snippets (never redacted). Persisting it is the user's own act (a shell redirect); the
sanctioned, redacting persistence is the file/sarif sinks.
"""
from __future__ import annotations

import sys

from stayawake.bots.security.models import ScanReport
from stayawake.bots.security.sinks.base import Sink
from stayawake.bots.security.sinks.render import render_terminal
from stayawake.utils.pager import page
from stayawake.utils.streaming import Streamer
from stayawake.utils.terminal import supports_color

COLLAPSE_CLEAN_OVER = 40


class TerminalSink(Sink):
    def __init__(self, *, enabled: bool | None = None, pager: bool = False,
                 detail: bool = True) -> None:
        self._stream = Streamer(enabled=enabled, out=sys.stdout)
        self._color = supports_color(sys.stdout)
        self._pager = pager
        self._detail = detail

    def emit(self, report: ScanReport) -> None:
        text = render_terminal(report.to_payload(), color=self._color,
                               collapse_clean_over=COLLAPSE_CLEAN_OVER, detail=self._detail)
        if self._pager:
            page(text, enabled=True)
        else:
            self._stream.write(text)

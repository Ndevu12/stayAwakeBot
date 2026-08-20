#!/usr/bin/env python3
"""Post-scan presentation helpers: the per-target verdict tag and the written-report
pointer. Text/formatting only — the report bodies live in the sinks; this module owns the
small on-screen cues the orchestrator prints around them.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from stayawake.utils.render import path_link, rule
from stayawake.utils.terminal import supports_color

if TYPE_CHECKING:
    from pathlib import Path
    from stayawake.bots.security.models import ScanResult


def _status_tag(r: ScanResult) -> str:
    """Bracketed, padded verdict tag for a per-target line (INFECTED / SUSPECT / clean)."""
    tag = ("INFECTED" if r.infected else "SUSPECT" if r.suspicious
           else "ERROR" if r.error else "clean")
    return f"[{tag:8}]"


def _print_report_pointer(report_path: Path, *, spilled: bool, reason: str = "") -> None:
    """Point the user at the written report, PROMINENTLY — in EVERY case a report is written
    (local `-d`, or any spill — large fleet or many findings, local or remote). A ruled block on
    stderr (kept off stdout so it never mixes into the report body or a pipe). Paths are coloured
    and OSC-8 `file://` hyperlinks when stderr is a colour TTY, so a click opens the file/folder
    without typing a command; when piped / NO_COLOR they stay plain text. `spilled` picks the
    wording: a spilled sweep shows only the dashboard on-screen (the detail is in the file);
    otherwise the file is a full copy for the record (e.g. `-d`)."""
    on = supports_color(sys.stderr)
    head = (f"Full report with per-finding detail saved ({reason}) — the terminal shows a summary only:"
            if spilled else "Report written — a full copy saved for the record:")
    tip = "  (click a coloured path to open it)" if on else ""
    bar = rule(72)
    print("\n".join([
        bar,
        head + tip,
        f"  \u2192 {path_link(report_path, on=on)}",
        f"    machine-readable: {path_link(report_path.with_name('latest.json'), on=on)}",
        f"    folder: {path_link(report_path.parent, on=on)}",
        bar,
    ]), file=sys.stderr)

#!/usr/bin/env python3
"""Page long human output through `$PAGER` (like git/gh), so a big report is never lost to a
terminal's finite scrollback.

A deliberate no-op — a direct write — when paging is disabled, when the text already fits the
screen, or when no pager can be launched. So piped / CI / `--no-pager` output stays
byte-for-byte plain, and a small report prints inline exactly as before.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import TextIO

# Mirrors git's classic default: -R keep colour escapes, -F don't page if it fits on one
# screen, -X leave the text on screen after quitting (so the report stays visible afterward).
_DEFAULT_PAGER = "less -R -F -X"


def page(text: str, *, enabled: bool, out: TextIO | None = None) -> None:
    """Show `text` through a pager when `enabled` AND it's taller than the terminal AND a pager
    launches; otherwise write it straight to `out` (default stdout). The caller sets `enabled`
    False when piped / CI / `--no-pager`. Never raises — any pager failure falls back to a
    direct write, so output is never dropped."""
    out = out or sys.stdout
    if not text:
        return
    if not enabled:
        out.write(text)
        out.flush()
        return
    rows = shutil.get_terminal_size((80, 24)).lines
    if text.count("\n") + 1 <= rows:                     # fits on one screen → no pager
        out.write(text)
        out.flush()
        return
    cmd = os.environ.get("PAGER") or _DEFAULT_PAGER
    try:
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, text=True)
        proc.communicate(text)
    except (OSError, BrokenPipeError):                   # no pager / it died → don't lose output
        try:
            out.write(text)
            out.flush()
        except BrokenPipeError:
            pass

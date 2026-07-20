#!/usr/bin/env python3
"""Page long human output through `$PAGER` (like git/gh), so a big report is never lost to a
terminal's finite scrollback.

A deliberate no-op — a direct write — when paging is disabled, when the text already fits the
screen, or when no pager can be launched. Paging is OPT-IN (`saw scan --pager`); by default,
and always when piped / in CI, output stays byte-for-byte plain so nothing surprises a script
or a user who didn't ask for a pager.
"""
from __future__ import annotations

import shutil
import signal
import subprocess
import sys
from typing import TextIO

from stayawake.utils import env

# `-R` keeps colour escapes; we deliberately DON'T pass `-F`/`-X`. `-F` ("quit if it fits one
# screen") is redundant — we already write short reports straight through, below — and the
# `-F -X` pair on multi-screen *piped* input makes some `less` builds redraw/repeat the body
# instead of paging it (the "stuck, garbled, …skipping…" bug). Plain `less -R` uses the
# alternate screen, so the report pages cleanly and the prompt is restored on quit. `$PAGER`
# (and `$LESS`) still win when set.
_DEFAULT_PAGER = "less -R"


def page(text: str, *, enabled: bool, out: TextIO | None = None) -> None:
    """Show `text` through a pager when `enabled` AND it's taller than the terminal AND a pager
    launches; otherwise write it straight to `out` (default stdout). The caller sets `enabled`
    False unless `saw scan --pager` was given (and never when piped / CI). Never raises — any
    pager failure falls back to a direct write, so output is never dropped."""
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
    cmd = env.get(env.PAGER, _DEFAULT_PAGER)
    # While the pager owns the terminal, ignore SIGINT in THIS process: a Ctrl+C is the user
    # quitting the pager, not killing us. Without this the interrupt hits the whole foreground
    # process group, so we'd die before printing the post-report pointer (the bug where the
    # "Full report:" line never appeared). Restored in `finally`. Best-effort — `signal()`
    # only works on the main thread, so a worker-thread call just skips the shield.
    prev = None
    try:
        prev = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        prev = None
    try:
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, text=True)
        proc.communicate(text)
    except (OSError, BrokenPipeError):                   # no pager / it died → don't lose output
        try:
            out.write(text)
            out.flush()
        except BrokenPipeError:
            pass
    finally:
        if prev is not None:
            try:
                signal.signal(signal.SIGINT, prev)
            except (ValueError, OSError):
                pass

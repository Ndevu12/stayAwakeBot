#!/usr/bin/env python3
"""Reading one answer from an operator at the terminal.

The prompt is written to the error stream (so a captured stdout stays machine-clean) and one line is
read from the input stream. `attended` answers whether there is a person to address at all.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.utils import env
from stayawake.utils.terminal import is_tty


def interactive(stdin: TextIO | None = None, stderr: TextIO | None = None) -> bool:
    """True when both the input and the prompt stream are real terminals, so a person can see a
    question and type an answer. Defaults to the process stdin and stderr."""
    return (is_tty(sys.stdin if stdin is None else stdin)
            and is_tty(sys.stderr if stderr is None else stderr))


def attended(stdin: TextIO | None = None, stderr: TextIO | None = None) -> bool:
    """True when a person is there to address: both streams are terminals and the run is not
    automated. Defaults to the process stdin and stderr."""
    return interactive(stdin, stderr) and not env.is_ci()


def ask_line(prompt: str, *, stdin: TextIO | None = None,
             stderr: TextIO | None = None) -> str | None:
    """Write `prompt` to the error stream and read one line from input, returned without its trailing
    newline. Returns None at end of input or when the stream is closed — no answer, never a crash.
    A KeyboardInterrupt is left to propagate so the operator can abort the run."""
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    try:
        stderr.write(prompt)
        stderr.flush()
        line = stdin.readline()
    except (OSError, ValueError):
        return None
    if line == "":
        return None
    return line.rstrip("\r\n")

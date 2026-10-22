"""`saw mcp` — answer an editor's agent."""
from __future__ import annotations

import os
import sys

from stayawake.bots.mcp.launch import session_binary
from stayawake.cli.helptext import add_command
from stayawake.utils import exitcodes

_NOT_VERIFIED = "saw mcp could not start. The answer is not verified."


def register(sub) -> None:
    p = add_command(
        sub, "mcp", stream=False,
        help="answer an editor's agent",
        description=(
            "Speak the Model Context Protocol on standard input and output, so an editor's agent "
            "can ask for a verdict before it installs or runs anything. The answers are the same "
            "documents as saw scan --json and saw audit --json. This does not change files. If "
            "the session cannot start, nothing is verified."),
        examples=[
            ("saw mcp", "what an editor launches and keeps open"),
        ])
    p.set_defaults(func=run)


def run(_a: object) -> int:
    binary = session_binary()
    if not binary:
        print(_NOT_VERIFIED, file=sys.stderr)
        return exitcodes.INCOMPLETE
    try:
        os.execv(binary, [binary, "--python", sys.executable])
    except OSError:
        print(_NOT_VERIFIED, file=sys.stderr)
        return exitcodes.INCOMPLETE
    return exitcodes.INCOMPLETE

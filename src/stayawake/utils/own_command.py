#!/usr/bin/env python3
"""Name the saw that is running as a command a person can type in any shell, sudo's among them."""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

_SAW_NAMES = frozenset({"saw", "stayawake"})
_ON_EVERY_SUDO_PATH = frozenset({"/usr/bin", "/bin"})
_MODULE_MAIN = Path(__file__).resolve().parent.parent / "__main__.py"


def saw_command(started_as: str | None = None, interpreter: str | None = None) -> str:
    """Return the command that runs this saw: its bare name when it sits in a directory every sudo
    searches, its absolute path when it sits anywhere else, the interpreter running its module when
    it was run as a module, and `saw` when none of those can be told. Takes the program as this
    process was started (default: its own) and the interpreter (default: the one running). Returns
    the command, quoted for a shell."""
    started_as = sys.argv[0] if started_as is None else started_as
    interpreter = sys.executable if interpreter is None else interpreter
    if not started_as:
        return "saw"
    path = os.path.abspath(started_as)
    if not os.path.isfile(path):
        return "saw"
    name = os.path.basename(path)
    if name in _SAW_NAMES:
        return name if os.path.dirname(path) in _ON_EVERY_SUDO_PATH else shlex.quote(path)
    if Path(path).resolve() == _MODULE_MAIN and interpreter:
        return f"{shlex.quote(interpreter)} -m stayawake"
    return "saw"


def saw_through_sudo() -> str:
    """Return the command that runs this saw as an administrator, through sudo, without arguments."""
    return f"sudo {saw_command()}"

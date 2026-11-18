#!/usr/bin/env python3
"""`saw` — StayAwakeBot's terse, security-only command-line interface.

A thin ROUTING layer: the dispatcher ([dispatch.py]) wires together one module per
command ([commands/]) and forwards each verb to the security `service.*` / `remediator` /
`hygiene` functions — no detection or remediation logic lives here. `saw` is the single
entry point for the security bot (terminal-first, persists nothing by default). See
docs/reference/cli.md for the user guide.

The `saw` and `stayawake` console scripts both resolve to `main` below.
"""
from __future__ import annotations

import importlib
import os
import signal
import sys


def _end_on_ctrl_c() -> None:
    """Say saw stopped, then end this process as a Ctrl-C ends a program. Never returns."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        print("saw: stopped.", file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass
    if os.name == "posix":
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGINT)
    raise SystemExit(128 + signal.SIGINT)


try:
    from stayawake.cli._meta import DEFAULT_REPORTS, VERBS, __version__
except KeyboardInterrupt:
    _end_on_ctrl_c()

__all__ = ["main", "build_parser", "VERBS", "DEFAULT_REPORTS", "__version__"]


def main(argv: list[str] | None = None) -> int:
    """Run the saw command line. Takes the arguments (default: this process's own). Returns the
    exit status; a Ctrl-C ends saw with a one-line notice instead."""
    try:
        from stayawake.cli.dispatch import main as run

        return run(argv)
    except KeyboardInterrupt:
        _end_on_ctrl_c()


def __getattr__(name: str):
    """Load `build_parser` or one of this package's modules on first use. Takes the name. Returns it."""
    if name == "build_parser":
        from stayawake.cli.dispatch import build_parser

        return build_parser
    try:
        return importlib.import_module(f"{__name__}.{name}")
    except ModuleNotFoundError as missing:
        if missing.name != f"{__name__}.{name}":
            raise
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

#!/usr/bin/env python3
"""Builds the root `saw` parser and dispatches to command handlers.

This is the only place that knows about the whole tree; it stays thin by delegating
each verb to a module in `stayawake.cli.commands`.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.cli import commands
from stayawake.cli._meta import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="saw",
        description="StayAwakeBot sentinel toolkit — local supply-chain worm hunter.",
        epilog="Run `saw <command> -h` for command-specific help.",
    )
    p.add_argument(
        "--version", action="version",
        version=(f"saw (stayawakebot) {__version__}\n"
                 "capabilities: security: local + CI; health: CI-only (stayawake-health-*)"),
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")
    for module in commands.REGISTRARS:
        module.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Hidden, reserved `saw sec <verb>` namespace: a leading `sec` token is a no-op
    # synonym today (every verb is already at the root) and a seam for a future bot.
    if argv and argv[0] == "sec":
        argv = argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)

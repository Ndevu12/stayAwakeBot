#!/usr/bin/env python3
"""Shared argparse helpers, so every repo-sweeping command exposes an IDENTICAL `-j/--jobs`
UX from ONE definition instead of a copy per command."""
from __future__ import annotations

import argparse


def jobs(value: str) -> int | None:
    """Parse `-j/--jobs`: a positive int (worker cap), or `auto`/`` → None (auto-pick). Rejects
    zero/negative/junk with a clear argparse error rather than silently disabling concurrency."""
    s = value.strip().lower()
    if s in ("auto", ""):
        return None
    try:
        count = int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--jobs must be a positive integer or 'auto', got {value!r}")
    if count < 1:
        raise argparse.ArgumentTypeError("--jobs must be >= 1 (use 1 for sequential)")
    return count


def add_no_stream_arg(parser: argparse.ArgumentParser) -> None:
    """Register the shared `--no-stream` flag — same flag, dest, help and default everywhere.

    The default is SUPPRESS rather than False so a subcommand that also carries the flag does not
    overwrite a value its parent already set; read it with `no_stream()`, never off the namespace.
    """
    parser.add_argument("--no-stream", action="store_true", dest="no_stream",
                        default=argparse.SUPPRESS,
                        help="disable live progress/typewriter output (plain, instant lines)")


def no_stream_requested(a: argparse.Namespace) -> bool:
    """Whether this run was asked for plain, instant output. Takes the parsed namespace, returns
    False when the flag was given at no level."""
    return bool(getattr(a, "no_stream", False))


def add_jobs_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    """Register the shared `-j/--jobs` flag on a sweep command — SAME type parser, flag names,
    `dest`, and `metavar` everywhere, but each command supplies its OWN `help` text (its wording
    is the command's to own, not this helper's to dictate)."""
    parser.add_argument("-j", "--jobs", type=jobs, default=None, dest="jobs", metavar="N", help=help)

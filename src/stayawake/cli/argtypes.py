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
    """Register `--stream` and `--no-stream` — same flags, destinations, help and defaults everywhere.

    The default is SUPPRESS rather than False so a subcommand that also carries a flag does not
    overwrite a value its parent already set. Read them with `stream_requested` and
    `no_stream_requested`, never off the namespace.
    """
    parser.add_argument("--stream", action="store_true", dest="force_stream",
                        default=argparse.SUPPRESS,
                        help="show live progress even when the output is not a terminal")
    parser.add_argument("--no-stream", action="store_true", dest="no_stream",
                        default=argparse.SUPPRESS,
                        help="plain instant lines; wins over --stream")


def no_stream_requested(a: argparse.Namespace) -> bool:
    """Whether this run was asked for plain, instant output. Takes the parsed namespace. Returns
    False when the flag was given at no level."""
    return bool(getattr(a, "no_stream", False))


def stream_requested(a: argparse.Namespace) -> bool:
    """Whether this run asked for live output. Takes the parsed namespace. Returns False when the
    flag was given at no level."""
    return bool(getattr(a, "force_stream", False))


def add_progress_arg(parser: argparse.ArgumentParser) -> None:
    """Register `--progress=jsonl` — one JSON object per line on stderr, for a program drawing its
    own progress. Takes the parser. The human progress stays off stderr while it is on."""
    parser.add_argument("--progress", choices=("jsonl",), default=None,
                        help="write progress as one JSON object per line on stderr "
                             "(start, step, target, done); the human progress stays off stderr")


def add_ask_arg(parser: argparse.ArgumentParser) -> None:
    """Register `--ask=jsonl`. Takes the parser. A program then answers the questions a terminal
    would ask: one JSON object per line, questions on stderr and answers on stdin."""
    parser.add_argument("--ask", choices=("jsonl",), default=None,
                        help="let a program answer the questions a terminal asks, one JSON object "
                             "per line (questions on stderr, answers on stdin)")


def ask_mode(a: argparse.Namespace) -> str | None:
    """The ask channel this run requested. Takes the parsed namespace. Returns `jsonl`, or None
    when the flag was not given."""
    return getattr(a, "ask", None)


def progress_requested(a: argparse.Namespace) -> bool:
    """Whether this run was asked for progress events. Takes the parsed namespace. Returns False
    when the flag was not given."""
    return getattr(a, "progress", None) == "jsonl"


def add_jobs_arg(parser: argparse.ArgumentParser, *, help: str) -> None:
    """Register the shared `-j/--jobs` flag on a sweep command — SAME type parser, flag names,
    `dest`, and `metavar` everywhere, but each command supplies its OWN `help` text (its wording
    is the command's to own, not this helper's to dictate)."""
    parser.add_argument("-j", "--jobs", type=jobs, default=None, dest="jobs", metavar="N", help=help)

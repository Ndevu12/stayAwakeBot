#!/usr/bin/env python3
"""Build the interactive keep/remove resolver, or None when asking the operator is not appropriate.

Asking is appropriate only when both streams are a real terminal and the run is not automated (CI).
A git hook, a pipe, or a redirect has no interactive terminal, so the terminal check already excludes
them. The run-shape half of the gate — a single local repository, never a remote or parallel run —
lives with the remediator that owns those facts.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import Resolver
from stayawake.cli.resolve.ask import ask_decision
from stayawake.utils import env, prompt


def build_resolver(stdin: TextIO | None = None,
                   stderr: TextIO | None = None) -> Resolver | None:
    """A resolver that asks the operator about each uncertain file, or None when the terminal is not
    interactive or the run is automated. Defaults to the process stdin and stderr."""
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    if not prompt.interactive(stdin, stderr) or env.is_ci():
        return None
    return lambda item: ask_decision(item, stdin=stdin, stderr=stderr)

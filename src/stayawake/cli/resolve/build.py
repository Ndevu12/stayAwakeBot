#!/usr/bin/env python3
"""Build the interactive resolver, or None when asking the operator is not appropriate.

Asking is built only when both streams are a real terminal and the run is not CI. The run-shape half
of the gate — a single local repository, never a remote or parallel run — lives with the remediator.
"""
from __future__ import annotations

import sys
from typing import TextIO

from stayawake.bots.security.pr.resolve import DeliveryQuestion, Resolver
from stayawake.cli.resolve.ask import ask_delivery, ask_resolution
from stayawake.utils import env, prompt


def build_resolver(stdin: TextIO | None = None,
                   stderr: TextIO | None = None) -> Resolver | None:
    """Build a resolver that asks the operator about each uncertain file and each delivery. Takes
    the input and prompt streams, the process's own by default. Returns it, or None when the
    terminal is not interactive or the run is automated."""
    stdin = sys.stdin if stdin is None else stdin
    stderr = sys.stderr if stderr is None else stderr
    if not prompt.attended(stdin, stderr):
        return None

    def resolve(question):
        if isinstance(question, DeliveryQuestion):
            return ask_delivery(question, stdin=stdin, stderr=stderr)
        return ask_resolution(question, stdin=stdin, stderr=stderr)

    return resolve

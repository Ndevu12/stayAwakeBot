#!/usr/bin/env python3
"""`saw watch` — one unattended pass over what is running."""
from __future__ import annotations

import argparse

from stayawake.bots.security import watch
from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "watch",
        help="end running code this machine has identified, and remember the rest",
        description=(
            "Make one pass over what is running. It ends only code the tool has identified, "
            "never asks for a password, and records what it saw so a later pass can tell "
            "something that came back from something new. What it will not end is left for "
            "`saw harden`, which runs with you present."),
        examples=[("saw watch", "make one pass now")])
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    code, text = watch.watch_once()
    print(text)
    return code

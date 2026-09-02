#!/usr/bin/env python3
"""`saw harden` — create host-level denials on this machine."""
from __future__ import annotations

import argparse

from stayawake.bots.security import harden
from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "harden",
        help="create host denials; reports in place only after a read-back",
        description=(
            "Create host-level controls on this machine. It never touches a project's "
            "dependency tree. A write is reported as in place only after it is read back; "
            "an unverifiable write is unknown, never success. It does not claim that one "
            "control protects anything else."),
        examples=[
            ("saw harden", "create the controls, then read them back"),
            ("sudo saw harden", "the same, reaching what needs privilege"),
            ("saw harden --take-back", "remove the controls it placed"),
        ])
    p.add_argument("--take-back", action="store_true",
                   help="remove the controls this command placed, and nothing else")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    code, text = harden.take_back() if a.take_back else harden.run()
    print(text)
    return code

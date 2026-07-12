#!/usr/bin/env python3
"""`saw intro` — a short, branded tour of what saw is and how to use it (issue #1177).

The fuller companion to the bare-`saw` welcome: the `Get started` block advertises it. Colour
follows the same rules as the welcome (dropped when piped / CI / NO_COLOR), so `saw intro | cat`
stays plain text. A pure print — it runs no scan and touches nothing.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.cli._banner import render_intro
from stayawake.cli._meta import __version__
from stayawake.core.terminal import color_level


def register(sub) -> None:
    p = sub.add_parser("intro", aliases=["welcome"], help="a 60-second tour of saw")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    print(render_intro(color_level(sys.stdout), __version__), end="")
    return 0

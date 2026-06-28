#!/usr/bin/env python3
"""`saw` — StayAwakeBot's terse, security-only command-line interface.

A thin ROUTING layer: the dispatcher ([dispatch.py]) wires together one module per
command ([commands/]) and forwards each verb to the security `service.*` / `remediator` /
`hygiene` functions — no detection or remediation logic lives here. `saw` is the single
entry point for the security bot (terminal-first, persists nothing by default). See
docs/CLI.md for the user guide.

The `saw` and `stayawake` console scripts both resolve to `main` below.
"""
from __future__ import annotations

from stayawake.cli._meta import DEFAULT_REPORTS, VERBS, __version__
from stayawake.cli.dispatch import build_parser, main

__all__ = ["main", "build_parser", "VERBS", "DEFAULT_REPORTS", "__version__"]

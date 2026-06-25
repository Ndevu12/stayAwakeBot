#!/usr/bin/env python3
"""`saw` — StayAwakeBot's terse, security-only command-line interface.

A thin ROUTING layer: the dispatcher ([dispatch.py]) wires together one module per
command ([commands/]) and forwards each verb to the SAME security `service.*` /
`remediator` / `hygiene` functions the legacy `stayawake-security-*` console scripts
already call — no detection or remediation logic lives here. The legacy scripts stay
installed and unchanged; `saw` is purely additive. See docs/CLI.md for the user guide.

The `saw` and `stayawake` console scripts both resolve to `main` below.
"""
from __future__ import annotations

from stayawake.cli._meta import DEFAULT_LATEST, DEFAULT_REPORTS, VERBS, __version__
from stayawake.cli.dispatch import build_parser, main

__all__ = ["main", "build_parser", "VERBS", "DEFAULT_LATEST", "DEFAULT_REPORTS", "__version__"]

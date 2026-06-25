#!/usr/bin/env python3
"""Command registry for the `saw` CLI.

Each command lives in its own module and exposes `register(subparsers)`, which adds
its parser and binds its handler via `set_defaults(func=...)`. Adding a command is a
new module here plus one entry in `REGISTRARS` — nothing in the dispatcher changes.
The list order controls help-display order.
"""
from __future__ import annotations

from . import alert, audit, completion, doctor, fix, report, run, scan, search

REGISTRARS = [scan, run, report, alert, fix, audit, search, doctor, completion]

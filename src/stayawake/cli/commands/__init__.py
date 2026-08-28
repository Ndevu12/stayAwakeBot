#!/usr/bin/env python3
"""Command registry for the `saw` CLI.

Each command lives in its own module and exposes `register(subparsers)`, which adds
its parser and binds its handler via `set_defaults(func=...)`. Adding a command is a
new module here plus one entry in `REGISTRARS` — nothing in the dispatcher changes.
The list order controls help-display order.
"""
from __future__ import annotations

from . import (audit, auth, completion, condemn, db, discard, doctor, fix, guard, hook,
               intro, scan, search)

REGISTRARS = [scan, fix, condemn, discard, audit, guard, hook, auth, search, intro, db,
              doctor, completion]

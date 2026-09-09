#!/usr/bin/env python3
"""`python -m stayawake` — the same CLI as the `saw` console script.

It exists so something saw installs can name an entry point that does not go through PATH.
"""
from __future__ import annotations

from stayawake.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

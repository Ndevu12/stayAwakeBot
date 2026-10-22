#!/usr/bin/env python3
"""Whether saw's commands run on this operating system."""
from __future__ import annotations

import sys


def saw_runs_here() -> bool:
    """Tell whether saw's commands run on this operating system. Returns the answer."""
    return sys.platform == "darwin" or sys.platform.startswith(("linux", "win"))

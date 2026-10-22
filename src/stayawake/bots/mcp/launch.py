"""Find the program an editor keeps open."""
from __future__ import annotations

import os
import shutil
import sys


def _names() -> tuple[str, ...]:
    """Name the program on this system. Returns the names, the platform one first."""
    if sys.platform == "win32":
        return ("saw-mcp.exe", "saw-mcp")
    return ("saw-mcp",)


def session_binary() -> str | None:
    """Find the program an editor keeps open. Returns its path, or None when it is not installed."""
    named = os.environ.get("SAW_MCP_BIN", "").strip()
    if named:
        return named if os.path.isfile(named) else None
    folder = os.path.dirname(os.path.abspath(sys.argv[0]))
    for name in _names():
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            return candidate
    for name in _names():
        found = shutil.which(name)
        if found:
            return found
    return None

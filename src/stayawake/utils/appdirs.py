#!/usr/bin/env python3
"""Where applications keep their per-user data on this platform."""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.utils import env

_WINDOWS_BASES = ("APPDATA", "LOCALAPPDATA")

_ROOT_AND_INNER_BY_PACKAGING = {
    "flatpak": ("~/.var/app", "config"),
    "snap": ("~/snap", "current/.config"),
}


def user_data_dirs() -> list[Path]:
    """Every directory an application keeps per-user data under, most conventional first.

    Empty on Windows when neither variable is set, which reads as "nowhere to look" rather than
    as "nothing installed" — the caller reports its own coverage.
    """
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library" / "Application Support"]
    if sys.platform.startswith("win"):
        return [Path(value) for value in (env.get(name) for name in _WINDOWS_BASES) if value]
    configured = Path(env.xdg_config_home())
    plain = home / ".config"
    return [configured] if configured == plain else [configured, plain]


def sandboxed_data_dirs() -> list[Path]:
    """The same, for applications packaged so their config lives under the packaging root.

    A flatpak or snap keeps it one level in, per application, so these are found by walking rather
    than named: the package ids are not knowable in advance.
    """
    if sys.platform == "darwin" or sys.platform.startswith("win"):
        return []
    out: list[Path] = []
    for root, inner in _ROOT_AND_INNER_BY_PACKAGING.values():
        base = Path(root).expanduser()
        try:
            entries = sorted(base.iterdir())
        except OSError:
            continue
        out += [entry / inner for entry in entries if entry.is_dir()]
    return out

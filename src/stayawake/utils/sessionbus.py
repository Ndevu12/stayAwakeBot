#!/usr/bin/env python3
"""The environment that reaches this user's own session bus, built from the user id alone."""
from __future__ import annotations

import os
import stat


def user_manager_env(*, uid=os.getuid, lstat=os.lstat, runtime_dir: str | None = None) -> dict:
    """Build the environment the user's service manager is reached with. Takes the user id, the
    stat call and an optional runtime folder. Returns the runtime folder when it is a folder this
    user owns, with the session bus added when that is this user's own socket; else nothing."""
    user = uid()
    runtime = runtime_dir or f"/run/user/{user}"
    try:
        info = lstat(runtime)
    except OSError:
        return {}
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != user:
        return {}
    bus = session_bus_env(uid=lambda: user, lstat=lstat, runtime_dir=runtime) or {}
    return {"XDG_RUNTIME_DIR": runtime, **bus}


def session_bus_env(*, uid=os.getuid, lstat=os.lstat, runtime_dir: str | None = None) -> dict | None:
    """Build the environment a program needs to reach this user's session bus. Takes the user id,
    the stat call and an optional runtime folder. Returns the two variables, or None when the bus
    socket is missing or is not a socket this user owns."""
    user = uid()
    runtime = runtime_dir or f"/run/user/{user}"
    socket_path = f"{runtime}/bus"
    try:
        info = lstat(socket_path)
    except OSError:
        return None
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != user:
        return None
    return {"XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={socket_path}"}

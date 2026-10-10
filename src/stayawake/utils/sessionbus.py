#!/usr/bin/env python3
"""The environment that reaches this user's own session bus, built from the user id alone."""
from __future__ import annotations

import os
import stat


def user_manager_env(*, uid=os.getuid, lstat=os.lstat, runtime_dir: str | None = None,
                     environ=os.environ) -> dict:
    """Build the environment the user's service manager is reached with. Takes the user id, the
    stat call, an optional runtime folder and the caller's environment. Returns the user's runtime
    folder — `/run/user/<uid>`, else the caller's — when it is a folder this user owns, with the
    session bus added when that is this user's own socket; else nothing."""
    user = uid()
    for runtime in (runtime_dir or f"/run/user/{user}", environ.get("XDG_RUNTIME_DIR")):
        if runtime and _owned_folder(runtime, user, lstat):
            bus = session_bus_env(uid=lambda: user, lstat=lstat, runtime_dir=runtime) or {}
            return {"XDG_RUNTIME_DIR": runtime, **bus}
    return {}


def _owned_folder(path: str, user: int, lstat) -> bool:
    """Tell whether a path is a folder the user owns, not a link. Takes the path, the user id and
    the stat call. Returns the answer."""
    try:
        info = lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode) and info.st_uid == user


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

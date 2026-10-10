#!/usr/bin/env python3
"""Raise a desktop notification for the user this runs as."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from dataclasses import dataclass

from stayawake.utils import textsafe
from stayawake.utils.systembin import system_binary

SENT, UNCONFIRMED, FAILED, UNAVAILABLE = "sent", "unconfirmed", "failed", "unavailable"
APP_NAME = "saw"
TIMEOUT_SECONDS = 10
TEXT_LIMIT = 240
_OSASCRIPT = ("/usr/bin/osascript",)
_BUSCTL = ("/usr/bin/busctl", "/bin/busctl")
_MARKUP = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}


@dataclass(frozen=True)
class Delivery:
    """What happened to one notification: its state, and the id a later one may replace."""
    state: str
    replaces: int = 0


def _clean(text: str) -> str:
    """Make text safe to hand to a notifier. Takes the text. Returns it bounded, free of control
    characters, and never starting with an option dash."""
    return textsafe.plain(text, limit=TEXT_LIMIT).lstrip("- ") or " "


class NoNotifier:
    """A notifier that sends nothing."""

    def send(self, title: str, body: str, *, urgent: bool = False, replaces: int = 0) -> Delivery:
        """Send nothing. Takes the notification. Returns an unavailable delivery."""
        return Delivery(UNAVAILABLE, replaces)


class OsascriptNotifier:
    """Raise a notification on macOS through the system's AppleScript runner."""

    def __init__(self, run=None, binary: str | None = None):
        self._run = run
        self._binary = binary

    def send(self, title: str, body: str, *, urgent: bool = False, replaces: int = 0) -> Delivery:
        """Raise one notification. Takes the title, the body, whether it is urgent and the id it
        replaces. Returns an unconfirmed delivery when the runner accepted it, else failed or
        unavailable."""
        binary = self._binary or system_binary(_OSASCRIPT)
        if binary is None:
            return Delivery(UNAVAILABLE, replaces)
        argv = [binary, "-e", "on run argv",
                "-e", "display notification (item 1 of argv) with title (item 2 of argv)",
                "-e", "end run", _clean(body), _clean(title)]
        try:
            done = (self._run or subprocess.run)(argv, capture_output=True,
                                                 timeout=TIMEOUT_SECONDS, env={})
            return Delivery(UNCONFIRMED if done.returncode == 0 else FAILED, replaces)
        except Exception:
            return Delivery(FAILED, replaces)


class FreedesktopNotifier:
    """Raise a notification on Linux through the session bus's notification service."""

    def __init__(self, run=None, binary: str | None = None, runtime_dir: str | None = None,
                 lstat=os.lstat, uid=os.getuid):
        self._run = run
        self._binary = binary
        self._runtime_dir = runtime_dir
        self._lstat = lstat
        self._uid = uid

    def send(self, title: str, body: str, *, urgent: bool = False, replaces: int = 0) -> Delivery:
        """Raise one notification. Takes the title, the body, whether it is urgent and the id it
        replaces. Returns a sent delivery carrying the notification's id, else failed or
        unavailable."""
        binary = self._binary or system_binary(_BUSCTL)
        env = self._session_bus()
        if binary is None or env is None:
            return Delivery(UNAVAILABLE, replaces)
        argv = [binary, "--user", f"--timeout={TIMEOUT_SECONDS}", "--", "call",
                "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications", "Notify", "susssasa{sv}i",
                APP_NAME, str(max(int(replaces), 0)), "", _escaped(title), _escaped(body),
                "0", "1", "urgency", "y", "2" if urgent else "1", "0" if urgent else "-1"]
        try:
            done = (self._run or subprocess.run)(argv, capture_output=True, text=True,
                                                 errors="replace", timeout=TIMEOUT_SECONDS + 2,
                                                 env=env)
            if done.returncode != 0:
                return Delivery(FAILED, replaces)
            return Delivery(SENT, _notification_id(done.stdout) or replaces)
        except Exception:
            return Delivery(FAILED, replaces)

    def _session_bus(self) -> dict | None:
        """Build the environment that reaches this user's own session bus. Returns it, or None when
        the bus socket is missing or is not this user's."""
        uid = self._uid()
        runtime = self._runtime_dir or f"/run/user/{uid}"
        socket_path = f"{runtime}/bus"
        try:
            info = self._lstat(socket_path)
        except OSError:
            return None
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid:
            return None
        return {"XDG_RUNTIME_DIR": runtime, "DBUS_SESSION_BUS_ADDRESS": f"unix:path={socket_path}"}


def _escaped(text: str) -> str:
    """Escape the markup a notification server may render. Takes the text. Returns it cleaned and
    escaped."""
    return "".join(_MARKUP.get(c, c) for c in _clean(text))


def _notification_id(answer: str) -> int:
    """Read the id the notification service returned. Takes busctl's answer, such as `u 12`.
    Returns the id, or 0 when there is none."""
    parts = (answer or "").split()
    ok = len(parts) == 2 and parts[0] == "u" and parts[1].isascii() and parts[1].isdigit()
    return int(parts[1][:10]) if ok else 0


def platform_notifier(platform: str | None = None):
    """Choose the notifier for this operating system. Takes an optional platform name. Returns the
    notifier, or one that sends nothing where none is supported."""
    platform = platform or sys.platform
    if platform == "darwin":
        return OsascriptNotifier()
    if platform.startswith("linux"):
        return FreedesktopNotifier()
    return NoNotifier()

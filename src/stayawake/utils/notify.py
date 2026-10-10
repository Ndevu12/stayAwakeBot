#!/usr/bin/env python3
"""Raise a desktop notification for the user this runs as."""
from __future__ import annotations

import os
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
_SESSION_BUS_ENV = ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
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
        except (OSError, subprocess.SubprocessError):
            return Delivery(FAILED, replaces)
        return Delivery(UNCONFIRMED if done.returncode == 0 else FAILED, replaces)


class FreedesktopNotifier:
    """Raise a notification on Linux through the session bus's notification service."""

    def __init__(self, run=None, binary: str | None = None, environ=None):
        self._run = run
        self._binary = binary
        self._environ = os.environ if environ is None else environ

    def send(self, title: str, body: str, *, urgent: bool = False, replaces: int = 0) -> Delivery:
        """Raise one notification. Takes the title, the body, whether it is urgent and the id it
        replaces. Returns a sent delivery carrying the notification's id, else failed or
        unavailable."""
        binary = self._binary or system_binary(_BUSCTL)
        if binary is None:
            return Delivery(UNAVAILABLE, replaces)
        argv = [binary, "--user", f"--timeout={TIMEOUT_SECONDS}", "--", "call",
                "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications", "Notify", "susssasa{sv}i",
                APP_NAME, str(max(int(replaces), 0)), "", _escaped(title), _escaped(body),
                "0", "1", "urgency", "y", "2" if urgent else "1", "0" if urgent else "-1"]
        env = {k: self._environ[k] for k in _SESSION_BUS_ENV if k in self._environ}
        try:
            done = (self._run or subprocess.run)(argv, capture_output=True, text=True,
                                                 timeout=TIMEOUT_SECONDS + 2, env=env)
        except (OSError, subprocess.SubprocessError):
            return Delivery(FAILED, replaces)
        if done.returncode != 0:
            return Delivery(FAILED, replaces)
        return Delivery(SENT, _notification_id(done.stdout) or replaces)


def _escaped(text: str) -> str:
    """Escape the markup a notification server may render. Takes the text. Returns it cleaned and
    escaped."""
    return "".join(_MARKUP.get(c, c) for c in _clean(text))


def _notification_id(answer: str) -> int:
    """Read the id the notification service returned. Takes busctl's answer, such as `u 12`.
    Returns the id, or 0 when there is none."""
    parts = (answer or "").split()
    return int(parts[1]) if len(parts) == 2 and parts[0] == "u" and parts[1].isdigit() else 0


def platform_notifier(platform: str | None = None):
    """Choose the notifier for this operating system. Takes an optional platform name. Returns the
    notifier, or one that sends nothing where none is supported."""
    platform = platform or sys.platform
    if platform == "darwin":
        return OsascriptNotifier()
    if platform.startswith("linux"):
        return FreedesktopNotifier()
    return NoNotifier()

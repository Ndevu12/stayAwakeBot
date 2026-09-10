#!/usr/bin/env python3
"""Ask this machine to keep making the pass by itself.

Places a login item on macOS or a user service on Linux, kept alive by the system. It carries no
configuration, so the only two states are exactly what saw wrote and not that.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import env


LABEL = "com.ndevu.saw.watch"

PRISTINE, ALTERED, ABSENT, UNREADABLE = "pristine", "altered", "absent", "unreadable"

PLACED, IN_PLACE, REPLACED, REMOVED, NOTHING_TO_REMOVE = (
    "placed", "in-place", "replaced", "removed", "nothing-to-remove")


UNIT = "saw-watch.service"


def supported() -> bool:
    """Whether this platform has an implementation here.

    A platform without one says so; it never reports a machine as scheduled.
    """
    return sys.platform in ("darwin", "linux")


def _linux() -> bool:
    return sys.platform.startswith("linux")


def record_path() -> Path:
    """Where saw records what it placed, so a later run can recognise its own work."""
    return Path(env.xdg_state_home()) / "saw" / "watch-install.json"


def declare(argv: list[str], path: Path | None = None) -> bool:
    """Record the argv the item was placed with. True if it was written."""
    where = path or record_path()
    try:
        where.parent.mkdir(parents=True, exist_ok=True)
        where.write_text(json.dumps({"version": 1, "argv": list(argv)}), encoding="utf-8")
    except OSError:
        return False
    return True


def recorded(path: Path | None = None) -> list[str] | None:
    """The argv saw last placed, or None when there is no readable record."""
    try:
        data = json.loads((path or record_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    argv = data.get("argv") if isinstance(data, dict) else None
    return [str(a) for a in argv] if isinstance(argv, list) and argv else None


def item_path() -> Path:
    """Where the item that keeps the pass running is kept, on this platform."""
    if _linux():
        return Path.home() / ".config" / "systemd" / "user" / UNIT
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def program() -> list[str]:
    """How the item names saw, as argv."""
    return [sys.executable, "-E", "-P", "-m", "stayawake"]


def content(saw: list[str] | None = None) -> str:
    """The exact text saw writes on this platform. Deterministic: same machine, same bytes."""
    if isinstance(saw, (str, bytes)):
        raise TypeError("saw is an argv list, not a command line")
    argv = list(saw) if saw else program()
    if _linux():
        return _unit(argv)
    return _plist(argv)


def _unit(argv: list[str]) -> str:
    """A systemd user service: started with the session, and started again if it stops."""
    return (
        "[Unit]\n"
        "Description=saw — keep checking this machine for code running with no file behind it\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "WorkingDirectory=/\n"
        f"ExecStart={' '.join(argv)} watch run\n"
        "Restart=always\n"
        "RestartSec=10\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n")


def _plist(argv: list[str]) -> str:
    """A launch agent: started at login, and started again if it stops."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'\t<key>Label</key>\n\t<string>{LABEL}</string>\n'
        '\t<key>ProgramArguments</key>\n'
        '\t<array>\n' + "".join(f'\t\t<string>{a}</string>\n' for a in [*argv, "watch", "run"])
        + '\t</array>\n'
        '\t<key>RunAtLoad</key>\n\t<true/>\n'
        '\t<key>KeepAlive</key>\n\t<true/>\n'
        '\t<key>ProcessType</key>\n\t<string>Background</string>\n'
        '\t<key>LowPriorityIO</key>\n\t<true/>\n'
        '</dict>\n'
        '</plist>\n')


def verdict(path: Path | None = None, saw: list[str] | None = None,
            record: Path | None = None) -> str:
    """What the file at `path` is to saw: pristine, altered, absent, or unreadable.

    A symlink is never pristine, whatever it points at: the target can be swapped afterwards.
    """
    where = path or item_path()
    try:
        if where.is_symlink():
            return ALTERED
        text = where.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ABSENT
    except OSError:
        return UNREADABLE
    for candidate in ([saw] if saw else [recorded(record), program()]):
        if candidate and text == content(candidate):
            return PRISTINE
    return ALTERED


def is_ours(path: Path | None = None) -> bool:
    """Whether `path` is the item this tool placed on this machine, unchanged."""
    where = Path(path) if path is not None else item_path()
    try:
        if where != item_path():
            return False
    except OSError:
        return False
    return verdict(where) == PRISTINE


_SERVICE_MANAGERS_BY_ABSOLUTE_PATH = {
    "linux": ("/usr/bin/systemctl", "/bin/systemctl"),
    "darwin": ("/bin/launchctl", "/usr/bin/launchctl"),
}


def _activator() -> str | None:
    """The service manager's own binary, or None when there is no trustworthy one."""
    for candidate in _SERVICE_MANAGERS_BY_ABSOLUTE_PATH.get("linux" if _linux() else "darwin", ()):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _activate(where: Path, run=None, binary=None) -> bool:
    """Start it now rather than at the next login. Returns whether that was done.

    Best effort: the item is written either way, so a refusal costs promptness, not the control.
    """
    run = run or subprocess.run
    binary = binary or _activator()
    if binary is None:
        return False
    if _linux():
        commands = [[binary, "--user", "daemon-reload"],
                    [binary, "--user", "enable", "--now", UNIT]]
    else:
        commands = [[binary, "bootstrap", f"gui/{os.getuid()}", str(where)]]
    try:
        for argv in commands:
            if run(argv, capture_output=True, timeout=20).returncode != 0:
                return False
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _running(run=None, binary=None) -> bool:
    """Whether the service manager currently holds the job."""
    run = run or subprocess.run
    binary = binary or _activator()
    if binary is None:
        return False
    argv = ([binary, "--user", "is-active", "--quiet", UNIT] if _linux()
            else [binary, "print", f"gui/{os.getuid()}/{LABEL}"])
    try:
        return run(argv, capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_running(run=None, binary=None) -> bool:
    """Whether the service manager currently holds the job."""
    return _running(run=run, binary=binary)


def _deactivate(where: Path, run=None, binary=None) -> None:
    """Stop it now rather than leaving it running until the next login. Best effort."""
    run = run or subprocess.run
    binary = binary or _activator()
    if binary is None:
        return
    argv = ([binary, "--user", "disable", "--now", UNIT] if _linux()
            else [binary, "bootout", f"gui/{os.getuid()}", str(where)])
    try:
        run(argv, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        pass


@dataclass
class Scheduling:
    """What settling the item did, for a caller that reports it in its own words."""
    state: str = ""
    problem: str | None = None
    active: bool = False

    @property
    def settled(self) -> bool:
        return self.problem is None and self.state in (PLACED, IN_PLACE, REPLACED)

    @property
    def changed(self) -> bool:
        return self.state in (PLACED, REPLACED)


def _write(where: Path, text: str) -> bool:
    """Write `text` to `where` atomically, and read it back. True only when the read-back matches."""
    try:
        where.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(where.parent), prefix=".saw-", suffix=where.suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(tmp, 0o644)
            os.replace(tmp, where)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except OSError:
        return False
    try:                       # read back what was WRITTEN, never a re-derived expectation
        return where.read_text(encoding="utf-8") == text
    except OSError:
        return False


def settle(path: Path | None = None, saw: list[str] | None = None, write=_write,
           activate=_activate, running=_running, record: Path | None = None) -> Scheduling:
    """Put the item in place and say what that did: placed, in place, replaced, or a problem."""
    if not supported():
        return Scheduling(problem="not implemented on this platform")
    where = path or item_path()
    was = verdict(where, saw, record)
    if was == PRISTINE:
        if running():
            return Scheduling(state=IN_PLACE, active=True)
        # The file is saw's own and the manager is not holding it: something stopped the job.
        # Putting it back is the point of running this again.
        return Scheduling(state=REPLACED, active=activate(where))
    if was == UNREADABLE:
        return Scheduling(problem="the login item could not be read")
    argv = saw or program()
    if not write(where, content(argv)):
        return Scheduling(problem="the item could not be put in place")
    declare(argv, record)
    return Scheduling(state=PLACED if was == ABSENT else REPLACED, active=activate(where))


def take_back(path: Path | None = None, saw: list[str] | None = None,
              deactivate=_deactivate, record: Path | None = None) -> str:
    """Remove the item saw placed and nothing else. Returns what was done to it."""
    where = path or item_path()
    was = verdict(where, saw, record)
    if was == ABSENT:
        return NOTHING_TO_REMOVE
    if was != PRISTINE:
        return was
    deactivate(where)
    try:
        where.unlink()
    except OSError:
        return UNREADABLE
    return REMOVED if verdict(where, saw, record) == ABSENT else ALTERED

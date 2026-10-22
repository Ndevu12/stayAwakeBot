#!/usr/bin/env python3
"""Ask this machine to keep making the pass by itself.

Places a login item on macOS or a user service on Linux, kept alive by the system. It carries no
configuration, so the only two states are exactly what saw wrote and not that.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from xml.sax.saxutils import escape

from stayawake.utils import atomicwrite, env, pathsafe, sessionbus
from stayawake.utils.host import saw_runs_here
from stayawake.utils.systembin import system_binary, windows_system_root


LABEL = "com.ndevu.saw.watch"

PRISTINE, ALTERED, ABSENT, UNREADABLE = "pristine", "altered", "absent", "unreadable"

PLACED, IN_PLACE, REPLACED, REMOVED, NOTHING_TO_REMOVE = (
    "placed", "in-place", "replaced", "removed", "nothing-to-remove")


UNIT = "saw-watch.service"
_TASK = "saw-watch"
_WINDOWS_DIRECTORY = r"C:\Windows"


def supported() -> bool:
    """Tell whether this system can keep the pass running. Returns the answer."""
    return saw_runs_here()


def _linux() -> bool:
    return sys.platform.startswith("linux")


def _windows() -> bool:
    return sys.platform.startswith("win")


def record_path() -> Path:
    """Where saw records what it placed, so a later run can recognise its own work."""
    return Path(env.xdg_state_home()) / "saw" / "watch-install.json"


def declare(argv: list[str], path: Path | None = None) -> bool:
    """Record the argv the item was placed with. True if it was written."""
    where = path or record_path()
    return atomicwrite.replace(where, json.dumps({"version": 1, "argv": list(argv)}),
                               mode=atomicwrite.AS_A_PLAIN_WRITE, at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)


def forget(path: Path | None = None) -> None:
    """Drop the record of what was placed. Best effort: it is bookkeeping, not a control."""
    try:
        (path or record_path()).unlink(missing_ok=True)
    except OSError:
        pass


def was_placed(path: Path | None = None) -> bool:
    """Tell whether this tool recorded placing an item on this machine. Takes an optional record
    path. Returns True while a record is there, readable or not."""
    try:
        return os.path.lexists(path or record_path())
    except (OSError, ValueError):
        return True


def placed_since(path: Path | None = None) -> float | None:
    """Tell when saw last placed the item. Takes an optional record path. Returns the time, or None
    when the record is missing, is a link, or cannot be read."""
    try:
        info = os.lstat(path or record_path())
    except (OSError, ValueError):
        return None
    return info.st_mtime if stat.S_ISREG(info.st_mode) else None


def recorded(path: Path | None = None) -> list[str] | None:
    """The argv saw last placed, or None when there is no readable record."""
    raw = pathsafe.read_regular_no_follow(path or record_path(), _MOST_RECORD_BYTES)
    try:
        data = json.loads(raw.decode("utf-8")) if raw is not None else None
        argv = data.get("argv") if isinstance(data, dict) else None
        if isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv):
            return list(argv)
    except Exception:
        pass
    return None


def item_path() -> Path:
    """Where the item that keeps the pass running is kept, on this platform."""
    if _linux():
        return Path.home() / ".config" / "systemd" / "user" / UNIT
    if _windows():
        return Path.home() / "AppData" / "Local" / "saw" / f"{_TASK}.xml"
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def program() -> list[str]:
    """How the item names saw, as argv."""
    return [sys.executable, "-E", "-P", "-m", "stayawake"]


_MOST_RECORD_BYTES = 256 << 10
_CANNOT_SURVIVE = ("/tmp/", "/private/tmp/", "/var/tmp/", "/dev/shm/")


def survives_a_restart(argv: list[str] | None = None) -> bool:
    """Whether the program `argv` names will still be there after a restart."""
    named = os.path.expanduser((argv or program())[0])
    return not named.startswith(_CANNOT_SURVIVE)


def content(saw: list[str] | None = None) -> str:
    """The exact text saw writes on this platform. Deterministic: same machine, same bytes."""
    if isinstance(saw, (str, bytes)):
        raise TypeError("saw is an argv list, not a command line")
    argv = list(saw) if saw else program()
    if _linux():
        return _unit(argv)
    if _windows():
        return _task(argv)
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


def _quoted(text: str) -> str:
    """Quote one task argument the way the task scheduler reads it. Takes the argument. Returns it."""
    if text and not any(c in text for c in ' \t"'):
        return text
    return '"' + text.replace('"', '\\"') + '"'


def _task(argv: list[str]) -> str:
    """A scheduled task: started at login, and started again if it stops."""
    command = escape(argv[0])
    arguments = escape(" ".join(_quoted(part) for part in [*argv[1:], "watch", "run"]))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\n"
        "<Settings>\n"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "<RestartOnFailure><Interval>PT10S</Interval><Count>999</Count></RestartOnFailure>\n"
        "<StartWhenAvailable>true</StartWhenAvailable>\n"
        "</Settings>\n"
        "<Actions><Exec>\n"
        f"<Command>{command}</Command>\n"
        f"<Arguments>{arguments}</Arguments>\n"
        f"<WorkingDirectory>{_WINDOWS_DIRECTORY}</WorkingDirectory>\n"
        "</Exec></Actions>\n"
        "</Task>\n")


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
        if not os.path.lexists(where):
            return ABSENT
    except OSError:
        return UNREADABLE
    raw = pathsafe.read_regular_no_follow(where, _MOST_RECORD_BYTES)
    if raw is None:
        return ALTERED if _larger_than(where, _MOST_RECORD_BYTES) else UNREADABLE
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ALTERED
    for candidate in ([saw] if saw else [recorded(record), program()]):
        if candidate and text == content(candidate):
            return PRISTINE
    return ALTERED


def _larger_than(where: Path, limit: int) -> bool:
    """Tell whether a path is a regular file larger than a limit. Takes the path and the limit.
    Returns the answer, False when it cannot be told."""
    try:
        info = os.lstat(where)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size > limit


def _service_env() -> dict | None:
    """Build the environment the service manager runs with. Returns the user's own runtime folder
    and session bus on Linux, or None to keep the caller's environment elsewhere."""
    return sessionbus.user_manager_env() if _linux() else None


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


def manager_candidates() -> tuple[str, ...]:
    """The service manager's own binaries on this system, as absolute paths. Returns them."""
    if _windows():
        return (os.path.join(windows_system_root(), "System32", "schtasks.exe"),)
    return _SERVICE_MANAGERS_BY_ABSOLUTE_PATH.get("linux" if _linux() else "darwin", ())


def every_manager_candidate() -> tuple[str, ...]:
    """Every service-manager binary this code names, on every system. Returns their paths."""
    windows = (os.path.join(_WINDOWS_DIRECTORY, "System32", "schtasks.exe"),)
    return tuple(path for paths in _SERVICE_MANAGERS_BY_ABSOLUTE_PATH.values() for path in paths) + windows


def _activator() -> str | None:
    """Find the service manager's own binary. Returns its path, or None when there is no
    trustworthy one."""
    return system_binary(manager_candidates())


def _account() -> int | None:
    """The account id the service manager names. Returns it, or None when this system has none."""
    getuid = getattr(os, "getuid", None)
    return getuid() if getuid is not None else None


def _register_windows(where: Path, binary: str, run) -> bool:
    """Register the task and start it. Takes the item, the service manager and the runner. Returns
    whether both were accepted."""
    raw = pathsafe.read_regular_no_follow(where, _MOST_RECORD_BYTES)
    if raw is None:
        return False
    copy = where.with_name(where.name + ".utf16")
    try:
        copy.write_bytes(raw.decode("utf-8").encode("utf-16"))
        commands = ([binary, "/Create", "/TN", _TASK, "/XML", str(copy), "/F"],
                    [binary, "/Run", "/TN", _TASK])
        for argv in commands:
            if run(argv, capture_output=True, timeout=20, env=_service_env()).returncode != 0:
                return False
        return True
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return False
    finally:
        try:
            copy.unlink(missing_ok=True)
        except OSError:
            pass


def _activate(where: Path, run=None, binary=None) -> bool:
    """Start it now rather than at the next login. Returns whether that was done.

    Best effort: the item is written either way, so a refusal costs promptness, not the control.
    """
    run = run or subprocess.run
    binary = binary or _activator()
    if binary is None:
        return False
    if _windows():
        return _register_windows(where, binary, run)
    if _linux():
        commands = [[binary, "--user", "daemon-reload"],
                    [binary, "--user", "enable", "--now", UNIT]]
    else:
        account = _account()
        if account is None:
            return False
        commands = [[binary, "bootstrap", f"gui/{account}", str(where)]]
    try:
        for argv in commands:
            if run(argv, capture_output=True, timeout=20, env=_service_env()).returncode != 0:
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
    if _windows():
        argv = [binary, "/Query", "/TN", _TASK]
    elif _linux():
        argv = [binary, "--user", "is-active", "--quiet", UNIT]
    else:
        account = _account()
        if account is None:
            return False
        argv = [binary, "print", f"gui/{account}/{LABEL}"]
    try:
        return run(argv, capture_output=True, timeout=20, env=_service_env()).returncode == 0
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
    if _windows():
        argv = [binary, "/Delete", "/TN", _TASK, "/F"]
    elif _linux():
        argv = [binary, "--user", "disable", "--now", UNIT]
    else:
        account = _account()
        if account is None:
            return
        argv = [binary, "bootout", f"gui/{account}", str(where)]
    try:
        run(argv, capture_output=True, timeout=20, env=_service_env())
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
    return atomicwrite.replace(where, text, mode=0o644, at_a_link=atomicwrite.REPLACE_A_LINK)


def settle(path: Path | None = None, saw: list[str] | None = None, write=_write,
           activate=_activate, running=_running, record: Path | None = None) -> Scheduling:
    """Put the item in place and say what that did: placed, in place, replaced, or a problem."""
    if not supported():
        return Scheduling(problem="not implemented on this platform")
    where = path or item_path()
    if not survives_a_restart(saw):
        return Scheduling(problem="the running saw would not be there after a restart")
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
    if verdict(where, saw, record) != ABSENT:
        return ALTERED
    forget(record)
    return REMOVED

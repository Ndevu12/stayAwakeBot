#!/usr/bin/env python3
"""Windows autorun surfaces: the registry Run keys, the Startup folders, scheduled tasks, automatic
services and WMI event consumers, read as `AutorunEntry` records the shared grading understands.

Every reader is passed in, so the parsing runs and is tested on any platform; `entries` reads the
machine only when it is called on Windows. A place that exists but cannot be read is added to
`unread`, so it reaches the audit as unknown, never as clean.
"""
from __future__ import annotations

import codecs
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from stayawake.utils import pathsafe

RUN_KEY = "windows-run-key"
STARTUP_FOLDER = "windows-startup-folder"
SCHEDULED_TASK = "windows-scheduled-task"
SERVICE = "windows-service"
WMI_CONSUMER = "windows-wmi-consumer"
LOCATIONS = frozenset({RUN_KEY, STARTUP_FOLDER, SCHEDULED_TASK, SERVICE, WMI_CONSUMER})

_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN_ONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
_RUN_KEYS = (
    ("HKCU", _RUN, False, "at-logon"),
    ("HKCU", _RUN_ONCE, False, "once-at-logon"),
    ("HKLM", _RUN, False, "at-logon"),
    ("HKLM", _RUN_ONCE, False, "once-at-logon"),
    ("HKLM", _RUN, True, "at-logon"),
    ("HKLM", _RUN_ONCE, True, "once-at-logon"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", False, "at-logon"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", False, "at-logon"),
)
_SERVICES = r"SYSTEM\CurrentControlSet\Services"
_AUTOMATIC_START = 2
_PROCESS_SERVICE_TYPES = frozenset({0x10, 0x20, 0x50, 0x60})
_TASK_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
_XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>")
_TRIGGERS = {"LogonTrigger": "at-logon", "BootTrigger": "at-boot", "TimeTrigger": "scheduled",
             "CalendarTrigger": "scheduled", "EventTrigger": "event-triggered",
             "RegistrationTrigger": "at-registration", "IdleTrigger": "when-idle",
             "SessionStateChangeTrigger": "at-session-change"}
_MAX_READ = 1 << 20
_PROBE_TIMEOUT = 15

_WMI_QUERY = (
    "$c = @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer "
    "-ErrorAction Stop | ForEach-Object { [pscustomobject]@{kind='command'; name=$_.Name; "
    "command=$_.CommandLineTemplate; executable=$_.ExecutablePath} }) + "
    "@(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer "
    "-ErrorAction Stop | ForEach-Object { [pscustomobject]@{kind='script'; name=$_.Name; "
    "command=$_.ScriptFileName; script=$_.ScriptText} }); ConvertTo-Json -InputObject $c -Compress"
)


def applies() -> bool:
    """Tell whether this machine is Windows. Returns the answer."""
    return os.name == "nt"


def entries(unread: list, *, registry=None, environ=None, run=None) -> list:
    """Read every Windows autorun surface on this machine. Takes the list a place that could not be
    read is added to, and optionally the registry reader, the environment and the command runner.
    Returns the entries, in a stable order."""
    from .surface import AutorunEntry
    registry = registry or _registry
    environ = os.environ if environ is None else environ
    run = run or _run
    found: list = []
    found += run_key_entries(registry, unread, AutorunEntry)
    found += startup_entries(_startup_folders(environ), unread, AutorunEntry)
    found += task_entries(_tasks_folder(environ), unread, AutorunEntry)
    found += service_entries(registry, unread, AutorunEntry)
    found += wmi_entries(run, unread, AutorunEntry)
    return found


# ── command lines ─────────────────────────────────────────────────────────────────────────────

_QUOTED_FIRST = re.compile(r'^\s*"([^"]+)"\s*(.*)$', re.S)
_EXECUTABLE_FIRST = re.compile(r"^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|lnk))"
                               r"(?=\s|$)\s*(.*)$", re.I | re.S)


def split_command(command: str) -> list[str]:
    """Split a Windows command line into the program and its arguments, as CreateProcess reads the
    program: a quoted first token, else up to the first executable extension, else the first word.
    Takes the command line. Returns the words; an empty list for an empty line."""
    command = (command or "").strip()
    if not command:
        return []
    match = _QUOTED_FIRST.match(command) or _EXECUTABLE_FIRST.match(command)
    if match:
        program, rest = match.group(1), match.group(2)
    else:
        program, _, rest = command.partition(" ")
    try:
        args = shlex.split(rest, posix=False) if rest.strip() else []
    except ValueError:
        args = rest.split()
    return [program, *args]


# ── registry Run keys and services ────────────────────────────────────────────────────────────

def run_key_entries(registry, unread: list, make) -> list:
    """Read the Run and RunOnce keys. Takes the registry reader, the unread list and the entry
    type. Returns one entry per value."""
    out = []
    for hive, key, wow64, trigger in _RUN_KEYS:
        values = registry.values(hive, key, wow64=wow64)
        view = "WOW6432Node\\" if wow64 else ""
        label = f"{hive}\\{view}{key}"
        if values is None:
            unread.append(Path(label))
            continue
        for name, data in sorted(values):
            if not isinstance(data, str) or not data.strip():
                continue
            out.append(make(location=RUN_KEY, path=Path(f"{label}\\{name}"),
                            argv=split_command(data), body=f"{name} = {data}",
                            shell_lines=[data], argv_is_exact=False, persistence=[trigger]))
    return out


def service_entries(registry, unread: list, make) -> list:
    """Read the services that start automatically and run as their own process. Takes the
    registry reader, the unread list and the entry type. Returns one entry per service."""
    names = registry.subkeys("HKLM", _SERVICES)
    if names is None:
        unread.append(Path(f"HKLM\\{_SERVICES}"))
        return []
    out = []
    for name in sorted(names):
        values = registry.values("HKLM", f"{_SERVICES}\\{name}")
        if values is None:
            unread.append(Path(f"HKLM\\{_SERVICES}\\{name}"))
            continue
        held = dict(values)
        image, start, kind = held.get("ImagePath"), held.get("Start"), held.get("Type")
        if not isinstance(image, str) or start != _AUTOMATIC_START or kind not in _PROCESS_SERVICE_TYPES:
            continue
        out.append(make(location=SERVICE, path=Path(f"HKLM\\{_SERVICES}\\{name}"),
                        argv=split_command(image), body=f"{name} = {image}", shell_lines=[image],
                        argv_is_exact=False, persistence=["at-boot"]))
    return out


# ── Startup folders ───────────────────────────────────────────────────────────────────────────

def _startup_folders(environ) -> list[Path]:
    folders = []
    if environ.get("APPDATA"):
        folders.append(Path(environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    if environ.get("PROGRAMDATA"):
        folders.append(Path(environ["PROGRAMDATA"]) / "Microsoft/Windows/Start Menu/Programs/StartUp")
    return folders


def startup_entries(folders: list[Path], unread: list, make) -> list:
    """Read what the Startup folders hold. Takes the folders, the unread list and the entry type.
    Returns one entry per file; a shortcut runs what it points at."""
    out = []
    for folder in folders:
        try:
            names = sorted(p for p in folder.iterdir() if p.is_file() and p.name.lower() != "desktop.ini")
        except FileNotFoundError:
            continue
        except OSError:
            unread.append(folder)
            continue
        for path in names:
            raw = pathsafe.read_regular_bytes(path)
            if raw is None:
                unread.append(path)
                continue
            raw = raw[:_MAX_READ]
            if path.suffix.lower() == ".lnk":
                strings = _shortcut_strings(raw)
                target = next((s for s in strings if _EXECUTABLE_FIRST.match(s)), "")
                argv = split_command(" ".join([target, *[s for s in strings if s != target][:3]]))
                body = "\n".join(strings)
            else:
                body = _text(raw)
                argv = [str(path)]
            out.append(make(location=STARTUP_FOLDER, path=path, argv=argv, body=body,
                            shell_lines=[" ".join(argv)] if argv else [], argv_is_exact=False,
                            persistence=["at-logon"]))
    return out


def _shortcut_strings(raw: bytes) -> list[str]:
    """The readable paths and arguments a shortcut file holds, in the order it holds them."""
    found = []
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", raw):
        found.append(match.group().decode("utf-16-le", "replace"))
    for match in re.finditer(rb"[\x20-\x7e]{6,}", raw):
        text = match.group().decode("ascii", "replace")
        if (":\\" in text or "%" in text) and text not in found:
            found.append(text)
    return found


# ── scheduled tasks ───────────────────────────────────────────────────────────────────────────

def _tasks_folder(environ) -> Path | None:
    root = environ.get("SystemRoot") or environ.get("SYSTEMROOT") or environ.get("windir")
    return Path(root) / "System32" / "Tasks" if root else None


def task_entries(folder: Path | None, unread: list, make) -> list:
    """Read every scheduled task's definition. Takes the Tasks folder, the unread list and the
    entry type. Returns one entry per action that runs a program."""
    if folder is None:
        return []
    out = []
    for dirpath, dirnames, filenames in os.walk(folder, onerror=lambda e: unread.append(
            Path(getattr(e, "filename", None) or folder))):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            raw = pathsafe.read_regular_bytes(path)
            if raw is None:
                unread.append(path)
                continue
            parsed = parse_task(raw[:_MAX_READ])
            if parsed is None:
                unread.append(path)
                continue
            actions, triggers, hidden = parsed
            body = _text(raw[:_MAX_READ])
            for command, arguments in actions:
                line = f"{command} {arguments}".strip()
                out.append(make(location=SCHEDULED_TASK, path=path, argv=split_command(line),
                                body=body, shell_lines=[line], argv_is_exact=False,
                                persistence=list(triggers),
                                notes="hidden from the Task Scheduler list" if hidden else ""))
    return out


def parse_task(raw: bytes) -> tuple[list[tuple[str, str]], list[str], bool] | None:
    """Read one task definition. Takes its bytes. Returns its program actions as (command,
    arguments), its triggers, and whether it is hidden; None when it is not a task definition."""
    text = _XML_DECLARATION.sub("", _text(raw), count=1)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    if not root.tag.endswith("Task"):
        return None
    ns = _TASK_NS if root.tag.startswith(_TASK_NS) else ""
    actions = []
    for exec_ in root.iter(f"{ns}Exec"):
        command = (exec_.findtext(f"{ns}Command") or "").strip()
        if command:
            actions.append((command, (exec_.findtext(f"{ns}Arguments") or "").strip()))
    triggers = []
    for trigger in root.iter():
        name = trigger.tag[len(ns):] if ns and trigger.tag.startswith(ns) else trigger.tag
        if name in _TRIGGERS and _TRIGGERS[name] not in triggers:
            triggers.append(_TRIGGERS[name])
    hidden = (root.findtext(f"{ns}Settings/{ns}Hidden") or "").strip().lower() == "true"
    return actions, triggers, hidden


# ── WMI event consumers ───────────────────────────────────────────────────────────────────────

def wmi_entries(run, unread: list, make) -> list:
    """Read the WMI event consumers that run a command or a script. Takes the command runner, the
    unread list and the entry type. Returns one entry per consumer."""
    label = Path("WMI root\\subscription")
    done = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WMI_QUERY])
    if done is None or done.returncode != 0:
        unread.append(label)
        return []
    try:
        listed = json.loads(done.stdout or "[]")
    except ValueError:
        unread.append(label)
        return []
    listed = listed if isinstance(listed, list) else [listed]
    out = []
    for item in listed:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        command = str(item.get("command") or item.get("executable") or "")
        script = str(item.get("script") or "")
        out.append(make(location=WMI_CONSUMER, path=Path(f"{label}\\{name}"),
                        argv=split_command(command), body="\n".join(filter(None, [command, script])),
                        shell_lines=[command] if command else [], argv_is_exact=False,
                        persistence=["wmi-event"], script=script,
                        notes="runs a script" if item.get("kind") == "script" else ""))
    return out


# ── what the grading needs to know about Windows ──────────────────────────────────────────────

_TRUSTED_ROOTS = ("c:/windows/", "c:/program files/", "c:/program files (x86)/",
                  "%systemroot%/", "%windir%/", "%programfiles%/", "%programfiles(x86)%/",
                  "/systemroot/", "system32/")
_USER_WRITABLE = ("/appdata/local/temp/", "/windows/temp/", "%temp%/", "%tmp%/", "/users/public/",
                  "/downloads/", "/$recycle.bin/", "%localappdata%/temp/")


def is_windows_path(path: str) -> bool:
    """Tell whether a path is written the Windows way. Takes the path. Returns the answer."""
    return bool(re.match(r"^(?:[A-Za-z]:[\\/]|%\w+%|\\\\|\\SystemRoot\\)", path or ""))


def classify_path(path: str) -> str:
    """Grade where a Windows program lives: trusted, untrusted or unknown. Takes the path. Returns
    the class."""
    low = _expanded(path).replace("\\", "/").lower()
    if any(part in low for part in _USER_WRITABLE):
        return "untrusted"
    if low.startswith(_TRUSTED_ROOTS):
        return "trusted"
    return "unknown"


def in_user_writable_folder(path: str) -> bool:
    """Tell whether a Windows path is in a folder any program the user runs can write to, such as a
    temporary folder. Takes the path. Returns the answer."""
    return classify_path(path) == "untrusted"


_SHAPES = (
    (re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s[-/]e(?:nc?|ncodedcommand|ncoded|c)?\s+"
                r"[A-Za-z0-9+/=]{16,}", re.I), "runs an encoded PowerShell command"),
    (re.compile(r"(?:\biex\b|invoke-expression)[^\n]*(?:\biwr\b|\birm\b|invoke-webrequest|"
                r"invoke-restmethod|downloadstring|net\.webclient)|(?:\biwr\b|\birm\b|invoke-webrequest|"
                r"invoke-restmethod|downloadstring|net\.webclient)[^\n]*(?:\|\s*iex\b|invoke-expression)",
                re.I), "downloads code and runs it"),
    (re.compile(r"\bmshta(?:\.exe)?\b\s+[\"']?(?:https?:|javascript:|vbscript:)", re.I),
     "runs a script through mshta"),
    (re.compile(r"\brundll32(?:\.exe)?\b[^\n]*javascript:", re.I), "runs a script through rundll32"),
    (re.compile(r"\bregsvr32(?:\.exe)?\b[^\n]*/i:\s*[\"']?https?:", re.I),
     "loads a script from the internet through regsvr32"),
    (re.compile(r"\bcertutil(?:\.exe)?\b[^\n]*-urlcache[^\n]*https?:", re.I),
     "downloads a file through certutil"),
    (re.compile(r"\bbitsadmin(?:\.exe)?\b[^\n]*/transfer\b", re.I), "downloads a file through bitsadmin"),
)
_RUNNERS = re.compile(r"(?:^|[\\/])(?:wscript|cscript|mshta|powershell|pwsh|cmd|node|python[0-9.]*|"
                      r"rundll32|regsvr32)(?:\.exe)?$", re.I)


def command_shapes(entry) -> list[str]:
    """Name the decisive Windows shapes in one entry's command: an encoded or downloaded
    PowerShell command, a script run through a built-in program, a download through one, code run
    from a folder any program can write to, or a WMI consumer that runs a script. Takes the entry.
    Returns the reasons; none for an entry that is not a Windows one."""
    if entry.location not in LOCATIONS:
        return []
    text = "\n".join([" ".join(entry.argv), *entry.shell_lines, entry.body])
    reasons = [why for pattern, why in _SHAPES if pattern.search(text)]
    if entry.location == WMI_CONSUMER and entry.script.strip():
        reasons.append("runs a script through a WMI event subscription")
    words = entry.argv[1:] if entry.argv and _RUNNERS.search(entry.argv[0]) else entry.argv[:1]
    if any(is_windows_path(w.strip("\"'")) and in_user_writable_folder(w.strip("\"'")) for w in words):
        reasons.append("runs code from a folder any program can write to")
    return list(dict.fromkeys(reasons))


# ── readers ───────────────────────────────────────────────────────────────────────────────────

def _expanded(path: str) -> str:
    return os.path.expandvars(path) if applies() else path


def _text(raw: bytes) -> str:
    for bom, codec in ((codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
                       (codecs.BOM_UTF8, "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(codec, "replace")
    if len(raw) > 1 and raw[1:2] == b"\x00":
        return raw.decode("utf-16-le", "replace")
    return raw.decode("utf-8", "replace")


def _run(argv: list[str]):
    try:
        return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              timeout=_PROBE_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


class _Registry:
    """Read the Windows registry without changing it."""

    def _open(self, hive: str, key: str, wow64: bool):
        import winreg
        root = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]
        view = winreg.KEY_WOW64_32KEY if wow64 else winreg.KEY_WOW64_64KEY
        return winreg.OpenKey(root, key, 0, winreg.KEY_READ | view)

    def values(self, hive: str, key: str, *, wow64: bool = False) -> list[tuple[str, object]] | None:
        """List a key's values. Returns (name, data) pairs, [] when the key is absent, None when it
        cannot be read."""
        import winreg
        try:
            handle = self._open(hive, key, wow64)
        except FileNotFoundError:
            return []
        except OSError:
            return None
        out = []
        with handle:
            index = 0
            while True:
                try:
                    name, data, _kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                out.append((name, data))
                index += 1
        return out

    def subkeys(self, hive: str, key: str) -> list[str] | None:
        """List a key's subkeys. Returns their names, [] when the key is absent, None when it
        cannot be read."""
        import winreg
        try:
            handle = self._open(hive, key, False)
        except FileNotFoundError:
            return []
        except OSError:
            return None
        out = []
        with handle:
            index = 0
            while True:
                try:
                    out.append(winreg.EnumKey(handle, index))
                except OSError:
                    break
                index += 1
        return out


_registry = _Registry()

__all__ = ["LOCATIONS", "applies", "entries", "split_command", "parse_task", "classify_path",
           "is_windows_path", "in_user_writable_folder", "command_shapes"]

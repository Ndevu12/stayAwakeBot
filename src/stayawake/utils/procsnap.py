#!/usr/bin/env python3
"""Running-process snapshot — the real argv of each live process, or an explicit refusal."""
from __future__ import annotations

import ctypes
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

_CTL_KERN = 1
_KERN_ARGMAX = 8
_KERN_PROCARGS2 = 49
_ARGMAX_FALLBACK = 256 * 1024
_PS_TIMEOUT = 10


@dataclass(frozen=True)
class Process:
    """One live process. `argv` is the kernel's vector, never a re-split string.

    `argv_unreadable` is the load-bearing field: it distinguishes "this process runs no arguments"
    from "we were not allowed to look", which are the same empty list to a caller that only checks
    truthiness."""
    pid: int
    argv: tuple[str, ...] = ()
    argv_unreadable: bool = False

    @property
    def program(self) -> str | None:
        return self.argv[0] if self.argv else None


@dataclass
class Snapshot:
    """Every process this user could enumerate, and an honest account of what was refused."""
    processes: list[Process] = field(default_factory=list)
    unreadable: int = 0
    supported: bool = True

    def scope_note(self) -> str:
        """What this snapshot did NOT see — for a report that must not imply it saw everything."""
        if not self.supported:
            return (f"process arguments cannot be read on {sys.platform} — no start-up command was "
                    f"examined for any running process")
        if self.unreadable:
            # `processes` already holds the refused ones — adding `unreadable` again reported 740 of
            # 543, and a scope note that overstates what it missed is as untrustworthy as one that
            # understates it.
            return (f"{self.unreadable} of {len(self.processes)} running processes did not yield "
                    f"their arguments (processes of other users); their command lines were not "
                    f"examined")
        return ""


def _argv_from_procargs2(pid: int, argmax: int) -> tuple[str, ...] | None:
    """macOS: `KERN_PROCARGS2` → `argc`, the exec path, then argc NUL-separated arguments.

    Returns None when the kernel refuses (another uid, or the process exited mid-read) — never an
    empty tuple, because empty is a real answer for a process invoked with no arguments."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        buf = ctypes.create_string_buffer(argmax)
        size = ctypes.c_size_t(argmax)
        mib = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, pid)
        if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0:
            return None
    except (OSError, AttributeError, ValueError):
        return None
    raw = buf.raw[:size.value]
    if len(raw) < 4:
        return None
    argc = int.from_bytes(raw[:4], sys.byteorder)
    if argc <= 0:
        return None
    parts = raw[4:].split(b"\0")
    args, seen_path = [], False
    for part in parts:
        if not seen_path:
            seen_path = True
            continue
        if not part and not args:
            continue                    # alignment padding between the path and argv[0]
        if len(args) >= argc:
            break
        args.append(part.decode("utf-8", "replace"))
    return tuple(args) if args else None


def _argv_from_proc(pid: int) -> tuple[str, ...] | None:
    """Linux: `/proc/<pid>/cmdline` is already the NUL-separated vector."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, ValueError):
        return None
    if not raw:
        return None                     # a kernel thread, or refused
    return tuple(p.decode("utf-8", "replace") for p in raw.split(b"\0") if p)


def _argmax() -> int:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        val = ctypes.c_int(0)
        size = ctypes.c_size_t(ctypes.sizeof(val))
        mib = (ctypes.c_int * 2)(_CTL_KERN, _KERN_ARGMAX)
        if libc.sysctl(mib, 2, ctypes.byref(val), ctypes.byref(size), None, 0) == 0 and val.value > 0:
            return val.value
    except (OSError, AttributeError, ValueError):
        pass
    return _ARGMAX_FALLBACK


def _live_pids() -> list[int]:
    """Just the pid list — the one thing `ps` is safe for, because a pid has no quoting to lose."""
    if sys.platform.startswith("linux"):
        try:
            return sorted(int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit())
        except OSError:
            return []
    try:                                # macOS has no /proc; listing pids needs no privilege
        out = subprocess.run(["ps", "-axo", "pid="], capture_output=True, text=True,
                             timeout=_PS_TIMEOUT).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return sorted(int(tok) for tok in out.split() if tok.isdigit())


def snapshot() -> Snapshot:
    """Every running process this user can enumerate, with the kernel's argv where readable.

    Never raises: an unsupported platform, a refused process or a process that exits mid-read all
    resolve to a counted refusal, because a snapshot that throws leaves the caller with nothing to
    report and a snapshot that lies leaves it reporting an all-clear."""
    if sys.platform == "darwin":
        argmax = _argmax()
        read = lambda pid: _argv_from_procargs2(pid, argmax)   # noqa: E731 — one-line dispatch
    elif sys.platform.startswith("linux"):
        read = _argv_from_proc
    else:
        return Snapshot(supported=False)

    snap = Snapshot()
    for pid in _live_pids():
        argv = read(pid)
        if argv is None:
            snap.unreadable += 1
            snap.processes.append(Process(pid=pid, argv_unreadable=True))
        else:
            snap.processes.append(Process(pid=pid, argv=argv))
    return snap

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

_PROC_PIDTBSDINFO = 3
_ESRCH = 3
_EPERM = 1

#: What an identity read found. A pid alone is not an identity: pids are recycled, so a caller that
#: signals on a pid it read a moment ago can hit a stranger.
RUNNING, GONE, NOT_OURS, UNSUPPORTED = "running", "gone", "not-ours", "unsupported"

#: macOS `p_stat`. A ZOMBIE has been killed and not yet reaped by its parent: it executes nothing,
#: and a caller asking "did it die" must count it dead.
_SZOMB = 5


@dataclass(frozen=True)
class Identity:
    """Who a process is, in the only terms that survive a pid being reused.

    `start_time` is the discriminator. Two processes can share a pid over a machine's life; they
    cannot share a pid and a start time, so a signal guarded by both cannot land on a stranger.
    """
    pid: int
    ppid: int
    uid: int
    start_time: int
    zombie: bool = False

    def is_same(self, other: "Identity | None") -> bool:
        return other is not None and (self.pid, self.start_time) == (other.pid, other.start_time)


class _BsdInfo(ctypes.Structure):
    """`struct proc_bsdinfo` from `sys/proc_info.h`. Read whole and length-checked, so a layout
    that ever changes under us fails the read instead of yielding a plausible wrong number."""
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class Process:
    """One live process. `argv` is the kernel's vector, never a re-split string.

    `argv_unreadable` is the load-bearing field: it distinguishes "this process runs no arguments"
    from "we were not allowed to look", which are the same empty list to a caller that only checks
    truthiness."""
    pid: int
    argv: tuple[str, ...] = ()
    argv_unreadable: bool = False
    identity: "Identity | None" = None

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


def _identity_darwin(pid: int) -> tuple["Identity | None", str]:
    """Read one process's identity through libproc.

    The errno is the answer, not a detail: ESRCH means the process is not executing — which covers a
    ZOMBIE, whose bsdinfo is already gone while `kill(pid, 0)` still reports it alive. EPERM means it
    is running and belongs to someone else, which is also the boundary where signalling it fails, so
    a caller never has to guess which of the two it hit.
    """
    try:
        libc = ctypes.CDLL("libproc.dylib", use_errno=True)
    except OSError:
        return None, UNSUPPORTED
    info = _BsdInfo()
    ctypes.set_errno(0)
    read = libc.proc_pidinfo(ctypes.c_int(pid), ctypes.c_int(_PROC_PIDTBSDINFO),
                             ctypes.c_uint64(0), ctypes.byref(info),
                             ctypes.c_int(ctypes.sizeof(info)))
    if read == ctypes.sizeof(info):
        return Identity(pid=pid, ppid=int(info.pbi_ppid), uid=int(info.pbi_uid),
                        start_time=int(info.pbi_start_tvsec),
                        zombie=int(info.pbi_status) == _SZOMB), RUNNING
    err = ctypes.get_errno()
    if err == _EPERM:
        return None, NOT_OURS
    if err == _ESRCH:
        return None, GONE
    return None, GONE


def _identity_linux(pid: int) -> tuple["Identity | None", str]:
    """Read one process's identity from `/proc`.

    `stat` is parsed from the LAST `)` because a program name may contain spaces and brackets, which
    is what breaks every split-on-whitespace reading of this file.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        status = Path(f"/proc/{pid}/status").read_text()
    except FileNotFoundError:
        return None, GONE
    except PermissionError:
        return None, NOT_OURS
    except OSError:
        return None, GONE
    try:
        fields = raw[raw.rindex(")") + 2:].split()
        state, ppid, start = fields[0], int(fields[1]), int(fields[19])
    except (ValueError, IndexError):
        return None, GONE
    uid = -1
    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                uid = int(line.split()[1])
            except (ValueError, IndexError):
                uid = -1
            break
    return Identity(pid=pid, ppid=ppid, uid=uid, start_time=start,
                    zombie=state == "Z"), RUNNING


def identify(pid: int) -> tuple["Identity | None", str]:
    """This process's identity and what the read found: RUNNING, GONE, NOT_OURS or UNSUPPORTED."""
    if sys.platform == "darwin":
        return _identity_darwin(pid)
    if sys.platform.startswith("linux"):
        return _identity_linux(pid)
    return None, UNSUPPORTED


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


def ps_signature(pid: int) -> str | None:
    """A stable discriminator for ANY process, including one this user may not read.

    `identify` answers NOT_OURS for another user's process, so a caller that needs privilege to
    signal one has no way to tell, a moment later, that the pid still means the same thing. `ps`
    reports a start time for every process without needing any, and the string is compared to
    itself rather than parsed — no locale, no date format to get wrong.
    """
    if sys.platform.startswith("linux"):
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            fields = raw[raw.rindex(")") + 2:].split()
            return f"{fields[1]}|{fields[19]}"
        except (OSError, ValueError, IndexError):
            return None
    try:
        out = subprocess.run(["ps", "-o", "ppid=,uid=,lstart=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=_PS_TIMEOUT,
                             env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        return None
    line = " ".join(out.stdout.split())
    return line or None


def parent_map() -> dict[int, int]:
    """Every pid's parent, including processes this user may not otherwise read.

    `identify` needs permission and answers NOT_OURS for a root-owned process. An ancestor walk
    built on it therefore stops at the first one it cannot read — and on a default macOS terminal
    that is a uid-0 `login` sitting between the shell and the terminal application, so everything
    above it silently stops being recognised as an ancestor.
    """
    if sys.platform.startswith("linux"):
        out: dict[int, int] = {}
        try:
            pids = [int(d.name) for d in Path("/proc").iterdir() if d.name.isdigit()]
        except OSError:
            return out
        for pid in pids:
            try:
                raw = Path(f"/proc/{pid}/stat").read_text()
                out[pid] = int(raw[raw.rindex(")") + 2:].split()[1])
            except (OSError, ValueError, IndexError):
                continue
        return out
    try:
        text = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True,
                              timeout=_PS_TIMEOUT).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    pairs: dict[int, int] = {}
    for line in text.splitlines():
        bits = line.split()
        if len(bits) == 2 and bits[0].isdigit() and bits[1].isdigit():
            pairs[int(bits[0])] = int(bits[1])
    return pairs


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
        who, _state = identify(pid)
        if argv is None:
            snap.unreadable += 1
            snap.processes.append(Process(pid=pid, argv_unreadable=True, identity=who))
        else:
            snap.processes.append(Process(pid=pid, argv=argv, identity=who))
    return snap

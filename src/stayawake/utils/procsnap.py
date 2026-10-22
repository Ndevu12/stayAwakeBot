#!/usr/bin/env python3
"""Running-process snapshot — the real argv of each live process, or an explicit refusal."""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils.systembin import system_binary, windows_system_root

_CTL_KERN = 1
_KERN_ARGMAX = 8
_KERN_PROCARGS2 = 49
_ARGMAX_FALLBACK = 256 * 1024
_PS_TIMEOUT = 10
_PS = ("/bin/ps", "/usr/bin/ps")
_PS_ENV = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}

_PROC_PIDTBSDINFO = 3
_PROC_PIDPATHINFO_MAXSIZE = 4096
_EPERM = 1

RUNNING, GONE, NOT_OURS, UNSUPPORTED = "running", "gone", "not-ours", "unsupported"

_SZOMB = 5


@dataclass(frozen=True)
class Identity:
    """Who a process is, in terms that survive a pid being reused."""
    pid: int
    ppid: int
    uid: int
    start_time: int
    zombie: bool = False
    held_uids: tuple[int, ...] = field(default=(), compare=False)

    def is_same(self, other: "Identity | None") -> bool:
        return other is not None and (self.pid, self.start_time) == (other.pid, other.start_time)


class _BsdInfo(ctypes.Structure):
    """`struct proc_bsdinfo` from `sys/proc_info.h`, read whole and length-checked."""
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


def _bsd_info(pid: int) -> tuple["_BsdInfo | None", str]:
    """Read one process's `proc_bsdinfo` through libproc. Takes the pid. Returns it and RUNNING, or
    None and GONE, NOT_OURS or UNSUPPORTED."""
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
        return info, RUNNING
    return None, NOT_OURS if ctypes.get_errno() == _EPERM else GONE


def _identity_darwin(pid: int) -> tuple["Identity | None", str]:
    """One process's identity through libproc, as `(Identity | None, state)`."""
    info, state = _bsd_info(pid)
    if info is None:
        return None, state
    return Identity(pid=pid, ppid=int(info.pbi_ppid), uid=int(info.pbi_uid),
                    start_time=int(info.pbi_start_tvsec),
                    zombie=int(info.pbi_status) == _SZOMB,
                    held_uids=(int(info.pbi_ruid), int(info.pbi_uid), int(info.pbi_svuid))), RUNNING


def _identity_linux(pid: int) -> tuple["Identity | None", str]:
    """One process's identity from `/proc`, as `(Identity | None, state)`."""
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
    uid, held = -1, ()
    for line in status.splitlines():
        if line.startswith("Uid:"):
            try:
                held = tuple(int(value) for value in line.split()[1:])
                uid = held[0]
            except (ValueError, IndexError):
                uid, held = -1, ()
            break
    return Identity(pid=pid, ppid=ppid, uid=uid, start_time=start,
                    zombie=state == "Z", held_uids=held), RUNNING


@dataclass(frozen=True)
class Start:
    """When a process started, as wall-clock nanoseconds, the short name of what it runs, and its
    parent."""
    at_ns: int
    name: str
    ppid: int


def _started_darwin(pid: int) -> "Start | None":
    info, _ = _bsd_info(pid)
    if info is None:
        return None
    at_ns = int(info.pbi_start_tvsec) * 1_000_000_000 + int(info.pbi_start_tvusec) * 1_000
    return Start(at_ns, info.pbi_comm.decode("utf-8", "replace"), int(info.pbi_ppid))


def _started_linux(pid: int) -> "Start | None":
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        booted = Path("/proc/stat").read_text()
        ticks = os.sysconf("SC_CLK_TCK")
        name = raw[raw.index("(") + 1:raw.rindex(")")]
        fields = raw[raw.rindex(")") + 2:].split()
        ppid, since_boot = int(fields[1]), int(fields[19])
        boot = next(int(line.split()[1]) for line in booted.splitlines() if line.startswith("btime "))
    except (OSError, ValueError, IndexError, StopIteration):
        return None
    if ticks <= 0:
        return None
    return Start(boot * 1_000_000_000 + since_boot * 1_000_000_000 // ticks, name, ppid)


def started(pid: int) -> "Start | None":
    """Read when a process started. Takes the pid. Returns its start, never later than the real one,
    with its program's short name and its parent, or None when it cannot be read."""
    if sys.platform == "darwin":
        return _started_darwin(pid)
    if sys.platform.startswith("linux"):
        return _started_linux(pid)
    if sys.platform.startswith("win"):
        row, _state = _windows_row(pid)
        if row is None:
            return None
        name = os.path.basename(row["path"]) if row["path"] else ""
        return Start(row["start"] * 1_000_000, name, row["ppid"])
    return None


def identify(pid: int) -> tuple["Identity | None", str]:
    """This process's identity and what the read found: RUNNING, GONE, NOT_OURS or UNSUPPORTED."""
    if sys.platform == "darwin":
        return _identity_darwin(pid)
    if sys.platform.startswith("linux"):
        return _identity_linux(pid)
    if sys.platform.startswith("win"):
        row, state = _windows_row(pid)
        if row is None:
            return None, state
        return _identity_of(row), RUNNING
    return None, UNSUPPORTED


def _run_ps(*args: str) -> str | None:
    """Run the system's own `ps`. Takes its arguments. Returns what it printed, or None when the
    system has no `ps` of its own or it could not run."""
    binary = system_binary(_PS)
    if binary is None:
        return None
    try:
        return subprocess.run([binary, *args], capture_output=True, text=True, timeout=_PS_TIMEOUT,
                              env=_PS_ENV).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def _live_pids() -> list[int]:
    """Just the pid list — the one thing `ps` is safe for, because a pid has no quoting to lose."""
    if sys.platform.startswith("linux"):
        try:
            return sorted(int(p.name) for p in Path("/proc").iterdir() if p.name.isdigit())
        except OSError:
            return []
    out = _run_ps("-axo", "pid=")      # macOS has no /proc; listing pids needs no privilege
    if out is None:
        return []
    return sorted(int(tok) for tok in out.split() if tok.isdigit())


def program_path(pid: int) -> str | None:
    """The file a process is executing, or None when it cannot be read."""
    if sys.platform.startswith("linux"):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
    if sys.platform.startswith("win"):
        row, _state = _windows_row(pid)
        return row["path"] if row is not None else None
    try:
        libc = ctypes.CDLL("libproc.dylib", use_errno=True)
    except OSError:
        return None
    buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    if libc.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(len(buf))) <= 0:
        return None
    return buf.value.decode("utf-8", "replace") or None


_DELETED = " (deleted)"
_WRITABLE_BY_OTHERS = 0o022
_MEMORY_FILESYSTEM_KINDS = frozenset({0x01021994, 0x858458F6})
_STATFS_BYTES = 256


def _running_file(pid: int) -> os.stat_result:
    """Read the status of the file `pid` executes. Takes the pid. Returns its status; raises
    OSError when it cannot be read."""
    return os.stat(f"/proc/{pid}/exe")


def _filesystem_of(pid: int) -> int:
    """Read the kind of filesystem the file `pid` executes lives on. Takes the pid. Returns the
    kernel's number for it; raises OSError when it cannot be read."""
    if not sys.platform.startswith("linux"):
        raise OSError(0, "only Linux describes a running file's filesystem")
    libc = ctypes.CDLL(None, use_errno=True)
    status = ctypes.create_string_buffer(_STATFS_BYTES)
    if libc.statfs(f"/proc/{pid}/exe".encode(), status) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return ctypes.c_ulong.from_buffer(status).value & 0xFFFFFFFF


def _account_of(pid: int) -> int | None:
    """Read the account `pid` runs as. Takes the pid. Returns its uid, or None when it cannot be
    read."""
    identity, _state = identify(pid)
    return identity.uid if identity is not None else None


def _runs_as_root() -> bool:
    """Tell whether this run is root's. Returns True when it is."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def program_is_gone(pid: int, *, path=program_path, running=_running_file,
                    filesystem=_filesystem_of, account=_account_of,
                    as_root=_runs_as_root) -> bool:
    """Tell whether `pid` is executing something that is no longer a file on this disk. Takes the
    pid, the readers of the path it executes, of that file's status, of the filesystem it lives on
    and of the account it runs as, and whether this run is root's. Returns True when it is, and
    False when it is not or cannot be read."""
    where = path(pid)
    if where is None:
        return False
    if where.startswith("/memfd:"):
        return True
    deleted = where.endswith(_DELETED)
    try:
        info = running(pid)
    except PermissionError:
        return False if as_root() else deleted or not _exists(where)
    except (OSError, ValueError):
        return deleted or not _exists(where)
    if deleted:
        view, runs_as = _view_of(pid), account(pid)
        return not _an_administrators_program(where[:-len(_DELETED)], info, view, runs_as)
    try:
        here = os.stat(where)
    except (FileNotFoundError, NotADirectoryError):
        return _on_memory(pid, filesystem)
    except PermissionError:
        return _on_memory(pid, filesystem) if as_root() else True
    except (OSError, ValueError):
        return True
    if (here.st_dev, here.st_ino) == (info.st_dev, info.st_ino):
        return False
    return _on_memory(pid, filesystem)


def _exists(where: str) -> bool:
    """Tell whether `where` names a file this run can see. Takes the path. Returns True when it
    does, and False when it does not or cannot be read."""
    try:
        return os.path.exists(where)
    except (OSError, ValueError):
        return False


def _an_administrators_program(gone_from: str, info: os.stat_result, view: str,
                               runs_as: int | None) -> bool:
    """Tell whether a removed running program was an administrator's. Takes the path it ran from,
    the status of the file it runs, the view the path is read through and the account it runs as.
    Returns True when it was, and False when not or when it cannot be told."""
    if not (_installed_by_root(info) and _only_root_changes(os.path.dirname(gone_from), view)):
        return False
    if runs_as is not None and runs_as > 0:
        return True
    try:
        now = os.stat(view + gone_from)
    except (OSError, ValueError):
        return False
    return _installed_by_root(now) and (now.st_dev, now.st_ino) != (info.st_dev, info.st_ino)


def _installed_by_root(info: os.stat_result) -> bool:
    """Tell whether a file is an administrator's. Takes its status. Returns True when it is."""
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & _WRITABLE_BY_OTHERS)


def _on_memory(pid: int, filesystem) -> bool:
    """Tell whether the file `pid` executes lives only in memory. Takes the pid and the reader of
    the filesystem it lives on. Returns True when it does or when that cannot be read."""
    try:
        kind = filesystem(pid)
    except (OSError, ValueError):
        return True
    return kind in _MEMORY_FILESYSTEM_KINDS


def _own_uid_map() -> str:
    """Read how this run's accounts map onto the machine's. Returns the map, the identity map off
    Linux; raises OSError when it cannot be read."""
    if not sys.platform.startswith("linux"):
        return "0 0 4294967295"
    with open("/proc/self/uid_map", encoding="ascii", errors="replace") as table:
        return table.read()


def maps_the_hosts_root(*, read=_own_uid_map) -> bool:
    """Tell whether this run sees the machine's administrator as root. Takes the reader of this
    run's account map. Returns True when it does or the machine maps no accounts, and False when
    not or when the map cannot be read."""
    try:
        table = read()
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False
    return any(line.split()[:2] == ["0", "0"] for line in table.splitlines())


def _view_of(pid: int) -> str:
    """Name the root of the filesystem `pid` sees when it is not this run's. Takes the pid.
    Returns the prefix that turns a path the process sees into one this run can open, or "" when
    it shares this run's mounts or that cannot be read."""
    if not sys.platform.startswith("linux"):
        return ""
    try:
        if os.readlink(f"/proc/{pid}/ns/mnt") == os.readlink("/proc/self/ns/mnt"):
            return ""
        os.stat(f"/proc/{pid}/root/")
    except OSError:
        return ""
    return f"/proc/{pid}/root"


def _only_root_changes(folder: str, view: str = "") -> bool:
    """Tell whether only an administrator can change what `folder` holds. Takes the folder and the
    view it is read through. Returns True when only one can, and False when not or when it cannot
    be read."""
    path = os.path.normpath(folder) if folder else ""
    if not path.startswith("/"):
        return False
    while True:
        try:
            info = os.lstat(view + path)
        except OSError:
            return False
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & _WRITABLE_BY_OTHERS):
            return False
        if path == "/":
            return True
        path = os.path.dirname(path)


def ps_signature(pid: int) -> str | None:
    """A stable discriminator for any process, readable or not, or None.

    Compared to itself rather than parsed, so no date format or locale is involved.
    """
    if sys.platform.startswith("linux"):
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            fields = raw[raw.rindex(")") + 2:].split()
            return f"{fields[1]}|{fields[19]}"
        except (OSError, ValueError, IndexError):
            return None
    out = _run_ps("-o", "ppid=,uid=,lstart=", "-p", str(pid))
    if out is None:
        return None
    line = " ".join(out.split())
    return line or None


def parent_map() -> dict[int, int]:
    """Every pid's parent, including processes this user may not otherwise read."""
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
    if sys.platform.startswith("win"):
        rows = _powershell_rows()
        return {row["pid"]: row["ppid"] for row in rows} if rows else {}
    text = _run_ps("-axo", "pid=,ppid=")
    if text is None:
        return {}
    pairs: dict[int, int] = {}
    for line in text.splitlines():
        bits = line.split()
        if len(bits) == 2 and bits[0].isdigit() and bits[1].isdigit():
            pairs[int(bits[0])] = int(bits[1])
    return pairs


def _account_number(name: str) -> int:
    """Turn an account name into the number an identity carries. Takes the name. Returns the number,
    or -1 when there is none."""
    if not name:
        return -1
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:4], "big") or 1


def _windows_start(value) -> int:
    """Read a process start from a CIM value. Takes the value. Returns milliseconds, or 0 when it
    has none."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    if "/Date(" not in value:
        return 0
    digits = value.split("/Date(", 1)[1].split(")", 1)[0].split("+", 1)[0].split("-", 1)[0]
    return int(digits) if digits.isdigit() else 0


def _split_command(line: str) -> tuple[str, ...] | None:
    """Split a command line the way this system does. Takes the line. Returns the arguments, or
    None when this system has no splitter."""
    try:
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        return None
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    count = ctypes.c_int()
    parsed = shell.CommandLineToArgvW(line, ctypes.byref(count))
    if not parsed or count.value <= 0:
        return None
    try:
        return tuple(parsed[i] for i in range(count.value))
    finally:
        kernel.LocalFree(parsed)


def rows_from_cim(text: str, split=_split_command) -> list[dict] | None:
    """Read process rows from a CIM JSON document. Takes the document and the splitter for each
    command line. Returns the rows, or None when the document is not that JSON."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    items = data if isinstance(data, list) else [data]
    rows = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("ProcessId"), int):
            continue
        command = item.get("CommandLine")
        user = item.get("User") if isinstance(item.get("User"), str) else ""
        rows.append({
            "pid": item["ProcessId"],
            "ppid": item["ParentProcessId"] if isinstance(item.get("ParentProcessId"), int) else 0,
            "argv": split(command) if isinstance(command, str) and command else None,
            "path": item.get("ExecutablePath") if isinstance(item.get("ExecutablePath"), str) else None,
            "start": _windows_start(item.get("CreationDate")),
            "uid": _account_number(user),
        })
    return rows


_CIM = (
    "Get-CimInstance Win32_Process | ForEach-Object { "
    "$user = ''; try { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner; "
    "if ($o.User) { $user = $o.User } } catch {} "
    "[pscustomobject]@{ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; "
    "CommandLine=$_.CommandLine; ExecutablePath=$_.ExecutablePath; "
    "CreationDate=$_.CreationDate; User=$user} } | ConvertTo-Json -Compress"
)


def _powershell_rows(run=subprocess.run) -> list[dict] | None:
    """Read this system's processes. Takes the runner. Returns their rows, or None when they cannot
    be read."""
    binary = system_binary((
        os.path.join(windows_system_root(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),))
    if binary is None:
        return None
    try:
        done = run([binary, "-NoProfile", "-NonInteractive", "-Command", _CIM],
                   capture_output=True, text=True, timeout=30, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0 or not done.stdout.strip():
        return None
    return rows_from_cim(done.stdout)


def _identity_of(row: dict) -> Identity:
    """Build an identity from one process row. Takes the row. Returns the identity."""
    uid = row["uid"]
    return Identity(pid=row["pid"], ppid=row["ppid"], uid=uid, start_time=row["start"],
                    held_uids=(uid,) if uid >= 0 else ())


def _snapshot_of(rows: list[dict] | None) -> Snapshot:
    """Build a snapshot from process rows. Takes the rows. Returns the snapshot, unsupported when
    the rows are absent."""
    if rows is None:
        return Snapshot(supported=False)
    snap = Snapshot()
    for row in rows:
        who = _identity_of(row)
        if row["argv"] is None:
            snap.unreadable += 1
            snap.processes.append(Process(pid=row["pid"], argv_unreadable=True, identity=who))
        else:
            snap.processes.append(Process(pid=row["pid"], argv=tuple(row["argv"]), identity=who))
    return snap


def _windows_row(pid: int) -> tuple[dict | None, str]:
    """Read one Windows process. Takes the pid. Returns the row and RUNNING, or None and GONE or
    UNSUPPORTED."""
    rows = _powershell_rows()
    if rows is None:
        return None, UNSUPPORTED
    found = next((row for row in rows if row["pid"] == pid), None)
    return (found, RUNNING) if found is not None else (None, GONE)


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
    elif sys.platform.startswith("win"):
        return _snapshot_of(_powershell_rows())
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

#!/usr/bin/env python3
"""Tell a shell the Erlang VM runs for one of its own port programs, read from
`data/erlang_port_programs.yml`."""
from __future__ import annotations

import functools
import posixpath
from dataclasses import dataclass
from pathlib import Path

import yaml

PROGRAMS_FILE = Path(__file__).resolve().parent / "data" / "erlang_port_programs.yml"


@dataclass(frozen=True)
class PortPrograms:
    """The port programs and the processes that start them."""

    port_argvs: frozenset[tuple[str, ...]]
    spawn_argvs: frozenset[tuple[str, ...]]
    helpers: frozenset[str]
    vms: frozenset[str]


def _names(data: dict, field: str) -> frozenset[str]:
    names = data.get(field)
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
        raise ValueError(f"erlang port programs need a non-empty list of names in `{field}`")
    return frozenset(names)


def _port(raw, shells: frozenset[str]) -> tuple[set[tuple[str, ...]], tuple[str, ...]]:
    argv, spawned_as = (raw.get("argv"), raw.get("spawned_as")) if isinstance(raw, dict) else (None, None)
    if (not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv)
            or not isinstance(spawned_as, str) or not spawned_as):
        raise ValueError(f"erlang port program entry needs `argv` and `spawned_as`: {raw!r}")
    return {(shell, *argv) for shell in shells}, ("sh", "-c", spawned_as)


@functools.lru_cache(maxsize=None)
def port_programs(path: Path = PROGRAMS_FILE) -> PortPrograms:
    """Load the port programs. Takes the file (default: the shipped list). Returns them; raises
    ValueError on a malformed file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    shells = _names(data, "shells")
    ports = [_port(raw, shells) for raw in data.get("ports") or ()]
    if not ports:
        raise ValueError("erlang port programs need at least one entry in `ports`")
    return PortPrograms(port_argvs=frozenset(argv for argvs, _ in ports for argv in argvs),
                        spawn_argvs=frozenset(spawn for _, spawn in ports),
                        helpers=_names(data, "helpers"), vms=_names(data, "vms"))


def _parent(process, processes_by_pid: dict):
    """Return the process that started `process`, or None when it cannot be read: unknown, without
    readable arguments, or started after `process`."""
    if process.identity is None:
        return None
    parent = processes_by_pid.get(process.identity.ppid)
    if (parent is None or parent.argv_unreadable or not parent.argv or parent.identity is None
            or parent.identity.start_time > process.identity.start_time):
        return None
    return parent


def runs_for_the_erlang_vm(process, processes_by_pid: dict, programs: PortPrograms | None = None) -> bool:
    """Tell whether a process is a shell the Erlang VM runs for one of its own port programs: its
    arguments are that port program's, its parent is the VM's helper, or the shell the helper runs
    the port's command in, and the helper's parent is the VM. Takes the process, every process by
    pid and the port programs (default: the shipped list). Returns False when any of them cannot be
    read."""
    programs = programs if programs is not None else port_programs()
    if tuple(process.argv) not in programs.port_argvs:
        return False
    parent = _parent(process, processes_by_pid)
    if parent is not None and tuple(parent.argv) in programs.spawn_argvs:
        parent = _parent(parent, processes_by_pid)
    if parent is None or parent.argv[0] not in programs.helpers:
        return False
    vm = _parent(parent, processes_by_pid)
    return vm is not None and posixpath.basename(vm.argv[0]) in programs.vms

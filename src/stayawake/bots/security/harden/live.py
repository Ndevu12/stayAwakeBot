#!/usr/bin/env python3
"""End code that is running and never touched the disk."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from stayawake.utils import atomicwrite, elevate, env, operator, procstop
from stayawake.utils.procsnap import maps_the_hosts_root, parent_map, ps_signature
from stayawake.bots.security.livecode import live_code_finder

_MAX_ROUNDS = 12
_CAPTURE_KEEP = 20_000
_PROGRAM_KEEP = 300
_ANCESTOR_LIMIT = 64


@dataclass
class Ending:
    """What one pass did."""
    matched: int = 0
    frozen: int = 0
    ended: int = 0
    survived: list[int] = field(default_factory=list)
    refused: list[int] = field(default_factory=list)
    asked_for: list[int] = field(default_factory=list)
    asking: str = ""
    left_unidentified: list[int] = field(default_factory=list)
    cannot_reach_the_machines_root: bool = False
    frozen_left: list[int] = field(default_factory=list)
    quiet: bool = False
    still_holding: int = 0
    captured: str | None = None

    @property
    def finished(self) -> bool:
        """True when nothing that held live code is executing and nothing is left unreachable."""
        return (self.quiet and not self.survived and not self.refused
                and not self.left_unidentified and not self.frozen_left
                and self.still_holding == 0)


def capture_path() -> Path:
    """Where a captured process is written before anything ends it."""
    return Path(env.xdg_state_home()) / "saw" / "captured"


def _protected() -> set[int]:
    """This process, every ancestor of it, and init — none of which may be signalled."""
    safe = {1, os.getpid()}
    parents = parent_map()
    cur, seen = os.getpid(), 0
    while seen < _ANCESTOR_LIMIT:
        parent = parents.get(cur)
        if parent is None or parent in safe:
            break
        safe.add(parent)
        cur, seen = parent, seen + 1
    return safe


def _capture(held: dict[int, tuple], where: Path, now=None) -> str | None:
    """Write one record of what was running to `where`, and return its path.

    One record for the whole set, carrying a single representative payload.
    """
    if not held:
        return None
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    pids = sorted(held)
    code = held[pids[0]][1]
    record = {
        "captured_at": stamp,
        "processes": [{"pid": pid, "ppid": held[pid][0].ppid, "uid": held[pid][0].uid,
                       "start_time": held[pid][0].start_time,
                       "program": held[pid][2] if len(held[pid]) > 2 else ""} for pid in pids],
        "representative_pid": pids[0],
        "code": code[:_CAPTURE_KEEP],
        "code_bytes": len(code),
    }
    target = where / f"live-code-{stamp}-{pids[0]}.json"
    if not atomicwrite.replace(target, json.dumps(record, indent=2), mode=atomicwrite.AS_A_PLAIN_WRITE,
                               at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK):
        return None
    return str(target)


def _person_running_it() -> int | None:
    """Name the account saw acts for. Returns its uid, or None when that is root or cannot be
    told."""
    if not maps_the_hosts_root():
        return None
    geteuid = getattr(os, "geteuid", None)
    getuid = getattr(os, "getuid", None)
    if geteuid is None or getuid is None:
        return None
    if geteuid() != 0:
        return getuid()
    who = operator.resolve()
    if who is None or who.uid <= 0:
        return None
    return who.uid


def _only_of(identity, own: int | None) -> bool:
    """Tell whether a process holds no account but `own`. Takes its identity and the account.
    Returns True when every account it holds is that one."""
    return own is not None and all(uid == own for uid in (identity.held_uids or (identity.uid,)))


def _program_of(process) -> str:
    """Name the program a process runs. Takes the process. Returns its first argument, cut short,
    or "" when it has none."""
    argv = getattr(process, "argv", ()) or ()
    return str(argv[0])[:_PROGRAM_KEEP] if argv else ""


def _deepest_first(held: dict[int, tuple]) -> list[int]:
    """The pids in the order they must be ended: children before parents."""
    def depth(pid: int) -> int:
        steps, seen, cur = 0, set(), pid
        while cur in held and cur not in seen:
            seen.add(cur)
            parent = held[cur][0].ppid
            if parent not in held:
                break
            cur, steps = parent, steps + 1
        return steps
    return sorted(held, key=lambda pid: (-depth(pid), pid))


def end_live_code(*, find=None, freeze=procstop.freeze, end=procstop.end,
                  ended=procstop.has_ended, capture=_capture, where=None,
                  protected=_protected, elevated=procstop.end_as_root,
                  person=_person_running_it, rounds: int = _MAX_ROUNDS) -> Ending:
    """Freeze everything holding live code until a pass finds nothing new, then end it; another
    account's or a system process only when saw identified its code. Takes the finder, one that
    grades each code argument once when None, the collaborators that freeze, end, capture,
    elevate and name the account saw acts for, and the number of rounds. Returns what it did, as
    an Ending."""
    find = find if find is not None else live_code_finder()
    keep_out = protected()
    own = person()
    reaches_root = maps_the_hosts_root()
    held: dict[int, tuple] = {}
    held_done: set[int] = set()
    needs_root: dict[int, str | None] = {}
    refused: list[int] = []
    out = Ending(cannot_reach_the_machines_root=not reaches_root)

    try:
        for _round in range(rounds):
            fresh = []
            for item in find():
                process, code, _reason = item
                if (process.identity is not None and process.pid not in held
                        and process.pid not in keep_out):
                    fresh.append((item, process, code))
            if not fresh:
                out.quiet = True
                break
            for item, process, code in fresh:
                identified = getattr(item, "confirmed", False)
                if not identified and not _only_of(process.identity, own):
                    out.left_unidentified.append(process.pid)
                    keep_out.add(process.pid)
                    continue
                verdict = freeze(process.identity)
                if verdict == procstop.SIGNALLED:
                    held[process.pid] = (process.identity, code, _program_of(process))
                elif verdict == procstop.NEEDS_PRIVILEGE and identified:
                    needs_root[process.pid] = ps_signature(process.pid)
                    keep_out.add(process.pid)      # asking again every round answers the same way
                elif verdict == procstop.NEEDS_PRIVILEGE:
                    out.left_unidentified.append(process.pid)
                    keep_out.add(process.pid)
                elif verdict == procstop.REFUSED:
                    refused.append(process.pid)
                    keep_out.add(process.pid)
                else:
                    keep_out.add(process.pid)      # gone or recycled — not ours to end

        # Counted before anything moves between the fields below.
        out.matched = len(held) + len(needs_root) + len(refused)
        out.frozen = len(held)
        out.captured = capture(held, where or capture_path())

        for pid in _deepest_first(held):
            identity = held[pid][0]
            end(identity)
            if ended(identity):
                out.ended += 1
                held_done.add(pid)
            else:
                out.survived.append(pid)

        if needs_root:
            out.asked_for = sorted(needs_root)
            out.asking, ended_as_root = (elevated(out.asked_for, signatures=needs_root)
                                         if reaches_root else ("", []))
            out.ended += len(ended_as_root)
            refused.extend(pid for pid in out.asked_for if pid not in set(ended_as_root))
        out.refused = sorted(set(refused))
    finally:
        out.frozen_left = sorted(pid for pid in held if pid not in held_done)

    # Asked of the machine, not of the bookkeeping. Subtracting any of them hides a live one.
    out.still_holding = len(find())
    return out

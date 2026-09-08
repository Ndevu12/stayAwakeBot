#!/usr/bin/env python3
"""End code that is running and never touched the disk."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from stayawake.utils import elevate, env, procstop
from stayawake.utils.procsnap import parent_map, ps_signature
from stayawake.bots.security.hygiene.process import live_code_processes

_MAX_ROUNDS = 12
_CAPTURE_KEEP = 20_000
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
    frozen_left: list[int] = field(default_factory=list)
    quiet: bool = False
    still_holding: int = 0
    captured: str | None = None

    @property
    def finished(self) -> bool:
        """True when nothing that held live code is executing and nothing is left unreachable."""
        return (self.quiet and not self.survived and not self.refused
                and not self.frozen_left and self.still_holding == 0)


def capture_path() -> Path:
    """Where a captured process is written before anything ends it."""
    return Path(env.xdg_state_home()) / "saw" / "captured"


def _protected() -> set[int]:
    """This process, every ancestor of it, and init — none of which may be signalled.

    TRAP: read through `parent_map`, which needs no permission. An ancestor walk built on `identify`
    stops at the first process it cannot read, and everything above that stops being protected.
    """
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
    identity, code = held[pids[0]]
    record = {
        "captured_at": stamp,
        "processes": [{"pid": pid, "ppid": held[pid][0].ppid, "uid": held[pid][0].uid,
                       "start_time": held[pid][0].start_time} for pid in pids],
        "representative_pid": pids[0],
        "code": code[:_CAPTURE_KEEP],
        "code_bytes": len(code),
    }
    try:
        where.mkdir(parents=True, exist_ok=True)
        target = where / f"live-code-{stamp}-{pids[0]}.json"
        target.write_text(json.dumps(record, indent=2), encoding="utf-8")
    except OSError:
        return None
    return str(target)


def _deepest_first(held: dict[int, tuple]) -> list[int]:
    """The pids in the order they must be ended: children before parents.

    TRAP: ending a parent first reparents its children to init, leaving them running.
    """
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


def end_live_code(*, find=live_code_processes, freeze=procstop.freeze, end=procstop.end,
                  ended=procstop.has_ended, capture=_capture, where=None,
                  protected=_protected, elevated=procstop.end_as_root,
                  rounds: int = _MAX_ROUNDS) -> Ending:
    """Freeze everything holding live code until a pass finds nothing new, then end it.

    TRAP: the freeze comes first because a frozen process cannot fork. Ending them one at a time
    against something that spawns does not terminate.
    """
    keep_out = protected()
    held: dict[int, tuple] = {}
    held_done: set[int] = set()
    needs_root: dict[int, str | None] = {}
    refused: list[int] = []
    out = Ending()

    try:
        for _round in range(rounds):
            fresh = [(p, code) for p, code, _reason in find()
                     if p.identity is not None and p.pid not in held and p.pid not in keep_out]
            if not fresh:
                out.quiet = True
                break
            for process, code in fresh:
                verdict = freeze(process.identity)
                if verdict == procstop.SIGNALLED:
                    held[process.pid] = (process.identity, code)
                elif verdict == procstop.NEEDS_PRIVILEGE:
                    needs_root[process.pid] = ps_signature(process.pid)
                    keep_out.add(process.pid)      # asking again every round answers the same way
                elif verdict == procstop.REFUSED:
                    refused.append(process.pid)
                    keep_out.add(process.pid)
                else:
                    keep_out.add(process.pid)      # gone or recycled — not ours to end

        # Counted before anything moves between the fields below.
        out.matched = len(held) + len(needs_root) + len(refused)
        out.frozen = len(held)

        if needs_root:
            out.asked_for = sorted(needs_root)
            out.asking, ended_as_root = elevated(out.asked_for, signatures=needs_root)
            out.ended += len(ended_as_root)
            refused.extend(pid for pid in out.asked_for if pid not in set(ended_as_root))
        out.refused = sorted(set(refused))
        out.captured = capture(held, where or capture_path())

        for pid in _deepest_first(held):
            identity, _code = held[pid]
            end(identity)
            if ended(identity):
                out.ended += 1
                held_done.add(pid)
            else:
                out.survived.append(pid)
    finally:
        # TRAP: never resumed. A frozen one executes nothing; releasing it gives it back.
        out.frozen_left = sorted(pid for pid in held if pid not in held_done)

    # Asked of the machine, not of the bookkeeping. Subtracting any of them hides a live one.
    out.still_holding = len(find())
    return out

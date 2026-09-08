#!/usr/bin/env python3
"""End code that is running and never touched the disk.

Ordering is the whole design, because the measured case is not one process but a population that
grows while you work on it: 135 in a single snapshot, spread across 1577 pids. Against a spawner a
one-shot pass loses a race it cannot win, so this freezes first and ends afterwards.

Freezing is what makes the population shrink. A frozen process cannot fork, so each pass can only
reduce the set that is still able to spawn, and a pass that adds nothing new means nothing left is
spawning. A run that never reaches that point has found something outside the set it can see —
which is a finding, not a failure.
"""
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
    """What a pass did. `still_holding` is the only field that answers "is it over"."""
    matched: int = 0
    frozen: int = 0
    ended: int = 0
    survived: list[int] = field(default_factory=list)
    refused: list[int] = field(default_factory=list)
    asked_for: list[int] = field(default_factory=list)
    asking: str = ""
    quiet: bool = False
    still_holding: int = 0
    captured: str | None = None

    @property
    def finished(self) -> bool:
        """Every process that held live code is no longer executing, and none came back.

        A process we were refused permission to signal is not finished with: it is still running
        the same code, and the only thing that changed is that this run cannot reach it. A pass that
        never reached a quiet round has not finished either — something it cannot see is starting
        them again. Nothing having matched at all IS finished: an implant that exited on its own
        between one look and the next leaves nothing to end.
        """
        return (self.quiet and not self.survived and not self.refused
                and self.still_holding == 0)


def capture_path() -> Path:
    """Where a captured process is written before anything ends it."""
    return Path(env.xdg_state_home()) / "saw" / "captured"


def _protected() -> set[int]:
    """This process, everything that started it, and init.

    Freezing our own shell hangs the terminal the operator is watching, and ending our own ancestor
    ends the run. Neither can be undone from inside the run that did it.
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
    """Write one record of what was running, before any of it is ended.

    One representative payload, not one file per process: they are the same code, and writing 135
    copies is what makes a pass slow enough to lose the race it is in.
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
    """Children before parents. End a parent first and its children are reparented to init, which
    leaves them running and harder to attribute than they were a moment earlier."""
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
                  ended=procstop.has_ended, resume=procstop.resume, capture=_capture, where=None,
                  protected=_protected, elevated=procstop.end_as_root,
                  rounds: int = _MAX_ROUNDS) -> Ending:
    """Freeze everything holding live code until nothing new appears, then end it."""
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

        # Every process that held live code, however this run could or could not reach it. Counted
        # once, here, before anything moves between the buckets below.
        out.matched = len(held) + len(needs_root) + len(refused)
        out.frozen = len(held)

        # Privilege is asked for at the point it is needed, for those processes only. Reporting
        # them and walking away is what left another user's implant running on a machine the
        # operator does own.
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
        # A frozen process that is never ended and never resumed is stopped for good. It cannot be
        # restarted by the operator, it holds its files and locks, and `ps` shows it as ordinary
        # unless you read the state column. Anything raising here — the grader on attacker-chosen
        # text, the capture, or a Ctrl-C during a pass that takes seconds — used to leave exactly
        # that behind.
        for pid, (identity, _code) in held.items():
            if pid not in held_done:
                resume(identity)

    # Asked of the machine, not of the bookkeeping: whatever holds live code once the pass is over
    # holds it, whether this run froze it, was refused it, never saw it, or declined to touch it.
    # Subtracting the protected ones put a live holder in no field at all and still said finished.
    out.still_holding = len(find())
    return out

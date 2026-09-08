#!/usr/bin/env python3
"""Host-level acting — create denials on this machine. Never touches a project's tree."""
from __future__ import annotations

from collections import Counter

from stayawake.bots.security import hookscript
from stayawake.bots.security.hygiene.host_artifacts import _global_folders
from stayawake.bots.security.hygiene.models import PROCESSES_NOT_READABLE_ID
from stayawake.bots.security.hygiene.outcome import BLOCKED, run_probe
from stayawake.bots.security.hygiene.process import check_live_processes
from .live import end_live_code
from stayawake.utils import hostdenial, textsafe
from .denial import (ENFORCING, HELD_BY_ANOTHER, IN_A_LIVE_INSTALL, LEFT_OPEN_OVER_CONTENT,
                     NEEDS_ROOT, NOT_HERE_YET, LOCKED_OVER_CONTENT, NOTHING_TO_REMOVE,
                     NOT_WHERE_IT_WAS_NAMED, OCCUPIED, REMOVED, SELF_ENFORCING, UNKNOWN,
                     PathOutcome, apply_one, remove_one)

__all__ = ["run", "apply_one", "PathOutcome", "ENFORCING", "SELF_ENFORCING",
           "NEEDS_ROOT", "IN_A_LIVE_INSTALL", "NOT_HERE_YET", "REMOVED",
           "NOTHING_TO_REMOVE", "LOCKED_OVER_CONTENT", "LEFT_OPEN_OVER_CONTENT",
           "HELD_BY_ANOTHER", "NOT_WHERE_IT_WAS_NAMED", "UNKNOWN", "OCCUPIED",
           "remove_one", "take_back"]


_LIVE = "live-obfuscated-process"

_ENDED_LIVE = "Code that is not on disk was running here. It was captured and ended."
_STILL_LIVE = "Code that is not on disk is still running here."
_NOT_OURS_LIVE = "Run again where a password can be answered, or as root."
_STILL_SPAWNING = "They are being started again. Run again once the machine is off the network."
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
_REFUSED_BLOCKED = (
    "Running processes could not be examined, so this control was not applied. "
    "The check stopped on: {reason}"
)
_CAPTURE_EXCERPT = 300
_NOT_HERE = "This control is not implemented on this platform."
_CLAIM = "The staging paths a dropped payload uses are denied on this machine."
_CLAIM_AS_YOU = (
    "The staging paths a dropped payload uses are denied — by you, not by root, so anything "
    "running as you can lift them. Run again with sudo to make that stick."
)
_NEEDS_ROOT_NOTE = "Some locations need privilege this run did not have. Run again with sudo."
_NOT_EVERYWHERE = "The staging paths are not all denied on this machine."
_STUCK_ONE = "One location could not be taken, and privilege is not the reason — the system may hold it."
_STUCK_MANY = "{count} locations could not be taken, and privilege is not the reason — the system may hold them."
_LEFT_OPEN_NOTE = (
    "Something is sitting where nothing should be. It was left readable rather than locked over. "
    "Run `saw audit` to see it."
)
_DEAD_SAW_NOTE = (
    "The saw that saw's git hooks call is gone or cannot run, so clones are not scanned. "
    "`saw hook repair` points the hooks at this saw."
)
_ALTERED_HOOKS_NOTE = (
    "saw's git hooks are not what saw installed. `saw hook repair` puts them back."
)


_TOOK_BACK = "Every control this tool placed here has been taken back."
_NOT_ALL_BACK = ("Not every control was taken back. This command deletes nothing, and every "
                 "location below says what was done to it.")


def take_back(*, folders=_global_folders, remove=remove_one,
              supported=hostdenial.platform_supported) -> tuple[int, str]:
    """Remove the denials this tool placed. Removed only after a read-back says the path is gone.

    No capture gate here: this opens a location rather than closing one, so it cannot crash a
    process that a payload is holding open — which is the reason applying one waits for capture.

    A location holding content is never settled, locked or open: counting it as one reported a
    machine as back to normal over content nobody had read.
    """
    if not supported():
        return 2, _NOT_HERE
    outcomes = [remove(p) for p in folders()]
    settled = {REMOVED, NOTHING_TO_REMOVE}
    done = bool(outcomes) and all(o.state in settled for o in outcomes)
    lines = [_TOOK_BACK if done else _NOT_ALL_BACK, ""]
    if any(o.state == LEFT_OPEN_OVER_CONTENT for o in outcomes):
        lines.extend([_LEFT_OPEN_NOTE, ""])
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    return (0, "\n".join(lines).rstrip()) if done else (3, "\n".join(lines).rstrip())


#: A location that is protected. `LOCKED_OVER_CONTENT` counts: the control is on.
_HELD = frozenset({ENFORCING, SELF_ENFORCING, LOCKED_OVER_CONTENT})

#: A location with nothing to protect, or deliberately left alone. Neither is a failure, and
#: counting them as one is what made a run that protected four of six say it had protected none.
_NOT_A_FAILURE = frozenset({NOT_HERE_YET, IN_A_LIVE_INSTALL})


def _every_reachable_one(outcomes) -> bool:
    """Whether every location that could be protected is."""
    reachable = [o for o in outcomes if o.state not in _NOT_A_FAILURE]
    return bool(reachable) and all(o.state in _HELD for o in reachable)


def _headline(outcomes, unresolved: bool) -> str:
    """The one line that says where this machine stands."""
    if unresolved:
        return _NOT_EVERYWHERE
    if not _every_reachable_one(outcomes):
        return _NOT_EVERYWHERE
    if any(o.state == SELF_ENFORCING for o in outcomes):
        return _CLAIM_AS_YOU
    return _CLAIM


def _what_to_do(outcomes) -> list[str]:
    """The lines an operator can act on, and nothing else.

    No path is printed. Six of them, each with its own explanation, is what an operator was given
    for a result they could not act on any of.
    """
    counted = Counter(o.state for o in outcomes)
    out: list[str] = []
    if counted[NEEDS_ROOT]:
        out.append(_NEEDS_ROOT_NOTE)
    if counted[LEFT_OPEN_OVER_CONTENT]:
        out.append(_LEFT_OPEN_NOTE)
    stuck = sum(counted[state] for state in
                (OCCUPIED, HELD_BY_ANOTHER, NOT_WHERE_IT_WAS_NAMED, UNKNOWN))
    if stuck:
        out.append(_STUCK_ONE if stuck == 1 else _STUCK_MANY.format(count=stuck))
    return out


def _ending_line(ending) -> str:
    """One line describing `ending`, whatever the number of processes."""
    if ending.matched == 0:
        return "  it had already exited before this command reached it"
    bits = [f"  {ending.ended} of {ending.matched} ended"]
    if ending.survived:
        bits.append(f"{len(ending.survived)} did not end ({_pids(ending.survived)})")
    if ending.asked_for:
        bits.append(f"{len(ending.asked_for)} needed privilege ({ending.asking or 'not asked'})")
    if ending.refused:
        bits.append(f"{len(ending.refused)} still not ended ({_pids(ending.refused)})")
    if ending.frozen_left:
        bits.append(f"{len(ending.frozen_left)} stopped and contained ({_pids(ending.frozen_left)})"
                    " — release with kill -CONT if one of them is yours")
    if ending.still_holding:
        bits.append(f"{ending.still_holding} still running")
    if ending.captured:
        bits.append(f"captured to {textsafe.plain(ending.captured, limit=4096)}")
    return ", ".join(bits)


def _pids(pids: list[int], shown: int = 8) -> str:
    head = ", ".join(str(p) for p in pids[:shown])
    return head if len(pids) <= shown else f"{head}, and {len(pids) - shown} more"


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, supported=hostdenial.platform_supported,
        altered=hookscript.altered_hooks, saw_runs=hookscript.recorded_saw_runs,
        stop=end_live_code) -> tuple[int, str]:
    """Apply the denial at every global-resolution entry. Enforcing only after read-back.

    Root is asked of the PATH rather than of the command. Most of these locations belong to the
    operator, so requiring privilege for the whole run withheld a control they could have had from
    every person unwilling to give a security tool root — while the locations that need it are
    named, not silently skipped.

    Every note that applies is printed, not the first that matches: a chain dropped whichever came
    second, and a run can hold both.
    """
    if not supported():
        return 2, _NOT_HERE
    outcome = run_probe("running processes", live)
    if outcome.state == BLOCKED:
        return 1, _REFUSED_BLOCKED.format(reason=textsafe.plain(outcome.reason or "", limit=200))
    issues = list(outcome.issues)
    if any(i.id == PROCESSES_NOT_READABLE_ID for i in issues):
        return 1, _REFUSED_UNREAD
    # TRAP: what could not be done never stops what could. A part that needs a password nobody can
    # answer must not cost the operator every control this run was able to place.
    ending, ending_failed = None, None
    if [i for i in issues if i.id == _LIVE]:
        try:
            ending = stop()
        except Exception as exc:                  # never let it take the command down
            ending_failed = textsafe.plain(f"{type(exc).__name__}: {exc}", limit=200)

    outcomes = [apply(p) for p in folders()]
    unresolved = ending_failed is not None or (ending is not None and not ending.finished)
    lines = [_headline(outcomes, unresolved), ""]
    if ending_failed is not None:
        lines.extend([_STILL_LIVE, f"  the attempt stopped on: {ending_failed}", ""])
    elif ending is not None:
        lines.append(_STILL_LIVE if unresolved else _ENDED_LIVE)
        if ending.refused:
            lines.append(_NOT_OURS_LIVE)
        if not ending.quiet:
            lines.append(_STILL_SPAWNING)
        lines.extend([_ending_line(ending), ""])
    lines.extend(_what_to_do(outcomes))
    if altered():
        lines.extend(["", _ALTERED_HOOKS_NOTE])
    if not saw_runs():
        lines.extend(["", _DEAD_SAW_NOTE])
    body = "\n".join(lines).rstrip()
    if unresolved:
        return 1, body
    return (0, body) if _every_reachable_one(outcomes) else (3, body)

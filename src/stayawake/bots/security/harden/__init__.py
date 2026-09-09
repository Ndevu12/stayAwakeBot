#!/usr/bin/env python3
"""Host-level acting — create denials on this machine. Never touches a project's tree."""
from __future__ import annotations

from collections import Counter

from stayawake.bots.security import hook, hookscript, schedule
from stayawake.bots.security.hygiene.host_artifacts import _global_folders
from stayawake.bots.security.hygiene.models import PROCESSES_NOT_READABLE_ID
from stayawake.bots.security.hygiene.outcome import BLOCKED, run_probe
from stayawake.bots.security.hygiene.process import check_live_processes
from .live import end_live_code
from . import settings as editorsettings
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


TOUCHES_THIS_MACHINE = frozenset({"live", "apply", "stop", "settle_hooks", "schedule_pass",
                                  "editor_pass"})
ONLY_READS = frozenset({"folders", "supported", "altered", "saw_runs"})
TAKE_BACK_TOUCHES = frozenset({"folders", "unschedule", "restore_editors"})


_LIVE = "live-obfuscated-process"

_ENDED_LIVE = "Code was running here with no file behind it. It has been stopped."
_STILL_LIVE = "Code is running here with no file behind it, and not all of it could be stopped."
_NOT_OURS_LIVE = "Run again with sudo."
_STILL_SPAWNING = "It is starting again by itself. Take this machine off the network."
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
_REFUSED_BLOCKED = (
    "Running processes could not be examined, so this control was not applied. "
    "The check stopped on: {reason}"
)
_CAPTURE_EXCERPT = 300
_NOT_HERE = "This control is not implemented on this platform."
_CLAIM = "This machine is protected."
_CLAIM_AS_YOU = ("This machine is protected, but you can undo it yourself. "
                 "Run again with sudo to make it stick.")
_NEEDS_ROOT_NOTE = "Run again with sudo."
_NOT_EVERYWHERE = "This machine is not fully protected."
_STUCK_ONE = "This is as far as this machine allows."
_STUCK_MANY = "This is as far as this machine allows."
_LEFT_OPEN_NOTE = "Something is here that should not be. Run `saw audit`."
_DEAD_SAW_NOTE = (
    "The saw that saw's git hooks call is gone or cannot run, so clones are not scanned. "
    "`saw hook repair` points the hooks at this saw."
)
_ALTERED_HOOKS_NOTE = "Run `saw hook repair`."
_HOOKS_ON = "New clones and pulls on this machine will be scanned."
_HOOKS_REPAIRED = "A hook on this machine had been changed. It has been put back."
_HOOKS_OFF = "Run `saw hook install`."
_WATCH_ON = "This machine will also keep checking itself for code running with no file behind it."
_WATCH_REPAIRED = "The check this machine runs by itself had been changed. It has been put back."
_WATCH_OFF = "This machine will not keep checking itself. Run `saw watch`."
_WATCH_LEFT = "This machine is still checking itself, and that was not taken back."
_EDITORS_FIXED = ("An editor here could run code without asking you. That is now off.")
_EDITORS_STUCK = "An editor on this machine still opens folders that can run code. Run `saw audit`."
_EDITORS_KEPT = "An editor setting was left as it is. Run `saw audit`."


_TOOK_BACK = "Every control this tool placed here has been taken back."
_NOT_ALL_BACK = ("Not every control was taken back. This command deletes nothing, and every "
                 "location below says what was done to it.")


def take_back(*, folders=_global_folders, remove=remove_one,
              supported=hostdenial.platform_supported,
              unschedule=schedule.take_back,
              restore_editors=editorsettings.take_back) -> tuple[int, str]:
    """Remove the denials this tool placed. Removed only after a read-back says the path is gone.

    No capture gate here: this opens a location rather than closing one, so it cannot crash a
    process that a payload is holding open — which is the reason applying one waits for capture.

    A location holding content is never settled, locked or open: counting it as one reported a
    machine as back to normal over content nobody had read.
    """
    if not supported():
        return 2, _NOT_HERE
    # TRAP: this returns a STATE, it does not raise.
    try:
        left_running = unschedule() not in (schedule.REMOVED, schedule.NOTHING_TO_REMOVE)
    except Exception:
        left_running = True
    try:
        editors_back = restore_editors()
    except Exception:
        editors_back = None
    outcomes = [remove(p) for p in folders()]
    settled = {REMOVED, NOTHING_TO_REMOVE}
    done = bool(outcomes) and all(o.state in settled for o in outcomes)
    done = done and not left_running and editors_back is not None and editors_back.done
    lines = [_TOOK_BACK if done else _NOT_ALL_BACK, ""]
    if left_running:
        lines.extend([_WATCH_LEFT, ""])
    if editors_back is None or not editors_back.done:
        lines.extend([_EDITORS_STUCK, ""])
    elif editors_back.kept:
        lines.extend([_EDITORS_KEPT, ""])
    if any(o.state == LEFT_OPEN_OVER_CONTENT for o in outcomes):
        lines.extend([_LEFT_OPEN_NOTE, ""])
    for o in outcomes:
        lines.append(f"  {o.state}: {o.path} — {o.detail}")
    return (0, "\n".join(lines).rstrip()) if done else (3, "\n".join(lines).rstrip())


_HELD = frozenset({ENFORCING, SELF_ENFORCING, LOCKED_OVER_CONTENT})

_NOT_A_FAILURE = frozenset({NOT_HERE_YET, IN_A_LIVE_INSTALL})


def _every_reachable_one(outcomes) -> bool:
    """Whether every location that could be protected is."""
    reachable = [o for o in outcomes if o.state not in _NOT_A_FAILURE]
    return bool(reachable) and all(o.state in _HELD for o in reachable)


def _headline(outcomes, unresolved: bool, hooks_ok: bool, editors_ok: bool = True) -> str:
    """The one line that says where this machine stands.

    TRAP: every control this run places is represented here. An operator reads the verdict, so a
    part left undone that this line does not know about is a machine reported as protected.
    """
    if unresolved or not hooks_ok or not editors_ok or not _every_reachable_one(outcomes):
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


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, supported=hostdenial.platform_supported,
        altered=hookscript.altered_hooks, saw_runs=hookscript.recorded_saw_runs,
        stop=end_live_code, settle_hooks=hook.settle_hooks,
        schedule_pass=schedule.settle,
        editor_pass=editorsettings.settle) -> tuple[int, str]:
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
    ending, ending_failed = None, None
    if [i for i in issues if i.id == _LIVE]:
        try:
            ending = stop()
        except Exception as exc:                  # never let it take the command down
            ending_failed = textsafe.plain(f"{type(exc).__name__}: {exc}", limit=200)

    outcomes = [apply(p) for p in folders()]
    # Putting the hooks in place is part of hardening a machine, and doing it twice changes
    # nothing: one already in place reads as such and is not rewritten.
    try:
        hooks = settle_hooks()
    except Exception:                         # never let it take the command down
        hooks = None
    try:
        scheduled = schedule_pass()
    except Exception:
        scheduled = None
    try:
        editors_settled = editor_pass()
    except Exception:
        editors_settled = None
    unresolved = ending_failed is not None or (ending is not None and not ending.finished)
    hooks_ok = hooks is not None and hooks.settled
    editors_ok = editors_settled is not None and editors_settled.settled
    lines = [_headline(outcomes, unresolved, hooks_ok, editors_ok), ""]
    if ending_failed is not None:
        lines.extend([_STILL_LIVE, ""])
    elif ending is not None:
        lines.append(_STILL_LIVE if unresolved else _ENDED_LIVE)
        if ending.refused:
            lines.append(_NOT_OURS_LIVE)
        if not ending.quiet:
            lines.append(_STILL_SPAWNING)
        lines.append("")
    lines.extend(_what_to_do(outcomes))
    if hooks_ok and hooks.repaired:
        lines.append(_HOOKS_REPAIRED)
    elif hooks_ok and hooks.changed:
        lines.append(_HOOKS_ON)
    elif not hooks_ok:
        lines.append(_HOOKS_OFF)
    if scheduled is not None and scheduled.settled:
        if scheduled.state == schedule.REPLACED:
            lines.append(_WATCH_REPAIRED)
        elif scheduled.changed:
            lines.append(_WATCH_ON)
    elif scheduled is not None and scheduled.problem and schedule.supported():
        lines.append(_WATCH_OFF)
    if editors_settled is not None and editors_settled.changed:
        lines.append(_EDITORS_FIXED)
    if not editors_ok:
        lines.append(_EDITORS_STUCK)
    if altered():
        lines.extend(["", _ALTERED_HOOKS_NOTE])
    if not saw_runs():
        lines.extend(["", _DEAD_SAW_NOTE])
    body = "\n".join(lines).rstrip()
    if unresolved:
        return 1, body
    if not _every_reachable_one(outcomes) or not hooks_ok or not editors_ok:
        return 3, body
    return 0, body

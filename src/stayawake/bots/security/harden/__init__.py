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
from . import approvals as agentapprovals
from stayawake.utils import elevate, hostdenial, textsafe
from stayawake.utils.own_command import saw_through_sudo
from . import hold_aside
from .denial import (ENFORCING, HELD_BY_ANOTHER, IN_A_LIVE_INSTALL, LEFT_OPEN_OVER_CONTENT,
                     NEEDS_ROOT, NOT_HERE_YET, LOCKED_OVER_CONTENT, NOTHING_TO_REMOVE,
                     NOT_WHERE_IT_WAS_NAMED, OCCUPIED, REMOVED, SELF_ENFORCING, UNKNOWN,
                     PathOutcome, apply_one, remove_one, KIT_LEFT, KIT_REMOVED)

__all__ = ["run", "apply_one", "PathOutcome", "ENFORCING", "SELF_ENFORCING",
           "NEEDS_ROOT", "IN_A_LIVE_INSTALL", "NOT_HERE_YET", "REMOVED",
           "NOTHING_TO_REMOVE", "LOCKED_OVER_CONTENT", "LEFT_OPEN_OVER_CONTENT",
           "HELD_BY_ANOTHER", "NOT_WHERE_IT_WAS_NAMED", "UNKNOWN", "OCCUPIED",
           "remove_one", "take_back"]


TOUCHES_THIS_MACHINE = frozenset({"live", "apply", "stop", "settle_hooks", "schedule_pass",
                                  "editor_pass", "agent_pass"})
ONLY_READS = frozenset({"folders", "supported", "altered", "saw_runs"})
TAKE_BACK_TOUCHES = frozenset({"folders", "unschedule", "restore_editors",
                               "restore_agents"})


_LIVE = "live-obfuscated-process"

_ENDED_LIVE = "Code was running here with no file behind it. It has been stopped."
_STILL_LIVE = "Code with no file behind it is still running on this machine."
_GONE_LIVE = "Code was running here with no file behind it. It is no longer running."
_RUN_AGAIN = "Run `saw harden` again to stop it."
_NOT_OURS_LIVE = "Run `{sudo_saw} harden` to stop it."
_NOT_OURS_BY_ASKING = {
    elevate.NOT_AN_ADMINISTRATOR: "An administrator can stop it with `{sudo_saw} harden`.",
    elevate.NOT_AVAILABLE: "An administrator can stop it by running `saw harden` as root.",
}
_UNIDENTIFIED_LEFT = "Suspicious code was left running. Run `saw audit` to see it."
_FROM_OUTSIDE = "Run `saw harden` outside this container to stop it."
_STILL_SPAWNING = "It is starting again by itself. Run `saw audit` to find what starts it."
_REFUSED_UNREAD = (
    "Running processes could not be examined, so this control was not applied."
)
_REFUSED_BLOCKED = (
    "Running processes could not be examined, so this control was not applied. "
    "The check stopped on: {reason}"
)
_CAPTURE_EXCERPT = 300
_NOT_HERE = "saw harden's controls are not available on this system."
_CLAIM = "saw harden's controls are in place on this machine."
_CLAIM_AS_YOU = ("saw harden's controls are in place on this machine, but your account can undo "
                 "them. Run `{sudo_saw} harden` so only an administrator can.")
_NEEDS_ROOT_NOTE = "Run `{sudo_saw} harden` to place the rest."
_NOT_EVERYWHERE = "Some of saw harden's controls are not in place on this machine."
_KIT_REMOVED = ("saw deleted a known worm's staging kit from this machine. Do NOT rotate any credential "
                "yet: run `saw audit` first.")
_KIT_LEFT = ("A known worm's staging kit could not be fully removed. Run `saw audit` before anything "
             "else, and do NOT rotate any credential yet.")
_MOVED_ASIDE = ("Something was where a control goes, so saw moved it aside, beside where it was, and "
                "placed the control. `saw harden --take-back` puts it back, unless it is a known worm's "
                "staging kit.")
_MOVED_ASIDE_LEFT = ("Something saw moved aside could not be put back after its control could not be "
                     "placed; it is still beside where it was. Run `saw audit`.")
_STUCK_ONE = ("A control could not be placed because something else is already there. "
              "Run `saw audit` to see what.")
_STUCK_MANY = ("{count} controls could not be placed because something else is already there. "
               "Run `saw audit` to see what.")
_LEFT_OPEN_NOTE = "Something is here that should not be. Run `saw audit`."
_DEAD_SAW_NOTE = (
    "saw's git hooks call a saw that is gone or cannot run, so clones are not scanned. "
    "Run `saw hook repair`."
)
_ALTERED_HOOKS_NOTE = ("Something where saw's git hooks run is not what saw installed. "
                       "Run `saw hook repair`.")
_HOOKS_ON = "New clones and pulls on this machine will be scanned."
_HOOKS_REPAIRED = "A hook on this machine had been changed. It has been put back."
_HOOKS_OFF = "New clones are not scanned on this machine. Run `saw hook install`."
_WATCH_ON = ("`saw watch` is now in place: it ends code saw has identified, from now on and after "
             "every login.")
_WATCH_REPAIRED = "`saw watch` had been changed on this machine. It has been put back."
_WATCH_OFF = "`saw watch` could not be put in place. Run `saw watch`."
_WATCH_LEFT = "`saw watch` is still in place; it was not taken back. Run `saw watch stop`."
_EDITORS_FIXED = ("An editor here could run code without asking you. That is now off.")
_EDITORS_STUCK = "An editor on this machine still opens folders that can run code. Run `saw audit`."
_EDITORS_KEPT = "An editor setting was left as it is. Run `saw audit`."
_AGENTS_FIXED = "An AI agent here could run commands without asking. That is now off."
_AGENTS_STUCK = "An AI agent here still runs commands without asking. Run `saw audit`."


_TOOK_BACK = "Every control saw harden placed has been taken back."
_NOTHING_PLACED = "No control saw harden places was found, so nothing was changed."
_NOT_ALL_BACK = "Not all of saw harden's controls could be taken back."
_EDITORS_NOT_BACK = ("An editor setting saw changed could not be put back. Run `saw harden "
                     "--take-back` again.")
_AGENTS_NOT_BACK = ("An AI agent setting saw changed could not be put back. Run `saw harden "
                    "--take-back` again.")
_TAKEN_BACK_OR_ABSENT = frozenset({REMOVED, NOTHING_TO_REMOVE, OCCUPIED})
_PUT_BACK_LINES = {
    hold_aside.PUT_BACK: "What saw had moved aside so a control could be placed has been put back.",
    hold_aside.KEPT_ASIDE: ("What was where a control goes is a known worm's staging kit, so saw kept it "
                            "aside. Run `saw audit` before anything else."),
    hold_aside.PATH_TAKEN: ("Something saw had moved aside was not put back, because something else is "
                            "now where it was. Run `saw audit`."),
    hold_aside.NOT_PUT_BACK: ("Something saw had moved aside could not be put back; it is still beside "
                              "where it was. Run `saw audit`."),
}
_LEFT_ASIDE = frozenset({hold_aside.PATH_TAKEN, hold_aside.NOT_PUT_BACK})
_SOMETHING_ELSE_THERE = ("A location saw guards holds something saw did not put there. "
                         "`saw audit` checks what is in it.")
_EDITORS_NOT_LOOKED_UP = ("The editor settings saw changed could not be looked up, so they were "
                          "left as they are. Run `saw audit`.")
_AGENTS_NOT_LOOKED_UP = ("The AI agent settings saw changed could not be looked up, so they were "
                         "left as they are. Run `saw audit`.")
_WHAT_TO_DO_WITH_WHAT_IS_LEFT = {
    NEEDS_ROOT: "Some of it needs an administrator. Run `{sudo_saw} harden --take-back` to take it "
                "back.",
    HELD_BY_ANOTHER: ("Another account placed some of it, so it was left as it is. That account can "
                      "take it back with `saw harden --take-back`."),
    LOCKED_OVER_CONTENT: "A location saw guards holds files saw did not put there, so it was left "
                         "locked. Run `saw audit` before anything else.",
    NOT_WHERE_IT_WAS_NAMED: "A location saw guards now leads somewhere else, so it was left as it "
                            "is. Run `saw audit`.",
}
_COULD_NOT_TAKE_BACK = "Some of it could not be taken back. Run `saw harden --take-back` again."


def take_back(*, folders=_global_folders, remove=remove_one,
              supported=hostdenial.platform_supported,
              unschedule=schedule.take_back,
              restore_editors=editorsettings.take_back,
              restore_agents=agentapprovals.take_back) -> tuple[int, str]:
    """Remove the denials this tool placed. Removed only after a read-back says the path is gone.

    No capture gate here: this opens a location rather than closing one, so it cannot crash a
    process that a payload is holding open — which is the reason applying one waits for capture.

    A location holding content is never settled, locked or open: counting it as one reported a
    machine as back to normal over content nobody had read.
    """
    if not supported():
        return 2, _NOT_HERE
    try:
        unscheduled = unschedule()
    except Exception:
        unscheduled = None
    left_running = unscheduled not in (schedule.REMOVED, schedule.NOTHING_TO_REMOVE)
    try:
        editors_back = restore_editors()
    except Exception:
        editors_back = None
    try:
        agents_back = restore_agents()
    except Exception:
        agents_back = None
    outcomes = [remove(p) for p in folders()]
    done = bool(outcomes) and all(o.state in _TAKEN_BACK_OR_ABSENT for o in outcomes)
    done = done and not any(o.put_back in _LEFT_ASIDE for o in outcomes)
    done = done and not left_running and editors_back is not None and editors_back.done
    done = done and agents_back is not None and agents_back.done
    placed_nothing = (done and unscheduled == schedule.NOTHING_TO_REMOVE
                      and all(o.state in (NOTHING_TO_REMOVE, OCCUPIED) for o in outcomes)
                      and not editors_back.restored and not editors_back.kept
                      and not agents_back.restored)
    lines = [(_NOTHING_PLACED if placed_nothing else _TOOK_BACK) if done else _NOT_ALL_BACK, ""]
    for state, line in _PUT_BACK_LINES.items():
        if any(o.put_back == state for o in outcomes):
            lines.extend([line, ""])
    if left_running:
        lines.extend([_WATCH_LEFT, ""])
    if editors_back is None or editors_back.unreadable_record:
        lines.extend([_EDITORS_NOT_LOOKED_UP, ""])
    elif editors_back.failed:
        lines.extend([_EDITORS_NOT_BACK, ""])
    elif editors_back.kept:
        lines.extend([_EDITORS_KEPT, ""])
    if agents_back is None or agents_back.unreadable_record:
        lines.extend([_AGENTS_NOT_LOOKED_UP, ""])
    elif agents_back.failed:
        lines.extend([_AGENTS_NOT_BACK, ""])
    if any(o.state == OCCUPIED for o in outcomes):
        lines.extend([_SOMETHING_ELSE_THERE, ""])
    if any(o.state == LEFT_OPEN_OVER_CONTENT for o in outcomes):
        lines.extend([_LEFT_OPEN_NOTE, ""])
    left = {o.state for o in outcomes} - _TAKEN_BACK_OR_ABSENT - {LEFT_OPEN_OVER_CONTENT}
    for state, line in _WHAT_TO_DO_WITH_WHAT_IS_LEFT.items():
        if state in left:
            lines.extend([line.format(sudo_saw=saw_through_sudo()), ""])
    if left - set(_WHAT_TO_DO_WITH_WHAT_IS_LEFT):
        lines.extend([_COULD_NOT_TAKE_BACK, ""])
    return (0, "\n".join(lines).rstrip()) if done else (3, "\n".join(lines).rstrip())


_HELD = frozenset({ENFORCING, SELF_ENFORCING, LOCKED_OVER_CONTENT})

_NOT_A_FAILURE = frozenset({NOT_HERE_YET, IN_A_LIVE_INSTALL})


def _every_reachable_one(outcomes) -> bool:
    """Whether every location that could be protected is."""
    reachable = [o for o in outcomes if o.state not in _NOT_A_FAILURE]
    return bool(reachable) and all(o.state in _HELD for o in reachable)


def _headline(outcomes, unresolved: bool, hooks_ok: bool, editors_ok: bool = True) -> str:
    """Say where this machine stands, in one line. Takes the outcomes of each location, whether
    code is still running, and whether the hooks and editor settings are settled. Returns the
    line."""
    if unresolved:
        return _STILL_LIVE
    if not hooks_ok or not editors_ok or not _every_reachable_one(outcomes):
        return _NOT_EVERYWHERE
    if any(o.state == SELF_ENFORCING for o in outcomes):
        return _CLAIM_AS_YOU.format(sudo_saw=saw_through_sudo())
    return _CLAIM


def _what_to_do(outcomes) -> list[str]:
    """The lines an operator can act on, and nothing else.

    No path is printed. Six of them, each with its own explanation, is what an operator was given
    for a result they could not act on any of.
    """
    left_aside = [o for o in outcomes if o.moved_aside and o.state not in _HELD]
    kit_left = [o for o in outcomes if o.kit == KIT_LEFT]
    counted = Counter(o.state for o in outcomes if o not in left_aside and o not in kit_left)
    out: list[str] = []
    if any(o.kit == KIT_REMOVED for o in outcomes):
        out.append(_KIT_REMOVED)
    if kit_left:
        out.append(_KIT_LEFT)
    if any(o.moved_aside and o.state in _HELD for o in outcomes):
        out.append(_MOVED_ASIDE)
    if left_aside:
        out.append(_MOVED_ASIDE_LEFT)
    if counted[NEEDS_ROOT]:
        out.append(_NEEDS_ROOT_NOTE.format(sudo_saw=saw_through_sudo()))
    if counted[LEFT_OPEN_OVER_CONTENT]:
        out.append(_LEFT_OPEN_NOTE)
    stuck = sum(counted[state] for state in
                (OCCUPIED, HELD_BY_ANOTHER, NOT_WHERE_IT_WAS_NAMED, UNKNOWN))
    if stuck:
        out.append(_STUCK_ONE if stuck == 1 else _STUCK_MANY.format(count=stuck))
    return out


IN_PLACE, LIVE_CODE_LEFT, NOT_ON_THIS_PLATFORM, CONTROLS_INCOMPLETE = 0, 1, 2, 3


def dealt_with_live_code(code: int) -> bool:
    """Tell whether a run ended every piece of live code it found. Takes the code `run` returned.
    Returns True when the process table was read and nothing was left running, whatever the other
    controls reached."""
    return code in (IN_PLACE, CONTROLS_INCOMPLETE)


def run(*, live=check_live_processes, folders=_global_folders,
        apply=apply_one, supported=hostdenial.platform_supported,
        altered=hookscript.altered_hooks, saw_runs=hookscript.recorded_saw_runs,
        stop=end_live_code, settle_hooks=hook.settle_hooks,
        schedule_pass=schedule.settle,
        editor_pass=editorsettings.settle,
        agent_pass=agentapprovals.settle) -> tuple[int, str]:
    """Apply the denial at every global-resolution entry. Enforcing only after read-back.

    Root is asked of the PATH rather than of the command. Most of these locations belong to the
    operator, so requiring privilege for the whole run withheld a control they could have had from
    every person unwilling to give a security tool root — while the locations that need it are
    named, not silently skipped.

    Every note that applies is printed, not the first that matches: a chain dropped whichever came
    second, and a run can hold both.
    """
    if not supported():
        return NOT_ON_THIS_PLATFORM, _NOT_HERE
    outcome = run_probe("running processes", live)
    if outcome.state == BLOCKED:
        return LIVE_CODE_LEFT, _REFUSED_BLOCKED.format(
            reason=textsafe.plain(outcome.reason or "", limit=200))
    issues = list(outcome.issues)
    if any(i.id == PROCESSES_NOT_READABLE_ID for i in issues):
        return LIVE_CODE_LEFT, _REFUSED_UNREAD
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
    try:
        agents_settled = agent_pass()
    except Exception:
        agents_settled = None
    unresolved = ending_failed is not None or (ending is not None and not ending.finished)
    hooks_ok = hooks is not None and hooks.settled
    editors_ok = editors_settled is not None and editors_settled.settled
    agents_ok = agents_settled is not None and agents_settled.settled
    lines = [_headline(outcomes, unresolved, hooks_ok, editors_ok and agents_ok), ""]
    if ending_failed is not None:
        lines.extend([_RUN_AGAIN, ""])
    elif ending is not None:
        if not unresolved:
            lines.append(_ENDED_LIVE if ending.matched else _GONE_LIVE)
        if ending.survived or ending.frozen_left:
            lines.append(_RUN_AGAIN)
        if ending.refused and not ending.cannot_reach_the_machines_root:
            lines.append(_NOT_OURS_BY_ASKING.get(ending.asking, _NOT_OURS_LIVE).format(sudo_saw=saw_through_sudo()))
        if ending.left_unidentified:
            lines.append(_UNIDENTIFIED_LEFT)
        if ending.cannot_reach_the_machines_root and (ending.refused or ending.left_unidentified):
            lines.append(_FROM_OUTSIDE)
        if not ending.quiet:
            lines.append(_STILL_SPAWNING)
        lines.append("")
    lines.extend(_what_to_do(outcomes))
    if hooks_ok and hooks.repaired:
        lines.append(_HOOKS_REPAIRED)
    elif hooks_ok and hooks.changed:
        lines.append(_HOOKS_ON)
    elif hooks is not None and hooks.may_not_run:
        lines.append(hooks.may_not_run)
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
    if agents_settled is not None and agents_settled.changed:
        lines.append(_AGENTS_FIXED)
    if not agents_ok:
        lines.append(_AGENTS_STUCK)
    if altered():
        lines.extend(["", _ALTERED_HOOKS_NOTE])
    if not saw_runs():
        lines.extend(["", _DEAD_SAW_NOTE])
    body = "\n".join(lines).rstrip()
    if unresolved:
        return LIVE_CODE_LEFT, body
    if not _every_reachable_one(outcomes) or not hooks_ok or not editors_ok or not agents_ok:
        return CONTROLS_INCOMPLETE, body
    return IN_PLACE, body

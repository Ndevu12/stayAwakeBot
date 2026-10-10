#!/usr/bin/env python3
"""`saw harden` — create host-level denials on this machine."""
from __future__ import annotations

import argparse

from stayawake.bots.security import harden, watchrecord
from stayawake.cli.helptext import add_command
from stayawake.utils.streaming import busy, say
from stayawake.cli.argtypes import no_stream_requested


def register(sub) -> None:
    p = add_command(
        sub, "harden",
        help="create host denials; reports in place only after a read-back",
        description=(
            "Create host-level controls on this machine. It never touches a project's "
            "dependency tree. A write is reported as in place only after it is read back; "
            "an unverifiable write is unknown, never success. It does not claim that one "
            "control protects anything else."),
        examples=[
            ("saw harden", "create the controls, then read them back"),
            ("sudo saw harden", "the same, reaching what needs privilege"),
            ("saw harden --take-back", "remove the controls it placed"),
        ])
    p.add_argument("--take-back", action="store_true",
                   help="remove the controls this command placed, and nothing else")
    p.set_defaults(func=run)


acknowledge_came_back = watchrecord.acknowledge


def run(a: argparse.Namespace) -> int:
    """Put the host controls in place, or take them back. Takes the parsed arguments. Returns the
    exit code; a run that protected the machine also marks code that came back as dealt with."""
    label = "removing host denials…" if a.take_back else "creating host denials…"
    no_stream = no_stream_requested(a)
    counted = _returns_counted()
    with busy(label, no_stream=no_stream):
        code, text = harden.take_back() if a.take_back else harden.run()
    say(text, no_stream=no_stream)
    if code == 0 and not a.take_back:
        line = _after_protecting(counted)
        if line:
            say(line, no_stream=no_stream)
    return code


_NOT_ACKNOWLEDGED = ("The watcher could not record that code which came back has been dealt with, "
                     "so it will keep reminding you. Run `saw watch status`.")
_CAME_BACK_DURING = ("Code came back while saw harden was running. Take this machine off the "
                     "network, then run `saw harden` again.")


def _returns_counted():
    """Read which returns the watcher had counted before this run, never failing. Returns the
    record's name and count, or None."""
    try:
        return watchrecord.returns_so_far(watchrecord.load())
    except Exception:
        return None


def _after_protecting(counted) -> str:
    """Mark the returns counted before this run started as dealt with, never failing. Takes what
    was counted then. Returns the line to print, or "" when there is nothing to say."""
    try:
        if counted is None:
            return ""
        if not acknowledge_came_back(counted):
            return _NOT_ACKNOWLEDGED
        still = watchrecord.settled(watchrecord.load(), watchrecord.load_acknowledgement())
        return _CAME_BACK_DURING if still.get("unacknowledged") else ""
    except Exception:
        return _NOT_ACKNOWLEDGED

#!/usr/bin/env python3
"""`saw watch` — keep this machine checking itself for code running with no file behind it.

Thin CLI: parse args and delegate to `bots.security.watch`. `saw watch run` is the internal entry
the scheduled item calls — hidden from help.
"""
from __future__ import annotations

import argparse
import time

from stayawake.bots.security import watch, watchalerts, watchrecord
from stayawake.utils import notify
from stayawake.cli.helptext import add_command, declare_streaming
from stayawake.utils.streaming import busy, say
from stayawake.cli.argtypes import no_stream_requested


def register(sub) -> None:
    p = add_command(
        sub, "watch",
        help="keep this machine checking itself; ends code it has identified",
        description=(
            "Ask this machine to keep checking itself. From then on, and from every login, it "
            "makes a pass over what is running and ends code the tool has identified. It never "
            "asks for a password; what it will not end is left for `saw harden`, which runs with "
            "you present. It keeps checking until you stop it."),
        examples=[
            ("saw watch", "keep checking this machine from now on"),
            ("saw watch status", "say whether it is checking itself"),
            ("saw watch stop", "stop checking it"),
        ])
    p.set_defaults(func=run)
    wsub = p.add_subparsers(dest="watch_command", metavar="<subcommand>")

    stop = add_command(
        wsub, "stop",
        help="stop this machine checking itself",
        description="Stop the checking `saw watch` started. Removes what saw placed and leaves "
                    "anything else under that name alone.",
        examples=[("saw watch stop", "stop checking this machine")])
    stop.set_defaults(func=run_stop)

    status = add_command(
        wsub, "status",
        help="say whether this machine is checking itself",
        description="Say whether this machine is checking itself, and what to run if it is not.",
        examples=[("saw watch status", "check whether this machine is checking itself")])
    status.set_defaults(func=run_status)

    internal = wsub.add_parser("run")          # the entry the scheduled item calls, not offered
    declare_streaming(internal, False)
    internal.set_defaults(func=run_internal)


_HERE = ("saw will tell you here when it stops code running on this machine, and once a day.")
_SENT = ("A notification was sent to show where saw will tell you. If none appeared, allow "
         "notifications for Script Editor in System Settings.")
_NOT_SHOWN = ("Notifications could not be shown on this machine. Run `saw watch status` to see what "
              "it finds.")
notifier_for_this_machine = notify.platform_notifier


def run(a: argparse.Namespace) -> int:
    no_stream = no_stream_requested(a)
    with busy("asking this machine to keep checking itself…", no_stream=no_stream):
        code, text = watch.schedule_it()
    say(text, no_stream=no_stream)
    if code != 0:
        return code
    shown = notifier_for_this_machine().send(watchalerts.TITLE, _HERE)
    if shown.state == notify.UNCONFIRMED:
        say(_SENT, no_stream=no_stream)
    elif shown.state != notify.SENT:
        say(_NOT_SHOWN, no_stream=no_stream)
    return code


def run_stop(a: argparse.Namespace) -> int:
    no_stream = no_stream_requested(a)
    with busy("stopping the check…", no_stream=no_stream):
        code, text = watch.unschedule_it()
    say(text, no_stream=no_stream)
    return code


def run_status(a: argparse.Namespace) -> int:
    no_stream = no_stream_requested(a)
    with busy("checking whether this machine is watching itself…", no_stream=no_stream):
        code, text = watch.status_of()
    say(text, no_stream=no_stream)
    return code


def run_internal(a: argparse.Namespace) -> int:
    """Keep making the pass until stopped, telling the user what it finds. Takes the parsed
    arguments. Returns the code of the last pass."""
    tell = watchalerts.teller(notifier_for_this_machine(), load=watchrecord.load,
                              save=watchrecord.save, clock=time.time, local=time.localtime,
                              acknowledged=watchrecord.load_acknowledgement)
    return watch.keep_going(tell=tell)

#!/usr/bin/env python3
"""`saw watch` — keep this machine checking itself for code running with no file behind it.

Thin CLI: parse args and delegate to `bots.security.watch`. `saw watch run` is the internal entry
the scheduled item calls — hidden from help.
"""
from __future__ import annotations

import argparse

from stayawake.bots.security import watch
from stayawake.cli.helptext import add_command
from stayawake.utils.streaming import busy, say


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
    internal.set_defaults(func=run_internal)


def run(a: argparse.Namespace) -> int:
    no_stream = getattr(a, "no_stream", False)
    with busy("asking this machine to keep checking itself…", no_stream=no_stream):
        code, text = watch.schedule_it()
    say(text, no_stream=no_stream)
    return code


def run_stop(a: argparse.Namespace) -> int:
    no_stream = getattr(a, "no_stream", False)
    with busy("stopping the check…", no_stream=no_stream):
        code, text = watch.unschedule_it()
    say(text, no_stream=no_stream)
    return code


def run_status(a: argparse.Namespace) -> int:
    no_stream = getattr(a, "no_stream", False)
    with busy("checking whether this machine is watching itself…", no_stream=no_stream):
        code, text = watch.status_of()
    say(text, no_stream=no_stream)
    return code


def run_internal(a: argparse.Namespace) -> int:
    """What the scheduled item calls: keep making the pass until stopped."""
    return watch.keep_going()

#!/usr/bin/env python3
"""`saw hook` — scan-on-clone. Install global git hooks that scan a repo the moment it is
cloned/pulled, so a supply-chain worm is caught BEFORE `npm install` or an editor auto-run fires.

Thin CLI: parse args and delegate to `bots.security.hook`. `saw hook run` is the internal entry the
installed git hook calls — hidden from help.
"""
from __future__ import annotations

import argparse

from stayawake.cli.helptext import add_command, declare_streaming
from stayawake.cli.argtypes import add_no_stream_arg, no_stream_requested


def register(sub) -> None:
    p = add_command(
        sub, "hook", aliases=["hk"], stream=False,
        help="scan-on-clone: auto-scan repos as they are cloned/pulled",
        description=(
            "Install global git hooks so a fresh clone, a pull, a branch switch or a rebase "
            "automatically scans the code that just landed and warns you before you run it. The "
            "scan is read-only and offline, uses your allowlist and never a cloned repo's own "
            "config, and can never break a git command."),
        examples=[
            ("saw hook install", "future clones/pulls are scanned"),
            ("saw hook status", "is it active? where is its state?"),
            ("saw hook uninstall", "stop scanning future clones"),
            ("SAW_HOOK_DISABLED=1 git clone <url>", "one-off bypass, no uninstall"),
        ])
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    hsub = p.add_subparsers(dest="hook_command", metavar="<subcommand>")

    ins = add_command(
        hsub, "install",
        help="install saw's git hooks (new clones and your existing repos)",
        description="Give saw's git hooks to every repository you clone or create from now on, and "
                    "to the ones you already have: those you name, your configured local targets, "
                    "or the repository you run it in. The hooks scan what lands (a clone, pull, "
                    "branch switch or rebase) and warn before you run it, and check a push before it "
                    "leaves. Your own hooks keep running. Read-only and offline.",
        examples=[
            ("saw hook install", "scan every future clone and pull"),
            ("saw hook install -c ~/security.yml", "scan them against your allowlist"),
            ("saw hook install ~/code", "hooks for every repo under ~/code"),
        ])
    ins.add_argument("paths", nargs="*", metavar="PATH",
                     help="existing repositories, directories or globs to add the hooks to "
                          "(default: your configured local targets, else the repo you are in)")
    ins.add_argument("-c", "--config", default=None,
                     help="your config, whose allowlist the hooks scan with; a repository's own "
                          "config is never read")
    ins.set_defaults(func=run_install)

    un = add_command(
        hsub, "uninstall",
        help="remove the scan-on-clone git hooks",
        description="Reverse `saw hook install`: remove saw's hooks and restore any hook of yours "
                    "they ran before. Repositories already cloned keep the hooks they have.",
        examples=[
            ("saw hook uninstall", "stop scanning future clones"),
            ("SAW_HOOK_DISABLED=1 git clone <url>", "one-off bypass; stays installed"),
        ])
    un.set_defaults(func=run_uninstall)

    rp = add_command(
        hsub, "repair",
        help="put back the hooks saw installed",
        description="Put back every hook saw installed and set aside whatever stood in its place. "
                    "Nothing is deleted: what is set aside is kept, with a record of where it came "
                    "from, for you to examine.",
        examples=[
            ("saw hook repair", "after `saw audit` reports an altered saw hook"),
        ])
    rp.set_defaults(func=run_repair)

    stt = add_command(
        hsub, "status",
        help="show whether saw's hooks are in place",
        description="Report whether saw's hooks are in place and will run, and warn when something "
                    "would stop them.",
        examples=[
            ("saw hook status", "is it active, and where is its state?"),
        ])
    stt.set_defaults(func=run_status)

    rn = hsub.add_parser("run")                # the entry git's hook calls, not offered in help
    declare_streaming(rn, True)
    rn.add_argument("-c", "--config", default=None)
    add_no_stream_arg(rn)
    rn.add_argument("event")
    rn.add_argument("args", nargs=argparse.REMAINDER)
    rn.set_defaults(func=run_run)


def run_repair(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.repair(no_stream=no_stream_requested(a))


def run_install(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.install(config_path=a.config, no_stream=no_stream_requested(a),
                        repositories=a.paths, standing_in=True)


def run_uninstall(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.uninstall(no_stream=no_stream_requested(a))


def run_status(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.status(no_stream=no_stream_requested(a))


def run_run(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.run_event(a.event, list(a.args), config_path=a.config,
                          no_stream=no_stream_requested(a))

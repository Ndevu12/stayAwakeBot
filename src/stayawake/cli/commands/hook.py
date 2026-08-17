#!/usr/bin/env python3
"""`saw hook` — scan-on-clone (#1195). Install global git hooks that scan a repo the moment it is
cloned/pulled, so a supply-chain worm is caught BEFORE `npm install` or an editor auto-run fires.

Thin CLI: parse args and delegate to `bots.security.hook`. `saw hook run` is the internal entry the
installed git hook calls — hidden from help.
"""
from __future__ import annotations

import argparse

from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "hook", aliases=["hk"],
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
        help="install the global scan-on-clone git hooks (future clones/pulls)",
        description="Seed git's global init.templateDir so every FUTURE `git clone`/`git init` gets "
                    "post-checkout / post-merge / post-rewrite hooks that scan what just landed (a "
                    "clone, pull, branch switch, or rebase incl `git pull --rebase`) and warn before "
                    "you run it. Forward-looking (existing repos are unaffected) and coexists with a "
                    "repo's own hooks. Read-only, offline, operator-config only.",
        examples=[
            ("saw hook install", "scan every future clone and pull"),
            ("saw hook install -c ~/security.yml", "scan them against your allowlist"),
        ])
    ins.add_argument("-c", "--config", default=None,
                     help="operator config (its allowlist) to scan clones with — baked into the hook. "
                          "The hook NEVER reads a cloned repo's own config.")
    ins.set_defaults(func=run_install)

    un = add_command(
        hsub, "uninstall",
        help="remove the scan-on-clone git hooks",
        description="Reverse `saw hook install`: remove saw's hooks, restore any hook they were "
                    "chained onto, and unset git's global init.templateDir when saw owns it. Repos "
                    "already cloned keep the hook in their own .git/hooks.",
        examples=[
            ("saw hook uninstall", "stop scanning future clones"),
            ("SAW_HOOK_DISABLED=1 git clone <url>", "one-off bypass; stays installed"),
        ])
    un.set_defaults(func=run_uninstall)

    stt = add_command(
        hsub, "status",
        help="show whether scan-on-clone is installed",
        description="Report whether scan-on-clone is active, which template and hooks dir it uses, "
                    "and where the scan cache lives — and warn when a global core.hooksPath or "
                    "SAW_HOOK_DISABLED would silently stop the hooks from running.",
        examples=[
            ("saw hook status", "is it active, and where is its state?"),
        ])

    # Internal — invoked by the installed git hook, never by a person. Passing NO `help=` is what
    # keeps it out of the listing: argparse only skips a SUPPRESSed subcommand at the top level, so
    # `help=argparse.SUPPRESS` printed a literal "run  ==SUPPRESS==" row instead of hiding it.
    rn = hsub.add_parser("run")
    rn.add_argument("-c", "--config", default=None)
    rn.add_argument("event")
    rn.add_argument("args", nargs=argparse.REMAINDER)
    rn.set_defaults(func=run_run)


def run_install(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.install(config_path=a.config)


def run_uninstall(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.uninstall()


def run_status(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.status()


def run_run(a: argparse.Namespace) -> int:
    from stayawake.bots.security import hook
    return hook.run_event(a.event, list(a.args), config_path=a.config)

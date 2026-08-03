#!/usr/bin/env python3
"""`saw hook` — scan-on-clone (#1195). Install global git hooks that scan a repo the moment it is
cloned/pulled, so a supply-chain worm is caught BEFORE `npm install` or an editor auto-run fires.

Thin CLI: parse args and delegate to `bots.security.hook`. `saw hook run` is the internal entry the
installed git hook calls — hidden from help.
"""
from __future__ import annotations

import argparse


def register(sub) -> None:
    p = sub.add_parser("hook", aliases=["hk"],
                       help="scan-on-clone: auto-scan repos as they are cloned/pulled")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    hsub = p.add_subparsers(dest="hook_command", metavar="<subcommand>")

    ins = hsub.add_parser(
        "install", help="install the global scan-on-clone git hooks (future clones/pulls)",
        description="Seed git's global init.templateDir so every FUTURE `git clone`/`git init` gets "
                    "post-checkout / post-merge / post-rewrite hooks that scan what just landed (a "
                    "clone, pull, branch switch, or rebase incl `git pull --rebase`) and warn before "
                    "you run it. Forward-looking (existing repos are unaffected) and coexists with a "
                    "repo's own hooks. Read-only, offline, operator-config only.")
    ins.add_argument("-c", "--config", default=None,
                     help="operator config (its allowlist) to scan clones with — baked into the hook. "
                          "The hook NEVER reads a cloned repo's own config.")
    ins.set_defaults(func=run_install)

    un = hsub.add_parser("uninstall", help="remove the scan-on-clone git hooks")
    un.set_defaults(func=run_uninstall)

    stt = hsub.add_parser("status", help="show whether scan-on-clone is installed")
    stt.set_defaults(func=run_status)

    rn = hsub.add_parser("run", help=argparse.SUPPRESS)      # internal: invoked by the git hook
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

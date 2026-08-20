#!/usr/bin/env python3
"""`saw discard` — the inverse of `saw fix`. Routes to remediator.discard."""
from __future__ import annotations

import argparse

from stayawake.bots.security import remediator
from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "discard",
        help="undo `saw fix`: delete the auto-clean branch and/or close its PR",
        description=(
            "Remove what `saw fix` produced. It only ever touches the auto-generated "
            "`security/auto-clean` branch and its PR, never a real branch, so it cannot take "
            "your own work with it. At least one of --branch / --pr is required."),
        examples=[
            ("saw discard --branch", "delete the branch, local + remote"),
            ("saw discard --pr", "close the PRs, keep the branches"),
            ("saw discard --branch --remote", "…across the GitHub targets"),
        ])
    p.add_argument("paths", nargs="*", metavar="TARGETS",
                   help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                        "Omit to act on configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional target (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("-br", "--branch", action="store_true",
                   help="delete the security/auto-clean branch locally and on its remote (git only)")
    p.add_argument("--pr", "--close-pr", action="store_true", dest="pr",
                   help="close the open security/auto-clean PR (leaves the branch)")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep GitHub repos: ad-hoc --user/--org/owner-repo, else configured "
                        "targets, else your own repos")
    p.add_argument("--user", action="append", default=[], metavar="USER",
                   help="act on this GitHub user's repos (repeatable; implies --remote)")
    p.add_argument("--org", action="append", default=[], metavar="ORG",
                   help="act on this GitHub org's repos (repeatable; implies --remote)")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    positionals = [*a.paths, *a.extra_paths]
    remote = a.remote or bool(a.user) or bool(a.org)
    return remediator.discard(a.config, branch=a.branch, pr=a.pr, remote=remote,
                              paths=None if remote else (positionals or None),
                              slugs=(positionals or None) if remote else None,
                              users=a.user or None, orgs=a.org or None, no_stream=a.no_stream)

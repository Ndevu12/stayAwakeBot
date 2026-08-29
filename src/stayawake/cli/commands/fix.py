#!/usr/bin/env python3
"""`saw fix` — clean up worm findings on a branch. Routes to remediator.fix.

Default: PREPARE the fix on a local `security/auto-clean` branch and stop — no push, no PR,
no network. `--pr` also pushes and opens/updates one rolling PR per repo. `--remote` (or
naming `--user`/`--org`) sweeps GitHub repos (ad-hoc selectors → configured targets → your
own repos), cloning each. Scope is LOCAL by default. Each repo's outcome streams live.
(`saw discard` is the inverse.)
"""
from __future__ import annotations

import argparse
import sys

from stayawake.bots.security import remediator
from stayawake.cli.argtypes import add_jobs_arg
from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "fix",
        help="prepare a cleanup branch per infected repo (--pr to open a PR)",
        description=(
            "Clean up detected worm findings on a branch. By default the fix is PREPARED on a "
            "local `security/auto-clean` branch and nothing else happens — no push, no PR, no "
            "network. Source changes land on that branch. On a confirmed infection it also removes "
            "the installed tree, generated build outputs, and lockfile in this repository. "
            "Heuristic-only findings are disclosed for review, never auto-touched. "
            "`saw fix amend` replaces past commits that still carry the payload; it is local "
            "and does not publish. `saw discard` is the inverse of the branch/PR path."),
        examples=[
            ("saw fix", "prepare a branch per infected local repo"),
            ("saw fix .", "just this repo; review the diff, then push"),
            ("saw fix --pr", "also push + open/update one rolling PR"),
            ("saw fix --remote", "sweep the configured GitHub targets"),
            ("saw fix --branch develop", "fix a branch other than the default"),
            ("saw fix amend", "replace past commits that still carry the payload (local; not a PR)"),
        ])
    p.add_argument("paths", nargs="*", metavar="TARGETS",
                   help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                        "Omit to fix configured targets or the current repo.")
    p.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                   metavar="PATH", help="additional target (repeatable)")
    p.add_argument("-c", "--config", default=None,
                   help="config file (default: config/security.yml when present)")
    p.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                   help="also push the branch and open/update one rolling PR per repo")
    p.add_argument("-r", "--remote", action="store_true",
                   help="sweep GitHub repos (clone → fix → PR): ad-hoc --user/--org/owner-repo, "
                        "else configured targets, else your own repos")
    p.add_argument("--user", action="append", default=[], metavar="USER",
                   help="fix this GitHub user's repos (repeatable; implies --remote)")
    p.add_argument("--org", action="append", default=[], metavar="ORG",
                   help="fix this GitHub org's repos (repeatable; implies --remote)")
    add_jobs_arg(p, help="fix up to N repositories concurrently (a multi-repo sweep). Default AUTO: "
                         "one repo runs sequentially, several use one worker per CPU core. Pass a "
                         "number to cap it, `-j 1` to force sequential, or `auto`. Each repo keeps "
                         "its own branch/worktree/token, so concurrency never crosses repos.")
    p.add_argument("--branch", action="append", default=[], metavar="BRANCH",
                   help="fix this branch instead of the repository default (repeatable). "
                        "Deleting branches is not something `saw` does — remove any you no longer "
                        "want on GitHub.")
    p.add_argument("--no-stream", action="store_true", dest="no_stream",
                   help="disable live progress output (plain, instant lines)")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    positionals = [*a.paths, *a.extra_paths]
    if positionals[:1] == ["amend"]:
        if a.pr or a.remote or a.user or a.org:
            print("saw fix amend is local and does not publish", file=sys.stderr)
            return 2
        rest = positionals[1:] or None
        return remediator.amend(a.config, paths=rest, no_stream=a.no_stream)
    remote = a.remote or bool(a.user) or bool(a.org)
    return remediator.fix(a.config, pr=a.pr, remote=remote,
                          paths=None if remote else (positionals or None),
                          slugs=(positionals or None) if remote else None,
                          users=a.user or None, orgs=a.org or None, no_stream=a.no_stream,
                          jobs=a.jobs, branches=a.branch or None)

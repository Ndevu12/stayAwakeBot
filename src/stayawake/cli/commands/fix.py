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
from stayawake.cli.argtypes import add_jobs_arg, no_stream_requested
from stayawake.cli.helptext import add_command
from stayawake.cli.resolve import build_resolver
from stayawake.utils import exitcodes


def register(sub) -> None:
    p = add_command(
        sub, "fix",
        help="clear each infected checkout and prepare its cleanup branch (--pr to open a PR)",
        description=(
            "Clean up detected worm findings. By default the fix is PREPARED on a "
            "local `security/auto-clean` branch and nothing is published — no push, no PR, no "
            "network. On a confirmed infection saw also clears the checkout you are standing in: "
            "the files it confirms, the installed tree, the generated build outputs and the "
            "lockfile. What your working tree held and had not committed is recorded on a local "
            "`saw/uncommitted-…` branch that is never pushed. "
            "Heuristic-only findings are disclosed for review, never auto-touched. "
            "`saw fix amend` replaces past commits that still carry the payload and "
            "force-updates each branch they sat on. The replaced commit keeps its "
            "original message. It does not open a pull request and it does not take "
            "`--branch`. If a remote branch cannot be read, nothing is force-updated. "
            "Bare `saw fix` publishes nothing. "
            "`saw discard` is the inverse of the branch/PR path."),
        examples=[
            ("saw fix", "prepare a branch per infected local repo"),
            ("saw fix .", "just this repo; review the diff, then push"),
            ("saw fix --pr", "also push + open/update one rolling PR"),
            ("saw fix --remote", "sweep the configured GitHub targets"),
            ("saw fix --branch develop", "fix a branch other than the default"),
            ("saw fix amend", "force-update branches that still carry it"),
            ("saw fix amend --remote", "clone GitHub targets, replace, force-update"),
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
    p.add_argument("--remove-foreign", action="store_true", dest="remove_foreign",
                   help="deprecated and ignored: `amend` removes a confirmed wholly-foreign file "
                        "from history by default")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    positionals = [*a.paths, *a.extra_paths]
    if positionals[:1] == ["amend"]:
        if a.pr:
            print("saw fix amend does not open a pull request", file=sys.stderr)
            return exitcodes.INCOMPLETE
        if a.branch:
            print("saw fix amend does not take --branch", file=sys.stderr)
            return exitcodes.INCOMPLETE
        if a.user or a.org:
            print("saw fix amend does not take --user or --org; name each repository with "
                  "--remote owner/name", file=sys.stderr)
            return exitcodes.INCOMPLETE
        rest = positionals[1:] or None
        return remediator.amend(a.config, paths=None if a.remote else rest,
                                remote=a.remote,
                                slugs=(rest or None) if a.remote else None,
                                no_stream=no_stream_requested(a), jobs=a.jobs,
                                resolver=build_resolver())
    if a.remove_foreign:
        print("note: --remove-foreign is deprecated and ignored; a confirmed wholly-foreign file "
              "is removed by default", file=sys.stderr)
    remote = a.remote or bool(a.user) or bool(a.org)
    return remediator.fix(a.config, pr=a.pr, remote=remote,
                          paths=None if remote else (positionals or None),
                          slugs=(positionals or None) if remote else None,
                          users=a.user or None, orgs=a.org or None, no_stream=no_stream_requested(a),
                          jobs=a.jobs, branches=a.branch or None)

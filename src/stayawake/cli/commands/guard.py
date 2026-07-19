#!/usr/bin/env python3
"""`saw guard` — install & verify the Strix CI gate on a repo (#1229).

This slice ships `saw guard check` (read-only). `saw guard setup` (writing/updating the workflow)
builds on the same detection and follows.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.core import auth
from stayawake.core.streaming import Streamer, stream_enabled
from stayawake.core.terminal import supports_color


def register(sub) -> None:
    p = sub.add_parser("guard", aliases=["gd"],
                       help="install & verify the Strix security-scan CI gate on a repo")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    gsub = p.add_subparsers(dest="guard_command", metavar="<subcommand>")

    ck = gsub.add_parser(
        "check", help="check the worm gate across repos: present, SHA-pinned, fresh, and required",
        description="Detect the worm gate (the `Ndevu12/strix` action, a local scan action, or a "
                    "direct `saw` step), grade a Strix pin (a commit SHA is best), report whether it "
                    "is behind the latest release, and — for a remote repo — whether branch protection "
                    "requires it. LOCAL by default (discovers git repos under the given paths / the "
                    "current repo); --remote (or --user/--org) sweeps GitHub repos. Read-only.")
    ck.add_argument("targets", nargs="*", metavar="TARGETS",
                    help="local repo/dir paths — or, with --remote, owner/repo slugs. "
                         "Omit to check configured targets or the current repo.")
    ck.add_argument("-p", "--path", action="append", default=[], dest="extra_paths",
                    metavar="PATH", help="additional target (repeatable)")
    ck.add_argument("-c", "--config", default=None,
                    help="config file (default: config/security.yml when present)")
    ck.add_argument("-r", "--remote", action="store_true",
                    help="check GitHub repos instead of local: ad-hoc --user/--org/owner-repo, "
                         "else configured targets, else your own repos")
    ck.add_argument("--user", action="append", default=[], metavar="USER",
                    help="check this GitHub user's repos (repeatable; implies --remote)")
    ck.add_argument("--org", action="append", default=[], metavar="ORG",
                    help="check this GitHub org's repos (repeatable; implies --remote)")
    ck.add_argument("--repo", metavar="OWNER/NAME", default=None,
                    help="shorthand for a single remote repo (same as `--remote owner/name`)")
    ck.add_argument("-b", "--branch", default="main",
                    help="branch whose protection must require the gate (default: main)")
    ck.add_argument("-f", "--fail", action="store_true", dest="fail",
                    help="exit non-zero when ANY gate is absent, unpinned, stale, or not required")
    ck.add_argument("--no-stream", action="store_true", dest="no_stream",
                    help="disable the typewriter output (plain, instant)")
    ck.set_defaults(func=run_check)

    st = gsub.add_parser(
        "setup", help="install or update the Strix gate: write it locally, or --pr to open a PR",
        description="Resolve the latest Strix release to a commit SHA, then install the worm-guard "
                    "workflow (or surgically bump an existing pin — found by its action reference, "
                    "not filename). Writes into the working tree for you to review + commit + PR; "
                    "with --pr, opens one rolling PR instead. Never pushes to the default branch.")
    st.add_argument("-p", "--path", default=None,
                    help="repo to set up (default: the current directory)")
    st.add_argument("--pr", "--open-pr", action="store_true", dest="pr",
                    help="open/update a rolling PR instead of writing to the working tree")
    st.add_argument("--ref", default=None, metavar="SHA|TAG",
                    help="pin this Strix ref explicitly (offline/deterministic); default: latest release")
    st.add_argument("-b", "--branch", default=None,
                    help="default branch to target (default: auto-detect)")
    st.add_argument("--dry-run", action="store_true", dest="dry_run",
                    help="preview the change without writing anything")
    st.add_argument("--no-stream", action="store_true", dest="no_stream",
                    help="disable the typewriter output (plain, instant)")
    st.set_defaults(func=run_setup)


def run_check(a: argparse.Namespace) -> int:
    from stayawake.bots.security import guard   # lazy: pull yaml/API in only when the command runs

    positionals = [*a.targets, *a.extra_paths]
    remote = a.remote or bool(a.user) or bool(a.org) or bool(a.repo)   # any GitHub selector → remote
    slugs = list(positionals) if remote else None
    if a.repo:                                    # --repo owner/name is sugar for a single remote target
        slugs = (slugs or []) + [a.repo]
    return guard.check_targets(
        paths=None if remote else (positionals or None),
        slugs=slugs, users=a.user or None, orgs=a.org or None, remote=remote,
        config_path=a.config, branch=a.branch, fail=a.fail, no_stream=a.no_stream)


def run_setup(a: argparse.Namespace) -> int:
    from stayawake.bots.security import guard   # lazy: pull yaml/API/git in only when the command runs

    # Resolving the latest Strix SHA hits the API (public repo → works unauthenticated, but a token
    # eases rate limits); --pr needs it to push and open the PR. --ref lets an operator pin offline.
    token, _ = auth.resolve_token()
    if a.pr and not token:
        print(auth.no_credential_hint("opening the guard PR") +
              " (pushing the branch and opening the PR need it)\n", file=sys.stderr)

    stream = stream_enabled(sys.stdout, force_off=a.no_stream)
    result = guard.setup(a.path, token=token, ref=a.ref, dry_run=a.dry_run, pr=a.pr,
                         branch=a.branch, spin=stream)
    Streamer(enabled=stream).line(guard.render_setup(result, color=supports_color(sys.stdout)))
    return 1 if result.error else 0

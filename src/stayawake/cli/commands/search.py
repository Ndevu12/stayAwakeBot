#!/usr/bin/env python3
"""`saw search` — fuzzy "what's the command for…?" lookup over the command tree.

A dispatcher-owned command (it produces its own output), so it honours --json / -q.
"""
from __future__ import annotations

import argparse
import json

from stayawake.cli.helptext import add_command

_INDEX = [
    ("saw scan", "hunt supply-chain worms (read-only); local by default, --remote for GitHub",
     "scan check find worm malware detect virus infect supply chain json sarif alert report remote local"),
    ("saw fix", "prepare a cleanup branch per infected repo; --pr to open a PR; on confirmed infection also removes the installed tree",
     "fix remediate clean repair remove branch pr pull request open publish remote local sweep installed tree"),
    ("saw discard", "undo `saw fix`: --branch deletes the auto-clean branch, --pr closes its PR",
     "discard undo revert cleanup delete branch close pr abandon drop remove remote local"),
    ("saw audit", "credential + editor + runner-persistence + branch-protection hygiene audit",
     "audit hygiene credential token branch protection vscode editor runner self-hosted persistence"),
    ("saw guard", "install/verify the Strix worm-guard CI gate (setup needs workflow scope)",
     "guard gate worm-guard strix ci workflow setup check pin"),
    ("saw auth", "credential/capability status; register a self-owned Saw GitHub App",
     "auth login credential token scope workflow github app register doctor"),
    ("saw doctor", "self-check the install and credentials (incl. guard workflow capability)",
     "doctor diagnose verify install check health auth scope"),
    ("saw intro", "a branded tour of what saw is and how to get started",
     "intro welcome tour guide getting started banner logo about help onboarding"),
    ("saw completion", "emit a shell-completion script",
     "completion shell bash zsh fish autocomplete tab"),
]


def register(sub) -> None:
    p = add_command(
        sub, "search", aliases=["se"],
        help="fuzzy 'what's the command for…?'",
        description=(
            "Look up a command by what you want to do, across the whole command tree. Prints "
            "each matching command with a one-line summary, best match first; no match is a "
            "normal empty result, not a failure."),
        examples=[
            ('saw search "open a pr"', "→ saw fix"),
            ("saw search persistence", "→ saw audit"),
            ("saw search worm -q", "just the command names"),
        ])
    p.add_argument("text", nargs="+", metavar="TEXT")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="print only command names")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    terms = " ".join(a.text).lower().split()
    scored = []
    for cmd, summary, keywords in _INDEX:
        hay = f"{cmd} {summary} {keywords}".lower()
        score = sum(1 for t in terms if t in hay)
        if score:
            scored.append((score, cmd, summary))
    scored.sort(key=lambda x: (-x[0], x[1]))

    if a.json:
        print(json.dumps([{"command": c, "summary": s} for _, c, s in scored], indent=2))
        return 0
    if not scored:
        # No match is a normal empty result, not a gate failure — keep exit 0 so it
        # never looks like the `1` the security commands return when --fail trips.
        print(f"No commands match {' '.join(a.text)!r}. Try `saw -h` for the full list.")
        return 0
    for _, cmd, summary in scored:
        print(cmd if a.quiet else f"{cmd:<16}{summary}")
    return 0

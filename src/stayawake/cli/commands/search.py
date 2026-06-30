#!/usr/bin/env python3
"""`saw search` — fuzzy "what's the command for…?" lookup over the command tree.

A dispatcher-owned command (it produces its own output), so it honours --json / -q.
"""
from __future__ import annotations

import argparse
import json

# (command, summary, extra search keywords)
_INDEX = [
    ("saw scan", "hunt supply-chain worms (read-only); local by default, --remote for GitHub",
     "scan check find worm malware detect virus infect supply chain json sarif alert report remote local"),
    ("saw fix", "open/update a cleanup PR per infected repo; local by default, --remote for GitHub",
     "fix remediate clean repair remove pr pull request open remote local sweep"),
    ("saw audit", "credential + editor + branch-protection hygiene audit",
     "audit hygiene credential token branch protection vscode editor"),
    ("saw doctor", "self-check the install and credentials",
     "doctor diagnose verify install check health"),
    ("saw completion", "emit a shell-completion script",
     "completion shell bash zsh fish autocomplete tab"),
]


def register(sub) -> None:
    p = sub.add_parser("search", aliases=["se"], help="fuzzy 'what's the command for…?'")
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

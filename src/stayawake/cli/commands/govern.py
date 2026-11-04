#!/usr/bin/env python3
"""`saw govern` — check a git or GitHub update in a holding directory before the open folder changes."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from stayawake.bots.security import govern as core
from stayawake.bots.mcp.launch import standin_binary
from stayawake.cli.argtypes import add_progress_arg, progress_requested
from stayawake.cli.helptext import add_command
from stayawake.utils import exitcodes
from stayawake.utils.progress_events import covering
from stayawake.utils.json_documents import versioned


def register(sub) -> None:
    p = add_command(
        sub, "govern",
        help="check a git/GitHub update before the open folder changes",
        description=(
            "Carry out an incoming update — pull, fetch, merge, rebase, checkout, switch, submodule "
            "update, pull-request checkout, repo sync, or a release or artifact download — into a "
            "holding directory saw owns, scan what arrived, and change the open folder only when the "
            "scan is clean. For the editor extension: the open folder is untouched until apply, and "
            "nothing from the incoming repository runs."),
        examples=[
            ("saw govern prepare -h", "how to check an incoming update"),
            ("saw govern apply -h", "how to apply a checked update"),
        ],
        stream=False)
    # --json on the parent so `saw capabilities` advertises `govern.json`.
    p.add_argument("--json", action="store_true", help="machine-readable output")
    actions = p.add_subparsers(dest="govern_action", metavar="<action>")

    pp = add_command(
        actions, "prepare",
        help="carry an incoming update into the holding directory and scan it",
        description=(
            "Carry out the incoming command so its result exists only in the holding directory, "
            "scan what arrived with the operator's allowlist, and print the verdict. The open "
            "folder is not changed, and nothing from the incoming repository runs."),
        examples=[("saw govern prepare --repo . --into D --tool git -- pull", "check a pull")],
        stream=False)
    pp.add_argument("--json", action="store_true", help="machine-readable output")
    pp.add_argument("--repo", required=True, help="the open folder")
    pp.add_argument("--into", required=True, help="the holding directory saw owns")
    pp.add_argument("--tool", required=True, choices=core.TOOLS, help="which tool the command is")
    pp.add_argument("-c", "--config", default=None, help="your config, never the repository's")
    add_progress_arg(pp)
    pp.add_argument("args", nargs=argparse.REMAINDER, help="the operator's arguments, after --")
    pp.set_defaults(func=run_prepare)

    ap = add_command(
        actions, "apply",
        help="make the open folder match the scanned tree",
        description=(
            "Make the open folder match the tree prepare scanned in the holding directory, without "
            "fetching again. Call this only after a clean or residue verdict; the operator's "
            "uncommitted work is kept, or the open folder is not changed."),
        examples=[("saw govern apply --repo . --into D", "apply the checked tree")],
        stream=False)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--repo", required=True, help="the open folder")
    ap.add_argument("--into", required=True, help="the holding directory saw owns")
    add_progress_arg(ap)
    ap.set_defaults(func=run_apply)

    for name, helptext, description, example in _PLACEMENT:
        c = add_command(actions, name, help=helptext, description=description,
                        examples=[example], stream=False)
        c.set_defaults(func=lambda a, _name=name: _run_placement(_name))

    p.set_defaults(func=_no_action)


def _no_action(a: argparse.Namespace) -> int:
    print(json.dumps(versioned("govern", {"reason": "name an action: prepare or apply"})))
    return exitcodes.DID_NOT_RUN


def _operator_args(raw: list[str]) -> list[str]:
    """The operator's arguments, dropping a leading `--` that argparse keeps in the remainder."""
    return raw[1:] if raw and raw[0] == "--" else raw


def run_prepare(a: argparse.Namespace) -> int:
    return covering("govern", progress_requested(a), lambda: _do_prepare(a),
                    unfinished=exitcodes.INCOMPLETE, out=sys.stderr)


def _do_prepare(a: argparse.Namespace) -> int:
    payload, code = core.prepare(a.repo, a.into, a.tool, _operator_args(a.args), a.config)
    print(json.dumps(versioned("govern", payload)))
    return code


def run_apply(a: argparse.Namespace) -> int:
    return covering("govern", progress_requested(a), lambda: _do_apply(a),
                    unfinished=exitcodes.INCOMPLETE, out=sys.stderr)


def _do_apply(a: argparse.Namespace) -> int:
    payload, code = core.apply(a.repo, a.into)
    print(json.dumps(versioned("govern", payload)))
    return code


_PLACEMENT = (
    ("install",
     "check updates to git and gh in terminals too",
     ("Put saw in front of git and gh for your terminals and the shells agents run, so an incoming "
      "update is checked before it reaches the folder you are working in. Your editor is already "
      "covered. saw always falls back to the real tool, and `saw govern uninstall` takes it back."),
     ("saw govern install", "cover your terminals")),
    ("status",
     "show whether terminals are covered",
     "Say whether git and gh are checked in your terminals, and whether this shell is covered yet.",
     ("saw govern status", "see whether terminals are covered")),
    ("uninstall",
     "stop checking updates in terminals",
     "Take saw back out of git and gh for your terminals. Your editor is unaffected.",
     ("saw govern uninstall", "stop covering your terminals")),
)


def _run_placement(action: str) -> int:
    """Run the placement action in saw's stand-in. Takes the action. Returns its exit code."""
    binary = standin_binary()
    if not binary:
        print("saw govern: the stand-in is not available on this machine yet.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    return subprocess.run([binary, action, "--saw", os.path.abspath(sys.argv[0])]).returncode

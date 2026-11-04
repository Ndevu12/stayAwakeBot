#!/usr/bin/env python3
"""`saw govern` — check an incoming update before it changes an open folder."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from stayawake.bots.security.incoming import scan_arrived
from stayawake.bots.security.models import CLEAN, RESIDUE_VERDICT
from stayawake.cli.helptext import add_command, declare_streaming
from stayawake.lib.git.incoming import Arrived, apply, claim, prepare
from stayawake.utils import exitcodes
from stayawake.utils.json_documents import versioned

_STATE = "state.json"


def register(sub) -> None:
    p = add_command(
        sub, "govern", stream=False,
        help="check a pull or checkout before it changes an open folder",
        description=(
            "Check a pull, fetch, checkout, merge, rebase, or a GitHub command that lands files, "
            "before it changes the folder you have open. The folder changes only when that check "
            "is clean or only has residue. Anything else, including a check that did not finish, "
            "leaves the folder as it was."),
        examples=[
            ("saw govern prepare --repo . --into /t --tool git -- pull", "check"),
            ("saw govern apply --repo . --into /t", "apply"),
        ])
    p.add_argument("--json", action="store_true", help="print the JSON report")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    commands = p.add_subparsers(dest="govern_command", metavar="<subcommand>")

    prepare_parser = add_command(
        commands, "prepare", stream=False,
        help="check an update outside the open folder",
        description=(
            "Run a git or GitHub command in a directory outside the open folder and check what "
            "it brought in. The open folder is not changed."),
        examples=[
            ("saw govern prepare --repo . --into /t --tool git -- pull", "check"),
        ])
    _shared(prepare_parser)
    prepare_parser.add_argument("--tool", required=True, choices=("git", "gh"))
    prepare_parser.add_argument("command_args", nargs=argparse.REMAINDER)
    prepare_parser.set_defaults(func=run_prepare)
    declare_streaming(prepare_parser, False)

    apply_parser = add_command(
        commands, "apply", stream=False,
        help="change the open folder to the tree that was checked",
        description=(
            "Make the open folder match the update that was checked. It reads that result. "
            "It does not fetch again. It does nothing when the check was not clean or residue."),
        examples=[
            ("saw govern apply --repo . --into /t", "apply"),
        ])
    _shared(apply_parser)
    apply_parser.set_defaults(func=run_apply)
    declare_streaming(apply_parser, False)


def _shared(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="print the JSON report")
    parser.add_argument("--repo", required=True, help="the open folder")
    parser.add_argument("--into", required=True, help="the directory outside the open folder")
    parser.add_argument("-c", "--config", default=None, help="your config, never the repository's")


def run_prepare(a: argparse.Namespace) -> int:
    args = list(a.command_args)
    if args[:1] == ["--"]:
        args = args[1:]
    arrived = prepare(Path(a.repo), Path(a.into), a.tool, args)
    if isinstance(arrived, str):
        return _reason(arrived)
    try:
        payload, code = scan_arrived(arrived.root, arrived.paths, a.config)
    except ValueError as exc:
        return _reason(str(exc) or "the check could not use your config")
    except OSError:
        return _reason("the check could not read what arrived")
    releasable = code == exitcodes.CLEAN and _verdict(payload) in {CLEAN, RESIDUE_VERDICT}
    _write_state(Path(a.into), arrived, releasable)
    _emit(versioned("govern", {"scan": payload}))
    return code


def run_apply(a: argparse.Namespace) -> int:
    state = _read_state(Path(a.into))
    if state is None:
        return _applied(False, "there is no checked update to apply")
    if not state.get("releasable"):
        return _applied(False, "the check cannot be applied")
    try:
        arrived = Arrived(
            root=Path(state["root"]),
            paths=tuple(state["paths"]),
            mode=state["mode"],
            commit=state["commit"],
            base=state["base"],
            head=state["head"],
            refs=tuple(tuple(item) for item in state["refs"]),
        )
    except (KeyError, TypeError):
        return _applied(False, "the checked update could not be read")
    claim(Path(a.into))
    reason = apply(Path(a.repo), Path(a.into), arrived)
    if reason:
        return _applied(False, reason)
    return _applied(True, "")


def _verdict(payload: dict) -> str:
    results = payload.get("results") or []
    if not results or not isinstance(results[0], dict):
        return ""
    verdict = results[0].get("verdict")
    return verdict if isinstance(verdict, str) else ""


def _write_state(into: Path, arrived: Arrived, releasable: bool) -> None:
    body = {
        "schema": 1,
        "releasable": releasable,
        "root": str(arrived.root),
        "paths": list(arrived.paths),
        "mode": arrived.mode,
        "commit": arrived.commit,
        "base": arrived.base,
        "head": arrived.head,
        "refs": [list(item) for item in arrived.refs],
    }
    path = into / _STATE
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(body), encoding="utf-8")
    temporary.replace(path)


def _read_state(into: Path) -> dict | None:
    try:
        loaded = json.loads((into / _STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _reason(sentence: str) -> int:
    _emit(versioned("govern", {"reason": sentence}))
    return exitcodes.INCOMPLETE


def _applied(done: bool, sentence: str) -> int:
    body: dict = {"applied": done}
    if sentence:
        body["reason"] = sentence
    _emit(versioned("govern", body))
    return exitcodes.CLEAN if done else exitcodes.INCOMPLETE


def _emit(body: dict) -> None:
    json.dump(body, sys.stdout)
    sys.stdout.write("\n")
    sys.stdout.flush()

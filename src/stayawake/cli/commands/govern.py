#!/usr/bin/env python3
"""`saw govern` — check a git or GitHub update in a holding directory before the open folder changes."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys

from stayawake.bots.security import govern as core, records
from stayawake.bots.security import govern_held_commands, kept_settings
from stayawake.bots.mcp.launch import standin_binary
from stayawake.cli.argtypes import add_deadline_arg, add_progress_arg, progress_requested
from stayawake.cli.helptext import add_command
from stayawake.lib.git import settings_fingerprint
from stayawake.utils import env, exitcodes
from stayawake.utils.progress_events import covering
from stayawake.utils.json_documents import versioned
from stayawake.utils.streaming import say


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
    pp.add_argument("--brings-no-files", action="store_true",
                    help="the stand-in reads the command as one that brings no files")
    pp.add_argument("--no-one-to-ask", action="store_true",
                    help="the command ran where no one can be asked: a held update's command is kept "
                         "for saw govern let-in")
    add_progress_arg(pp)
    add_deadline_arg(pp, help="stop the check after SECONDS; an unfinished check is left to the user "
                              "to decide")
    pp.add_argument("args", nargs=argparse.REMAINDER, help="the operator's arguments, after --")
    pp.set_defaults(func=run_prepare)

    ap = add_command(
        actions, "apply",
        help="make the open folder match the scanned tree",
        description=(
            "Make the open folder match the tree prepare scanned in the holding directory, without "
            "fetching again. Call this only after a clean or residue verdict; the operator's "
            "uncommitted work is kept, or the open folder is not changed. An update that stops for "
            "conflicts is brought in with them left to resolve."),
        examples=[("saw govern apply --repo . --into D", "apply the checked tree")],
        stream=False)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--repo", required=True, help="the open folder")
    ap.add_argument("--into", required=True, help="the holding directory saw owns")
    ap.add_argument("--accept", default=None, metavar="COMMIT",
                    help="let in an update saw held, after you reviewed it: the commit it checked")
    ap.add_argument("--confirm", default=None, metavar="FOLDER",
                    help="for an infected update, the open folder's name, typed by you")
    ap.add_argument("--expect", default=None, metavar="STATE_ID",
                    help="apply only the update whose check gave this state_id")
    add_progress_arg(ap)
    ap.set_defaults(func=run_apply)

    cp = add_command(
        actions, "classify",
        help="say how saw reads a git or gh command line",
        description=(
            "Read a git or gh command line the way the program does and say whether it could be "
            "read, its subcommand after aliases, the folder it acts on, and whether saw checks it "
            "before it runs, as saw's git stand-in decides. An unreadable command line answers "
            "readable: false with the reason, and is checked."),
        examples=[("saw govern classify --json --tool git --repo . -- pull", "ask about a pull")],
        stream=False)
    cp.add_argument("--json", action="store_true", help="machine-readable output")
    cp.add_argument("--repo", default=".", help="the folder the command runs in")
    cp.add_argument("--tool", required=True, choices=core.TOOLS, help="which tool the command is")
    cp.add_argument("args", nargs=argparse.REMAINDER, help="the command's arguments, after --")
    cp.set_defaults(func=run_classify)

    vp = add_command(
        actions, "verdict",
        help="say whether the open folder's tree is one saw let in",
        description=(
            "Answer whether the folder's current tree is one saw let in — scanned clean by a hook, "
            "or applied by govern with the tree still matching — or a change that came in another "
            "way. It reads what saw already recorded; it does not scan again or change anything."),
        examples=[("saw govern verdict --repo . --json", "ask about the open folder")],
        stream=False)
    vp.add_argument("--json", action="store_true", help="machine-readable output")
    vp.add_argument("--repo", required=True, help="the open folder")
    vp.add_argument("-c", "--config", default=None, help="your config, never the repository's")
    vp.set_defaults(func=run_verdict)

    rp = add_command(
        actions, "restore",
        help="put the open folder back on the tree saw let in",
        description=(
            "Put the open folder back on the commit saw let in, keeping your uncommitted work. The "
            "branch moves to that commit, so HEAD is not left detached. Nothing is fetched. Call this "
            "after a verdict that the tree is not one saw let in."),
        examples=[("saw govern restore --repo . --json", "put the open folder back")],
        stream=False)
    rp.add_argument("--json", action="store_true", help="machine-readable output")
    rp.add_argument("--repo", required=True, help="the open folder")
    rp.add_argument("-c", "--config", default=None, help="your config, never the repository's")
    rp.set_defaults(func=run_restore)

    lp = add_command(
        actions, "let-in",
        help="review an update saw held where no one could be asked, and let it in",
        description=(
            "Run again, in this terminal, the command whose update saw held where no one could be "
            "asked. saw checks it again and asks you whether to let it in: yes for a suspicious "
            "update, the folder's name for an infected one. It needs a person at a terminal."),
        examples=[("saw govern let-in", "review the update held here"),
                  ("saw govern let-in --repo ~/code/app", "review one held for another folder")],
        stream=False)
    lp.add_argument("--repo", default=".", help="any folder in the repository the update was held for")
    lp.set_defaults(func=run_let_in)

    tp = add_command(
        actions, "trust",
        help="keep the git settings a repository sets for itself",
        description=(
            "Show the programs a repository's own git settings start, such as its hooks, filters "
            "and fsmonitor, and ask whether to keep them. When saw runs git in that repository "
            "itself, kept settings stay in force. Settings you have not kept do not start. saw asks "
            "again when they change. `--forget` stops keeping them. Keeping them needs a person at a "
            "terminal."),
        examples=[("saw govern trust", "keep this repository's git settings"),
                  ("saw govern trust --forget --repo ~/code/app", "stop keeping them")],
        stream=False)
    tp.add_argument("--repo", default=".", help="any folder in the repository")
    tp.add_argument("--forget", action="store_true", help="stop keeping the repository's settings")
    tp.set_defaults(func=run_trust)

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
    environment = core.take_command_environment()
    payload, code = core.prepare(a.repo, a.into, a.tool, _operator_args(a.args), a.config,
                                 deadline=a.deadline, environment=environment,
                                 brings_no_files=a.brings_no_files)
    if a.no_one_to_ask:
        govern_held_commands.keep_for_let_in(a.repo, [a.tool, *_operator_args(a.args)], payload)
    print(json.dumps(versioned("govern", payload)))
    return code


def run_apply(a: argparse.Namespace) -> int:
    return covering("govern", progress_requested(a), lambda: _do_apply(a),
                    unfinished=exitcodes.INCOMPLETE, out=sys.stderr)


def _do_apply(a: argparse.Namespace) -> int:
    payload, code = core.apply(a.repo, a.into, a.accept, a.confirm, a.expect)
    for step in payload.get("next_steps") or []:
        print(f"saw: {step}", file=sys.stderr)
    print(json.dumps(versioned("govern", payload)))
    return code


def run_classify(a: argparse.Namespace) -> int:
    environment = core.take_command_environment()
    payload, code = core.classify(a.repo, a.tool, _operator_args(a.args), {**os.environ, **environment})
    print(json.dumps(versioned("govern", payload)))
    return code


def run_verdict(a: argparse.Namespace) -> int:
    payload, code = core.verdict(a.repo, a.config)
    print(json.dumps(versioned("govern", payload)))
    return code


def run_restore(a: argparse.Namespace) -> int:
    payload, code = core.restore(a.repo, a.config)
    print(json.dumps(versioned("govern", payload)))
    return code


def run_let_in(a: argparse.Namespace) -> int:
    """Run again, through saw's stand-in and attached to this terminal, the command whose update saw
    held for a folder where no one could be asked. Takes the parsed arguments. Returns the
    stand-in's exit code, or DID_NOT_RUN when nothing is held, no one is at a terminal or the
    stand-in is missing."""
    folder = os.path.realpath(a.repo)
    record = govern_held_commands.read(folder)
    if record is None:
        print(f"saw: no update is held for review in {govern_held_commands.repository_of(folder)}.",
              file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    refused = govern_held_commands.refusal_to_run(record)
    if refused:
        govern_held_commands.drop(record)
        print(f"saw: the held command cannot be let in: {refused}; saw dropped it and nothing ran.",
              file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        print("saw: saw govern let-in needs a person at a terminal; nothing ran.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    binary = standin_binary()
    if not binary:
        print("saw govern: the stand-in is not available on this machine yet.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    print(f"saw: checking again: {shlex.join(record['command'])}", file=sys.stderr)
    try:
        ran = subprocess.run([binary, *record["command"]], cwd=record["ran_in"], env=_standin_environment())
    except OSError as error:
        print(f"saw: it could not run in {record['ran_in']}: {error.strerror or error}; nothing ran.",
              file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    govern_held_commands.clear(folder, record)
    return ran.returncode


def run_trust(a: argparse.Namespace) -> int:
    """Show the programs a repository's own git settings start and ask the person at a terminal
    whether to keep them, or stop keeping them with `--forget`. Takes the parsed arguments. Returns
    the exit code."""
    found = settings_fingerprint.fingerprint(a.repo)
    if found is None:
        print(f"saw: {os.path.realpath(a.repo)} is not in a git repository. Nothing changed.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    if isinstance(found, str):
        print(f"saw: {found}. Nothing changed.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    if a.forget:
        forgotten = kept_settings.forget(found.repository)
        print(f"saw: {'stopped keeping' if forgotten else 'saw was not keeping'} the git settings of "
              f"{found.folder}. git runs there without the programs they start.", file=sys.stderr)
        return exitcodes.CLEAN
    if found.empty:
        print(f"saw: the git settings of {found.folder} start no program. There is nothing to keep.",
            file=sys.stderr)
        return exitcodes.CLEAN
    if kept_settings.is_kept(found):
        print(f"saw: the git settings of {found.folder} are kept already.", file=sys.stderr)
        return exitcodes.CLEAN
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        print("saw: saw govern trust needs a person at a terminal. Nothing was kept.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    hooks = found.hooks_folder()
    print(f"This folder's git settings run: {', '.join(found.named())}.", file=sys.stderr)
    if hooks:
        print(f"Its hooks are in {hooks}.", file=sys.stderr)
    print("Keep them for this folder? [y/N] ", end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline().strip().lower()
    if answer not in ("y", "yes"):
        print("saw: not kept. git runs here without them.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    if not kept_settings.keep(found):
        print("saw: they could not be recorded. git runs here without them.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    print("saw: kept. git runs here with them until they change.", file=sys.stderr)
    return exitcodes.CLEAN


def _standin_environment() -> dict:
    """Build the stand-in's environment from this process's: no placer's holding directory, no tool
    override, no decision made ahead, and `SAW_BIN` naming this saw when it is a program that runs.
    Returns the environment."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in (env.SAW_GOVERN_HOLDING, env.SAW_GOVERN_DECISION, "SAW_STANDIN_TOOL")}
    own = os.path.abspath(sys.argv[0])
    if os.path.isfile(own) and os.access(own, os.X_OK):
        environment["SAW_BIN"] = own
    return environment


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
    """Run the placement action in saw's stand-in, saying first, for status, when saw keeps no
    records. Takes the action. Returns its exit code."""
    not_kept = records.not_kept() if action == "status" else ""
    if not_kept:
        say(not_kept, no_stream=True)
    binary = standin_binary()
    if not binary:
        print("saw govern: the stand-in is not available on this machine yet.", file=sys.stderr)
        return exitcodes.DID_NOT_RUN
    return subprocess.run([binary, action, "--saw", os.path.abspath(sys.argv[0])]).returncode

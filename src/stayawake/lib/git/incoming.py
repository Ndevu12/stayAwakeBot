#!/usr/bin/env python3
"""Run a bringing-files git or gh command in a directory saw owns, then match the open folder to it.

The open folder is not written until `apply`. The git saw runs here uses the contexts that keep a
repository's hooks, filters and configuration from deciding what runs.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import conflicted, owned
from stayawake.lib.git.borrowed import BorrowError, place
from stayawake.lib.git.query import files_brought
from stayawake.lib.git.run import OPERATOR_CONFIG, OPERATOR_PUSH, SAW_OWNED, UNTRUSTED, run_ok, stdout, stdout_bytes
from stayawake.lib.git.write.branch import refs_under, update_refs
from stayawake.lib.git.write.checkouts import Checkout
from stayawake.lib.git.write.transfer import adopt_objects, missing_objects
from stayawake.lib.git.write.working_tree import PreparedMove, changes_in_the_way, uncommitted_paths
from stayawake.lib.signing.commits.git_command import fix_commit_signing

_GLOBAL = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
    "--config-env", "--exec-path",
})
_OPTIONS_TAKING_THE_NEXT_WORD = {
    "checkout": frozenset({"-b", "-B", "--orphan", "--conflict", "--pathspec-from-file", "-U", "--unified",
                           "--inter-hunk-context"}),
    "switch": frozenset({"-c", "-C", "--create", "--force-create", "--orphan", "--conflict"}),
    "pull": frozenset({"-s", "--strategy", "-X", "--strategy-option", "--depth", "--deepen", "--shallow-since",
                       "--shallow-exclude", "-o", "--server-option", "--upload-pack", "--negotiation-tip",
                       "--negotiation-include", "--negotiation-restrict", "--cleanup", "--refmap"}),
    "merge": frozenset({"-m", "--message", "-F", "--file", "-s", "--strategy", "-X", "--strategy-option",
                        "--into-name", "--cleanup"}),
    "rebase": frozenset({"--onto", "-s", "--strategy", "-X", "--strategy-option", "-x", "--exec", "-C",
                         "--whitespace", "--empty", "--trailer"}),
    "fetch": frozenset({"-o", "--server-option", "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
                        "-j", "--jobs", "--upload-pack", "--negotiation-tip", "--negotiation-include",
                        "--negotiation-restrict", "--refmap", "--filter", "--recurse-submodules-default",
                        "--submodule-prefix"}),
}
_ENDS_OR_ONLY_TRIES = frozenset({"--abort", "--quit", "--dry-run"})
_OPTIONS_TAKING_NO_WORD = {
    "checkout": frozenset({"-q", "--quiet", "--progress", "--no-progress", "-f", "--force", "--ours", "--theirs",
                           "-t", "--track", "--no-track", "--guess", "--no-guess", "-l", "-d", "--detach", "-m",
                           "--merge", "--overlay", "--no-overlay", "--ignore-skip-worktree-bits",
                           "--ignore-other-worktrees", "--recurse-submodules", "--no-recurse-submodules",
                           "--pathspec-file-nul"}),
    "switch": frozenset({"-q", "--quiet", "--progress", "--no-progress", "-f", "--force", "--discard-changes",
                         "-t", "--track", "--no-track", "--guess", "--no-guess", "-d", "--detach", "-m", "--merge",
                         "--ignore-other-worktrees", "--recurse-submodules", "--no-recurse-submodules"}),
}
_RAW = b"* -text -eol -ident -filter -working-tree-encoding\n"
_GH_INBOUND = frozenset({("pr", "checkout"), ("repo", "sync"), ("release", "download"), ("run", "download")})
_TRACKING_KEYS = {"remote": frozenset({"url", "pushurl", "fetch", "tagopt", "prune"}),
                  "branch": frozenset({"remote", "merge", "rebase"})}
_PLAIN_KEYS = frozenset({"pull.rebase", "pull.ff"})
_IDENTITY_KEYS = ("user.name", "user.email")
_LONG_OPTIONS_THAT_RUN_A_PROGRAM = {
    "rebase": ("--exec", "--interactive", "--edit-todo"),
    "merge": ("--edit",),
    "pull": ("--edit", "--upload-pack"),
    "fetch": ("--upload-pack",),
}
_SHORT_OPTIONS_THAT_RUN_A_PROGRAM = {"rebase": "xi", "merge": "e", "pull": "e"}
_SHORT_OPTIONS_TAKING_THE_REST = "S"
_TAKES_A_STRATEGY = frozenset({"merge", "pull", "rebase"})
_BUILT_IN_STRATEGIES = frozenset({"ort", "recursive", "resolve", "octopus", "ours", "subtree"})
RUNS_OTHER_COMMANDS = "a command that runs other commands cannot be checked"

WRITE_LEFT_PART_WAY = ("the update could not be written into the open folder, and the folder may have "
                       "changed; check it with git status")
PUT_BACK_LEFT_PART_WAY = "the folder could not be put back, and it may have changed; check it with git status"
UNCARRIED_CONFLICTS = "uncarried-conflicts"


@dataclass(frozen=True)
class Arrived:
    """What a command produced outside the open folder. `written` holds the sha256 each file it
    writes into the folder must hold, by path. `versions` names other versions of files the update
    brings, as (commit, paths), and `stopped` the merge or rebase that stopped for conflicts, when
    it did. `bring_in` is the git subcommand and commit that bring in exactly the checked commit,
    for a pull that stopped for conflicts that cannot be carried."""

    root: Path
    paths: tuple[str, ...]
    mode: str
    commit: str
    base: str
    head: str
    refs: tuple[tuple[str, str, str], ...]
    written: tuple[tuple[str, str], ...] = ()
    versions: tuple[tuple[str, tuple[str, ...]], ...] = ()
    stopped: "conflicted.Stopped | None" = None
    bring_in: tuple[str, ...] = ()


def classify(tool: str, args: list[str]) -> str | None:
    """The bringing-files command `args` is, or None when saw does not check it. Takes `git` or
    `gh` and the arguments without the program name. Returns the command kind, or None."""
    if tool == "git":
        return _git_kind(args)
    if tool == "gh":
        words = [a for a in args if a != "--" and not a.startswith("-")]
        if tuple(words[:2]) in _GH_INBOUND:
            return "gh"
    return None


def brings_nothing(tool: str, args: list[str]) -> bool:
    """Tell whether a command certainly moves nothing into the open folder: a checkout or switch
    whose every option git reads as saw does, naming no commit. Takes the tool and the arguments
    without the program name. Returns the answer."""
    parsed = _parse_git(args) if tool == "git" else None
    if parsed is None:
        return False
    sub, rest = parsed
    if sub not in _OPTIONS_TAKING_NO_WORD or not _options_read_as_git_reads_them(sub, rest):
        return False
    return not (_checkout_brings(rest) if sub == "checkout" else _switch_brings(rest))


def prepare(repo: Path, into: Path, tool: str, args: list[str]) -> "Arrived | str":
    """Produce `args` under `into` and leave `repo` as it was. Takes the open folder, the holding
    directory, `git` or `gh`, and the arguments. Returns what arrived, or a sentence when it could
    not."""
    kind = classify(tool, args)
    if kind is None:
        return "saw does not check that command"
    parsed = _parse_git(args) if tool == "git" else None
    if parsed is not None and runs_other_commands(*parsed):
        return RUNS_OTHER_COMMANDS
    repo, into = Path(repo).resolve(), Path(into).resolve()
    if not (repo / ".git").exists() and _git_dir(repo) is None:
        return "the open folder is not a git checkout"
    if into == repo or repo in into.parents or into in repo.parents:
        return "the holding directory must be outside the open folder"
    base = stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip()
    if not base:
        return "the open folder has no commit to check from"
    before = refs_under(repo, "refs/heads", "refs/remotes", "refs/tags")
    if into.exists():
        shutil.rmtree(into)
    into.mkdir(parents=True)
    try:
        borrowed = place(repo, into / "repo.git")
    except (BorrowError, OSError):
        return "saw could not prepare a place to check the update"
    if not update_refs(borrowed.path, [(ref, oid, "") for ref, oid in before.items()], context=SAW_OWNED):
        return "saw could not copy the repository's refs"
    head = _head_text(repo)
    if head.startswith("ref: "):
        if not run_ok(borrowed.path, ["symbolic-ref", "HEAD", head.removeprefix("ref: ").strip()],
                      context=SAW_OWNED):
            return "saw could not prepare a place to check the update"
    elif not run_ok(borrowed.path, ["update-ref", "--no-deref", "HEAD", base], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    work = into / "work"
    work.mkdir()
    (work / ".git").write_text(f"gitdir: {borrowed.path}\n", encoding="utf-8")
    owned.own(work)
    (into / "no-hooks").mkdir()
    info = borrowed.path / "info" / "attributes"
    info.parent.mkdir(exist_ok=True)
    info.write_bytes(borrowed.attributes + _RAW)
    for key, value in (("core.bare", "false"), ("core.worktree", str(work)),
                       ("core.hooksPath", str(into / "no-hooks"))):
        if not run_ok(borrowed.path, ["config", key, value], context=SAW_OWNED):
            return "saw could not prepare a place to check the update"
    if not _carry_tracking(repo, borrowed.path):
        return "saw could not prepare a place to check the update"
    if not run_ok(work, ["checkout", "-f", "--detach", base], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    if head.startswith("ref: "):
        run_ok(borrowed.path, ["symbolic-ref", "HEAD", head.removeprefix("ref: ").strip()], context=SAW_OWNED)
    ran = _run_command(work, tool, args, kind, fix_commit_signing(repo))
    if ran and conflicted.stopped_for_conflicts(work, borrowed.path):
        return _arrived_with_conflicts(work, borrowed.path, base, kind)
    if ran:
        return ran
    after = stdout(work, ["rev-parse", "--verify", "--quiet", "HEAD"], context=SAW_OWNED).strip()
    if not after:
        return "the update did not produce a commit"
    names = files_brought(work, base, after, context=SAW_OWNED)
    if names is None:
        return "saw could not list what the update brought in"
    return Arrived(work, names, "refs" if kind == "fetch" else "tree", after, base,
                   _head_text(borrowed.path), _moved_refs(work, before, kind))


def claim(into: Path) -> None:
    """Mark the holding repository and its work tree as ones this process may write. Takes the
    holding directory. Returns nothing."""
    for made in (Path(into) / "repo.git", Path(into) / "work"):
        if made.is_dir():
            owned.own(made)


def apply(repo: Path, into: Path, arrived: Arrived) -> str:
    """Make `repo` match `arrived`. Takes the open folder, the holding directory and what prepare
    stored. Returns "" when the folder matches it, else a sentence that also names a folder that
    may have changed."""
    repo = Path(repo).resolve()
    claim(into)
    bare = Path(into) / "repo.git"
    if arrived.mode == UNCARRIED_CONFLICTS:
        return conflicted.CANNOT_CARRY
    if arrived.mode == "conflicts":
        return _apply_conflicts(repo, bare, arrived)
    if arrived.mode == "refs":
        if not arrived.refs:
            return ""
        why = adopt_objects(repo, bare, [new for _, new, _ in arrived.refs], [arrived.base])
        if why:
            return f"the update could not be copied into the open folder: {why}"
        if not update_refs(repo, list(arrived.refs)):
            return "the open folder's refs changed while the update was checked"
        return ""
    why = adopt_objects(repo, bare, [arrived.commit], [arrived.base])
    if why:
        return f"the update could not be copied into the open folder: {why}"
    way = changes_in_the_way(repo, arrived.commit)
    if way is None:
        return "saw could not tell whether uncommitted work could be kept"
    if way.blocking or way.carryable:
        return "uncommitted work would be overwritten, so the folder was not changed"
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    before = uncommitted_paths(repo)
    if before is None:
        return "the folder was not changed: its uncommitted work could not be read"
    move = PreparedMove(repo, Checkout(repo, gitdir), arrived.base, arrived.commit)
    if not move.prepare():
        move.release()
        return "the update could not be written into the open folder"
    if arrived.refs and not update_refs(repo, list(arrived.refs)):
        move.release()
        return "the open folder changed while the update was checked"
    expected = {os.fsencode(rel): digest for rel, digest in arrived.written}
    if move.apply(expected) and _write_head(gitdir, arrived.head):
        move.release()
        return ""
    move.release()
    if arrived.refs:
        update_refs(repo, [(ref, old, new) for ref, new, old in arrived.refs])
    if move.undo(before):
        return "the update could not be written into the open folder"
    return WRITE_LEFT_PART_WAY


def _arrived_with_conflicts(work: Path, holding: Path, base: str, kind: str) -> "Arrived | str":
    """Describe what a merge or rebase stopped for conflicts in the holding copy brings. Takes the
    holding work tree, its git directory, the open folder's commit and the command's kind. Returns
    what arrived: the conflicts to carry into the folder, or an update to check that stays out of
    it. Returns a sentence when neither can be described."""
    stopped = conflicted.read(work, holding, base)
    if isinstance(stopped, str):
        return _arrived_uncarried(work, holding, base, kind)
    changed = files_brought(work, base, stopped.landed, context=SAW_OWNED)
    names = None if changed is None else tuple(dict.fromkeys((*changed, *stopped.conflicts)))
    versions = conflicted.versions_brought(work, base, (stopped.incoming,), stopped.head)
    if names is None or versions is None:
        return "the files the update brings could not be listed"
    return Arrived(work, names, "conflicts", stopped.incoming, base, _head_text(holding), (),
                   versions=versions, stopped=stopped)


def _arrived_uncarried(work: Path, holding: Path, base: str, kind: str) -> "Arrived | str":
    """Describe a stop whose conflicts cannot be carried into the folder: an update to check that
    stays out of it. Takes the holding work tree, its git directory, the open folder's commit and
    the command's kind. Returns what arrived, or a sentence when its incoming commits cannot be
    read."""
    incoming = conflicted.incoming_commits(holding)
    head = stdout(work, ["rev-parse", "--verify", "--quiet", "HEAD"], context=SAW_OWNED).strip()
    versions = conflicted.versions_brought(work, base, incoming, head) if incoming and head else None
    if versions is None:
        return conflicted.CANNOT_CARRY
    bring_in = (conflicted.operation_in(holding), incoming[0]) if kind == "pull" else ()
    return Arrived(work, (), UNCARRIED_CONFLICTS, incoming[0], base, _head_text(holding), (), versions=versions,
                   bring_in=bring_in)


def _apply_conflicts(repo: Path, bare: Path, arrived: Arrived) -> str:
    """Carry a merge or rebase that stopped for conflicts into `repo`: the checked files, the
    conflicted index entries and the operation's state. Takes the open folder, the holding
    repository and what prepare stored. Returns "" when the folder holds it,
    else a sentence that also names a folder that may have changed."""
    stopped = conflicted.read(arrived.root, bare, arrived.base)
    if isinstance(stopped, str) or stopped != arrived.stopped:
        return "the checked update is no longer in the holding directory; check it again"
    if stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip() != arrived.base:
        return "the open folder changed while the update was checked"
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    head = _head_text(repo)
    if stopped.operation == conflicted.REBASE and conflicted.branch_named(stopped.files) != (
            head.removeprefix("ref: ").strip() if head.startswith("ref: ") else "detached HEAD"):
        return "the open folder changed while the update was checked"
    why = adopt_objects(repo, bare, [stopped.incoming, stopped.landed, stopped.head], [arrived.base])
    if why:
        return f"the update could not be copied into the open folder: {why}"
    if not conflicted.all_commits(repo, conflicted.commits_named(stopped.files) | {stopped.head}):
        return "the update could not be copied into the open folder"
    stages = stopped.entries_by_path()
    if missing_objects(repo, [oid.decode() for entries in stages.values() for _, oid, _ in entries]) != []:
        return "the update could not be copied into the open folder"
    way = changes_in_the_way(repo, stopped.landed)
    before = uncommitted_paths(repo)
    if way is None or before is None:
        return "the folder was not changed: its uncommitted work could not be read"
    if way.blocking or way.carryable or set(before) & set(stages):
        return "uncommitted work would be overwritten, so the folder was not changed"
    move = PreparedMove(repo, Checkout(repo, gitdir), arrived.base, stopped.landed,
                        conflict_stages=stages)
    if not move.prepare():
        move.release()
        return "the update could not be written into the open folder"
    placed = conflicted.place(gitdir, stopped.files)
    if placed is None:
        move.release()
        return "the update could not be written into the open folder"
    expected = {os.fsencode(rel): digest for rel, digest in arrived.written}
    if move.apply(expected) and (stopped.operation == conflicted.MERGE or _write_head(gitdir, stopped.head)):
        move.release()
        return ""
    move.release()
    if placed.take_back() and move.undo(before):
        return "the update could not be written into the open folder"
    return WRITE_LEFT_PART_WAY


def restore(repo: Path, commit: str) -> str:
    """Put the open folder back on `commit`, a tree saw let in, keeping uncommitted work. Takes the
    open folder and the commit, which must already be in the repository. Returns "" when the folder
    is on it, else a sentence that also names a folder that may have changed. The current branch is
    moved to the commit and HEAD stays attached."""
    repo = Path(repo).resolve()
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    if not run_ok(repo, ["cat-file", "-e", f"{commit}^{{commit}}"], context=UNTRUSTED):
        return "saw does not have the tree to put back"
    base = stdout(repo, ["rev-parse", "--verify", "--quiet", "HEAD"], context=UNTRUSTED).strip()
    if not base:
        return "the open folder has no commit to put back from"
    way = changes_in_the_way(repo, commit)
    if way is None:
        return "saw could not tell whether uncommitted work could be kept"
    if way.blocking:
        return "uncommitted work would be overwritten, so the folder was not changed"
    head = _head_text(repo)
    branch = head[len("ref: "):].strip() if head.startswith("ref: ") else None
    keep = frozenset(path.encode() for path in way.carryable)
    before = uncommitted_paths(repo)
    if before is None:
        return "the folder was not changed: its uncommitted work could not be read"
    move = PreparedMove(repo, Checkout(repo, gitdir), base, commit, keep=keep)
    if not move.prepare():
        move.release()
        return "the folder could not be put back"
    if branch and not update_refs(repo, [(branch, commit, base)]):
        move.release()
        return "the open folder changed while saw was putting it back"
    if not (move.apply() and _write_head(gitdir, head if branch else commit)):
        move.release()
        if branch:
            update_refs(repo, [(branch, base, commit)])
        if move.undo(before):
            return "the folder could not be put back"
        return PUT_BACK_LEFT_PART_WAY
    move.release()
    return ""


def _git_kind(args: list[str]) -> str | None:
    parsed = _parse_git(args)
    if parsed is None:
        return None
    sub, rest = parsed
    if any(option in _ENDS_OR_ONLY_TRIES for option in _options(sub, rest)):
        return None
    if sub in {"pull", "merge", "rebase", "fetch"}:
        return sub
    if sub == "submodule" and _positionals(sub, rest)[:1] == ["update"]:
        return sub
    if sub == "checkout" and _checkout_brings(rest):
        return sub
    if sub == "switch" and _switch_brings(rest):
        return sub
    return None


def _parse_git(args: list[str]) -> "tuple[str, list[str]] | None":
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-C") and len(arg) > 2:
            index += 1
            continue
        if arg in _GLOBAL or arg.startswith("--git-dir=") or arg.startswith("--work-tree="):
            index += 1 if "=" in arg else 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg, args[index + 1:]
    return None


def runs_other_commands(sub: str, args: list[str]) -> bool:
    """Tell whether a git command, as typed, would have git run another program or an editor: an
    exec line, an interactive edit, a merge strategy git does not build in, or a program to fetch
    with. Takes the subcommand and its arguments. Returns the answer."""
    long_options = _LONG_OPTIONS_THAT_RUN_A_PROGRAM.get(sub, ())
    short_options = _SHORT_OPTIONS_THAT_RUN_A_PROGRAM.get(sub, "")
    taking_the_next_word = "".join(option[1] for option in _OPTIONS_TAKING_THE_NEXT_WORD.get(sub, ())
                                   if len(option) == 2)
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            return False
        if arg.startswith("--"):
            name, has_value, value = arg.partition("=")
            if len(name) <= 2:
                continue
            if any(option.startswith(name) for option in long_options):
                return True
            if sub == "pull" and "--rebase".startswith(name) and value.lower().startswith("i"):
                return True
            if sub in _TAKES_A_STRATEGY and "--strategy".startswith(name):
                strategy = value if has_value else (args[index] if index < len(args) else "")
                index += 0 if has_value else 1
                if strategy not in _BUILT_IN_STRATEGIES:
                    return True
            continue
        if not arg.startswith("-") or arg == "-":
            continue
        for position, flag in enumerate(arg[1:], start=2):
            attached = arg[position:]
            if flag in short_options:
                return True
            if flag == "s" and sub in _TAKES_A_STRATEGY:
                strategy = attached or (args[index] if index < len(args) else "")
                index += 0 if attached else 1
                if strategy not in _BUILT_IN_STRATEGIES:
                    return True
                break
            if flag in taking_the_next_word:
                index += 0 if attached else 1
                break
            if flag in _SHORT_OPTIONS_TAKING_THE_REST:
                break
    return False


def _positionals(sub: str, args: list[str]) -> list[str]:
    """List the words of a git command that are not options or their values, up to `--`. Takes the
    subcommand and its arguments. Returns the words."""
    taking_a_word = _OPTIONS_TAKING_THE_NEXT_WORD.get(sub, frozenset())
    words: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg.startswith("-") and arg != "-":
            index += 2 if _takes_the_next_word(arg, taking_a_word) else 1
            continue
        words.append(arg)
        index += 1
    return words


def _options(sub: str, args: list[str]) -> list[str]:
    """List the options of a git command, up to `--`, leaving out the value an option takes. Takes the
    subcommand and its arguments. Returns the options as written."""
    taking_a_word = _OPTIONS_TAKING_THE_NEXT_WORD.get(sub, frozenset())
    options: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            break
        if arg.startswith("-") and arg != "-":
            options.append(arg)
            index += 1 if _takes_the_next_word(arg, taking_a_word) else 0
    return options


def _takes_the_next_word(arg: str, taking_a_word: frozenset[str]) -> bool:
    """Tell whether git reads the word after `arg` as its value: `arg` names an option that takes one,
    in full or by a leading part of its long name. Takes the argument and the options that take a
    word. Returns the answer."""
    if arg in taking_a_word:
        return True
    return arg.startswith("--") and "=" not in arg and len(arg) > 2 and any(
        option.startswith(arg) for option in taking_a_word if option.startswith("--"))


def _options_read_as_git_reads_them(sub: str, args: list[str]) -> bool:
    """Tell whether every option of a command, up to `--`, is one whose value saw reads the way git
    reads it. Takes the subcommand and its arguments. Returns the answer."""
    taking_a_word = _OPTIONS_TAKING_THE_NEXT_WORD.get(sub, frozenset())
    known = taking_a_word | _OPTIONS_TAKING_NO_WORD.get(sub, frozenset())
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            return True
        if not arg.startswith("-") or arg == "-":
            continue
        if arg in taking_a_word:
            index += 1
        elif arg.split("=", 1)[0] not in known and not (arg[:2] in taking_a_word and not arg.startswith("--")):
            return False
    return True


def _checkout_brings(args: list[str]) -> bool:
    """Tell whether a checkout names a commit to move the folder to. Takes its arguments. Returns the
    answer."""
    return len(_positionals("checkout", args)) > 0


def _switch_brings(args: list[str]) -> bool:
    """Tell whether a switch names a commit to move the folder to. Takes its arguments. Returns the
    answer."""
    return len(_positionals("switch", args)) > 0


def _run_command(work: Path, tool: str, args: list[str], kind: str, signing: tuple[str, ...] = ()) -> str:
    if tool == "gh":
        return _run_gh(work, args)
    parsed = _parse_git(args)
    if parsed is None:
        return "saw does not check that command"
    sub, rest = parsed
    if kind in ("pull", "fetch") and not stdout(work, ["remote"], context=SAW_OWNED).strip():
        return "the repository has no remote to fetch from"
    if kind == "pull":
        return _pull(work, rest, signing)
    if kind == "fetch":
        return "" if run_ok(work, ["fetch", *rest], context=OPERATOR_PUSH) else "the fetch did not finish"
    return "" if run_ok(work, [*signing, sub, *rest], context=SAW_OWNED) else "the update did not finish cleanly"


def _pull(work: Path, args: list[str], signing: tuple[str, ...] = ()) -> str:
    positionals = _positionals("pull", args)
    if not run_ok(work, ["fetch", *positionals[:1]], context=OPERATOR_PUSH):
        return "the fetch did not finish"
    onto = [f"{positionals[0]}/{positionals[1]}"] if len(positionals) >= 2 else ["@{upstream}"]
    rebase = _pull_rebases(work, args)
    if rebase:
        command = ["rebase", *(["--rebase-merges"] if rebase == "merges" else []), *onto]
    else:
        command = ["merge", *_pull_ff(work, args), *onto]
    return "" if run_ok(work, [*signing, *command], context=SAW_OWNED) else "the update did not finish cleanly"


def _pull_rebases(work: Path, args: list[str]) -> str:
    """Return how a pull rebases. Takes the holding checkout and the pull's arguments. Returns ""
    when it merges, else the rebase mode."""
    for arg in reversed(args):
        if arg in ("--rebase", "-r"):
            return "true"
        if arg.startswith("--rebase="):
            return _rebase_mode(arg.split("=", 1)[1])
        if arg == "--no-rebase":
            return ""
    branch = stdout(work, ["symbolic-ref", "--quiet", "--short", "HEAD"], context=SAW_OWNED).strip()
    for key in ([f"branch.{branch}.rebase"] if branch else []) + ["pull.rebase"]:
        value = stdout(work, ["config", "--get", key], context=SAW_OWNED).strip()
        if value:
            return _rebase_mode(value)
    return ""


def _rebase_mode(value: str) -> str:
    """Return the rebase mode a `pull.rebase`-style value names, or "" for no rebase."""
    lowered = value.strip().lower()
    return "" if lowered in ("false", "no", "off", "0") else ("true" if lowered in ("yes", "on", "1") else lowered)


def _pull_ff(work: Path, args: list[str]) -> list[str]:
    """Return the fast-forward option a pull's merge takes, or none."""
    for arg in reversed(args):
        if arg in ("--ff-only", "--no-ff", "--ff"):
            return [arg]
    value = stdout(work, ["config", "--get", "pull.ff"], context=SAW_OWNED).strip().lower()
    return {"only": ["--ff-only"], "false": ["--no-ff"]}.get(value, [])


def _carry_tracking(repo: Path, copy: Path) -> bool:
    """Copy into the holding repository the remotes, branch tracking, pull settings and identity a
    replay needs, read from the open folder. Takes the open folder and the holding repository.
    Returns whether every value was written."""
    listed = stdout(repo, ["config", "--local", "--null", "--get-regexp", r"^(remote|branch|pull|user)\."],
                    context=UNTRUSTED)
    carried: list[tuple[str, str]] = []
    for entry in listed.split("\0"):
        key, _, value = entry.partition("\n")
        if key and _carried(key):
            carried.append((key, value))
    present = {key.lower() for key, _ in carried}
    for key in _IDENTITY_KEYS:
        if key not in present:
            value = stdout(None, ["config", "--get", key], context=OPERATOR_CONFIG).strip()
            if value:
                carried.append((key, value))
    return all(run_ok(copy, ["config", "--add", key, value], context=SAW_OWNED) for key, value in carried)


def _carried(key: str) -> bool:
    """Return whether a config key is one a replay needs and that names no program."""
    lowered = key.lower()
    if lowered in _PLAIN_KEYS or lowered in _IDENTITY_KEYS:
        return True
    section, _, rest = lowered.partition(".")
    name = rest.rpartition(".")[2]
    return section in _TRACKING_KEYS and "." in rest and name in _TRACKING_KEYS[section]


def _run_gh(work: Path, args: list[str]) -> str:
    program = shutil.which("gh")
    if not program:
        return "gh was not found"
    try:
        result = subprocess.run([program, *args], cwd=work, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return "the GitHub command did not finish"
    return "" if result.returncode == 0 else "the GitHub command did not finish"


def _moved_refs(work: Path, before: dict, kind: str) -> tuple:
    if kind == "fetch":
        after = refs_under(work, "refs/remotes", context=SAW_OWNED)
        return tuple((ref, new, before.get(ref, "")) for ref, new in after.items() if new != before.get(ref, ""))
    gitdir = _git_dir(work)
    text = _read(gitdir / "HEAD").strip() if gitdir else ""
    if not text.startswith("ref: "):
        return ()
    ref = text.removeprefix("ref: ").strip()
    new = stdout(work, ["rev-parse", "--verify", "--quiet", ref], context=SAW_OWNED).strip()
    old = before.get(ref, "")
    return ((ref, new, old),) if new and new != old else ()


def _head_text(repo: Path) -> str:
    gitdir = _git_dir(repo)
    return _read(gitdir / "HEAD").strip() if gitdir else ""


def _git_dir(repo: Path) -> "Path | None":
    named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=UNTRUSTED).strip()
    if not named:
        named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=SAW_OWNED).strip()
    if not named or "\n" in named:
        return None
    path = Path(named)
    return path if path.is_dir() else None


def _write_head(gitdir: Path, text: str) -> bool:
    if _read(gitdir / "HEAD").strip() == text.strip():
        return True
    temporary = gitdir / "HEAD.saw"
    try:
        temporary.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        os.replace(temporary, gitdir / "HEAD")
    except OSError:
        return False
    return True


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""

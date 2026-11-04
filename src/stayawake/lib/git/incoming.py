#!/usr/bin/env python3
"""Run a bringing-files git or gh command in a directory saw owns, then match the open folder to it.

The open folder is not written until `apply`. Git saw runs uses the contexts that keep a
repository's hooks and filters from choosing what runs.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git import owned
from stayawake.lib.git.borrowed import BorrowError, place
from stayawake.lib.git.run import OPERATOR_PUSH, SAW_OWNED, UNTRUSTED, run_ok, stdout, stdout_bytes
from stayawake.lib.git.write.branch import refs_under, update_refs
from stayawake.lib.git.write.checkouts import Checkout
from stayawake.lib.git.write.transfer import adopt_objects
from stayawake.lib.git.write.working_tree import PreparedMove, changes_in_the_way

_GLOBAL = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
    "--config-env", "--exec-path",
})
_OPTION_VALUE = frozenset({"-b", "-B", "-c", "-C", "-m", "--orphan", "--recurse-submodules", "--conflict"})
_RAW = b"* -text -eol -ident -filter -working-tree-encoding\n"


@dataclass(frozen=True)
class Arrived:
    """What a command produced outside the open folder."""

    root: Path
    paths: tuple[str, ...]
    mode: str
    commit: str
    base: str
    head: str
    refs: tuple[tuple[str, str, str], ...]


def classify(tool: str, args: list[str]) -> str | None:
    """The bringing-files command `args` is, or None when saw does not check it.

    Takes `git` or `gh` and the arguments without the program name. Returns the command
    name, or None.
    """
    if tool == "git":
        return _git_kind(args)
    if tool == "gh":
        words = [a for a in args if a != "--" and not a.startswith("-")]
        pair = tuple(words[:2])
        if pair in {("pr", "checkout"), ("repo", "sync"), ("release", "download"), ("run", "download")}:
            return "gh"
    return None


def prepare(repo: Path, into: Path, tool: str, args: list[str]) -> Arrived | str:
    """Produce `args` under `into` and leave `repo` as it was. Takes the open folder, the holding
    directory, `git` or `gh`, and the arguments. Returns what arrived, or a sentence when it
    could not."""
    kind = classify(tool, args)
    if kind is None:
        return "saw does not check that command"
    repo, into = Path(repo).resolve(), Path(into).resolve()
    if not (repo / ".git").exists() and not _git_dir(repo):
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
    if not run_ok(borrowed.path, ["config", "core.bare", "false"], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    if not run_ok(borrowed.path, ["config", "core.worktree", str(work)], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    if not run_ok(borrowed.path, ["config", "core.hooksPath", str(into / "no-hooks")], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    if not run_ok(work, ["checkout", "-f", "--detach", base], context=SAW_OWNED):
        return "saw could not prepare a place to check the update"
    if head.startswith("ref: "):
        run_ok(borrowed.path, ["symbolic-ref", "HEAD", head.removeprefix("ref: ").strip()], context=SAW_OWNED)
    ran = _run_command(work, tool, args, kind)
    if ran:
        return ran
    after = stdout(work, ["rev-parse", "--verify", "--quiet", "HEAD"], context=SAW_OWNED).strip()
    if not after:
        return "the update did not produce a commit"
    names = _changed_files(work, base, after)
    if names is None:
        return "saw could not list what the update brought in"
    arrived_refs = _moved_refs(work, before, kind)
    return Arrived(work, names, "refs" if kind == "fetch" else "tree", after, base,
                   _head_text(borrowed.path), arrived_refs)


def claim(into: Path) -> None:
    """Mark the holding repository as one this process may write. Takes the holding directory.
    Returns nothing."""
    bare = Path(into) / "repo.git"
    if bare.is_dir():
        owned.own(bare)


def apply(repo: Path, into: Path, arrived: Arrived) -> str:
    """Make `repo` match `arrived`. Takes the open folder, the holding directory and what prepare
    stored. Returns "" when the folder matches it, else a sentence, and leaves the folder as it
    was when it returns a sentence."""
    repo = Path(repo).resolve()
    claim(into)
    bare = Path(into) / "repo.git"
    if arrived.mode == "refs":
        if not arrived.refs:
            return ""
        failure = adopt_objects(repo, bare, [new for _, new, _ in arrived.refs], [arrived.base])
        if failure:
            return "the update could not be copied into the open folder"
        if not update_refs(repo, list(arrived.refs)):
            return "the open folder's refs changed while the update was checked"
        return ""
    failure = adopt_objects(repo, bare, [arrived.commit], [arrived.base])
    if failure:
        return "the update could not be copied into the open folder"
    way = changes_in_the_way(repo, arrived.commit)
    if way is None:
        return "saw could not tell whether uncommitted work could be kept"
    if way.blocking:
        return "uncommitted work would be overwritten, so the folder was not changed"
    gitdir = _git_dir(repo)
    if gitdir is None:
        return "the open folder is not a git checkout"
    keep = frozenset(path.encode() for path in way.carryable)
    move = PreparedMove(repo, Checkout(repo, gitdir), arrived.base, arrived.commit, keep=keep)
    if not move.prepare():
        return "the update could not be written into the open folder"
    if arrived.refs and not update_refs(repo, list(arrived.refs)):
        move.release()
        return "the open folder changed while the update was checked"
    if not move.apply():
        if arrived.refs:
            update_refs(repo, [(ref, old, new) for ref, new, old in arrived.refs])
        return "the update could not be written into the open folder"
    if not _write_head(gitdir, arrived.head):
        move.restore_files()
        if arrived.refs:
            update_refs(repo, [(ref, old, new) for ref, new, old in arrived.refs])
        return "the update could not be written into the open folder"
    return ""


def _git_kind(args: list[str]) -> str | None:
    parsed = _parse_git(args)
    if parsed is None:
        return None
    sub, rest = parsed
    if any(flag in rest for flag in ("--abort", "--quit", "--dry-run", "-n")):
        return None
    if sub in {"pull", "merge", "rebase"}:
        return sub
    if sub == "fetch":
        return sub
    if sub == "submodule" and _positionals(rest)[:1] == ["update"]:
        return sub
    if sub == "checkout" and _checkout_brings(rest):
        return sub
    if sub == "switch" and _switch_brings(rest):
        return sub
    return None


def _parse_git(args: list[str]) -> tuple[str, list[str]] | None:
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


def _positionals(args: list[str]) -> list[str]:
    words = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg.startswith("-"):
            index += 2 if arg in _OPTION_VALUE and "=" not in arg else 1
            continue
        words.append(arg)
        index += 1
    return words


def _checkout_brings(args: list[str]) -> bool:
    if "-b" in args or "--orphan" in args:
        return False
    return len(_positionals(args[:args.index("--")] if "--" in args else args)) > 0


def _switch_brings(args: list[str]) -> bool:
    if any(flag in args for flag in ("-c", "--create", "-C", "--force-create", "--orphan")):
        return False
    return len(_positionals(args)) > 0


def _run_command(work: Path, tool: str, args: list[str], kind: str) -> str:
    """Run the command in `work`. Returns a sentence when it did not finish, else ""."""
    if tool == "gh":
        return _run_gh(work, args)
    parsed = _parse_git(args)
    if parsed is None:
        return "saw does not check that command"
    sub, rest = parsed
    if kind == "pull":
        return _pull(work, rest)
    if kind == "fetch":
        return "" if run_ok(work, ["fetch", *rest], context=OPERATOR_PUSH) else "the fetch did not finish"
    if not run_ok(work, [sub, *rest], context=SAW_OWNED):
        return "the update did not finish cleanly"
    return ""


def _pull(work: Path, args: list[str]) -> str:
    rebase = "--rebase" in args or any(a.startswith("--rebase=") and a.split("=", 1)[1] != "false" for a in args)
    positionals = _positionals(args)
    remote = positionals[:1]
    if not run_ok(work, ["fetch", *remote], context=OPERATOR_PUSH):
        return "the fetch did not finish"
    if rebase:
        onto = [f"{positionals[0]}/{positionals[1]}"] if len(positionals) >= 2 else positionals[:1]
        command = ["rebase", *onto]
    else:
        onto = [f"{positionals[0]}/{positionals[1]}"] if len(positionals) >= 2 else ["@{upstream}"]
        command = ["merge", *onto]
    return "" if run_ok(work, command, context=SAW_OWNED) else "the update did not finish cleanly"


def _run_gh(work: Path, args: list[str]) -> str:
    import subprocess
    program = shutil.which("gh")
    if not program:
        return "gh was not found"
    try:
        result = subprocess.run([program, *args], cwd=work, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return "the GitHub command did not finish"
    return "" if result.returncode == 0 else "the GitHub command did not finish"


def _changed_files(work: Path, base: str, head: str) -> tuple[str, ...] | None:
    if base == head:
        return ()
    listed = stdout_bytes(work, ["diff", "--name-only", "-z", base, head], context=SAW_OWNED)
    if listed is None:
        return None
    names = []
    for raw in listed.split(b"\0"):
        if not raw:
            continue
        name = os.fsdecode(raw)
        if (work / name).is_file():
            names.append(name)
    return tuple(names)


def _moved_refs(work: Path, before: dict[str, str], kind: str) -> tuple[tuple[str, str, str], ...]:
    if kind == "fetch":
        after = refs_under(work, "refs/remotes", context=SAW_OWNED)
        return tuple((ref, new, before.get(ref, "")) for ref, new in after.items() if new != before.get(ref, ""))
    gitdir = _git_dir(work)
    text = (gitdir / "HEAD").read_text(encoding="utf-8").strip() if gitdir else ""
    if not text.startswith("ref: "):
        return ()
    ref = text.removeprefix("ref: ").strip()
    new = stdout(work, ["rev-parse", "--verify", "--quiet", ref], context=SAW_OWNED).strip()
    old = before.get(ref, "")
    if new and new != old:
        return ((ref, new, old),)
    return ()


def _head_text(repo: Path) -> str:
    gitdir = _git_dir(repo)
    if gitdir is None:
        return ""
    try:
        return (gitdir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _git_dir(repo: Path) -> Path | None:
    named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=UNTRUSTED).strip()
    if not named:
        named = stdout(repo, ["rev-parse", "--path-format=absolute", "--git-dir"], context=SAW_OWNED).strip()
    if not named or "\n" in named:
        return None
    path = Path(named)
    return path if path.is_dir() else None


def _write_head(gitdir: Path, text: str) -> bool:
    current = _read(gitdir / "HEAD")
    if current.strip() == text.strip():
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

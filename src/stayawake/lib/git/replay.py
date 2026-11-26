#!/usr/bin/env python3
"""Replay a git command in a copy saw owns of the repository it acts on, and read what it would
change: each file of the working tree, the index, the refs, HEAD and the operation in progress.

The copy borrows the repository's objects, holds its refs, HEAD and index, and a working tree whose
files hold the bytes the folder holds now. The command runs there with hooks, filters and programs
off and no network, except that a pull or fetch fetches through the operator's own transports."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.lib.git import exec_keys, holding_directory, owned, subcommand_options
from stayawake.lib.git.borrowed import carried_attributes, write_alternates
from stayawake.lib.git.contexts import KEY_PREFIXES_A_CALLER_MAY_NOT_SET, KEYS_A_CALLER_MAY_NOT_SET
from stayawake.lib.git.run import (LOCAL_TIMEOUT, OPERATOR_CONFIG, OPERATOR_PUSH, SAW_OWNED, UNTRUSTED, run,
                                  run_ok, stdout, stdout_bytes, stdout_bytes_fed)
from stayawake.lib.git.typed_command import TypedCommand
from stayawake.lib.git.write.branch import update_refs
from stayawake.lib.git.write.working_tree import uncommitted_paths
from stayawake.lib.git.index_copy import copy_index
from stayawake.utils import pathsafe

NETWORK = frozenset({"pull", "fetch"})
READS_STANDARD_INPUT = "a command that reads what you type cannot be checked"
WRITES_ELSEWHERE = "a command that writes outside the folder's repository cannot be checked"
RUNS_OTHER_COMMANDS = "a command that runs other commands cannot be checked"
NOT_REPLAYED = "that command cannot be checked"
NO_REMOTE = "the repository has no remote to fetch from"
RECURSION_KEYS = frozenset({"submodule.recurse", "fetch.recursesubmodules"})
_RAW = b"* -text -eol -ident -filter -working-tree-encoding\n"
_STATE_FILES = ("MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD")
PSEUDO_REFS = ("ORIG_HEAD", "AUTO_MERGE")
_STATE_FOLDERS = ("rebase-merge", "rebase-apply", "sequencer")
_STASH_LOG = Path("logs") / "refs" / "stash"
_LARGEST_STATE_FILE = 16 << 20
_LARGEST_LOGS = 64 << 20
_LARGEST_OVERLAY = 1 << 30
_MOST_COPIED_FILES = 50000
_LARGEST_COPIED_TREE = 256 << 20
_GITLINK = b"160000"
_W_IDENTITY = {"GIT_AUTHOR_NAME": "saw", "GIT_AUTHOR_EMAIL": "saw@localhost", "GIT_AUTHOR_DATE": "0 +0000",
               "GIT_COMMITTER_NAME": "saw", "GIT_COMMITTER_EMAIL": "saw@localhost",
               "GIT_COMMITTER_DATE": "0 +0000"}
_TRACKING_KEYS = {"remote": frozenset({"url", "pushurl", "fetch", "tagopt", "prune"}),
                  "branch": frozenset({"remote", "merge", "rebase"})}
_PLAIN_KEYS = frozenset({"pull.rebase", "pull.ff"})
_IDENTITY_KEYS = ("user.name", "user.email")
_LONG_OPTIONS_THAT_RUN_A_PROGRAM = {
    "rebase": ("--exec", "--interactive", "--edit-todo"),
    "add": ("--patch", "--interactive", "--edit"),
    "stage": ("--patch", "--interactive", "--edit"),
    "merge": ("--edit",),
    "pull": ("--edit", "--upload-pack"),
    "fetch": ("--upload-pack",),
}
_SHORT_OPTIONS_THAT_RUN_A_PROGRAM = {"rebase": "xi", "merge": "e", "pull": "e", "add": "pie", "stage": "pie"}
_TAKES_A_STRATEGY = frozenset({"merge", "pull", "rebase"})
_BUILT_IN_STRATEGIES = frozenset({"ort", "recursive", "resolve", "octopus", "ours", "subtree"})


@dataclass(frozen=True)
class Replays:
    """How saw treats a subcommand it replays: long options that write outside the repository,
    matched by any prefix git would take, which saw refuses, whether it reads standard input when it
    names no file, and whether it writes files where it runs when its repository has no working
    tree."""

    writes_elsewhere: tuple[str, ...] = ()
    reads_input_without_a_file: bool = False
    writes_files_without_a_working_tree: bool = False


REPLAYED = {
    "checkout": Replays(), "switch": Replays(), "restore": Replays(), "reset": Replays(),
    "merge": Replays(), "rebase": Replays(), "cherry-pick": Replays(), "revert": Replays(),
    "stash": Replays(), "update-index": Replays(), "update-ref": Replays(), "symbolic-ref": Replays(),
    "add": Replays(), "stage": Replays(),
    "read-tree": Replays(writes_elsewhere=("--index-output",)),
    "checkout-index": Replays(writes_elsewhere=("--prefix", "--temp")),
    "apply": Replays(writes_elsewhere=("--unsafe-paths", "--build-fake-ancestor", "--output"),
                     reads_input_without_a_file=True, writes_files_without_a_working_tree=True),
    "pull": Replays(), "fetch": Replays(),
}


@dataclass(frozen=True)
class Location:
    """Where a command's repository is: where the command runs, its git directory, common
    directory, the working tree git gives the command (None when it gives none), index file, object
    directory and further object directories, the command's place in the working tree, the object
    format, the working tree's own repository top when it is one, and whether saw can write a result
    there: the command acts on the repository git finds there by itself."""

    folder: Path
    git_dir: Path
    common_dir: Path
    work_tree: "Path | None"
    index_file: Path
    objects: Path
    alternates: tuple[Path, ...]
    prefix: str
    object_format: str
    folder_repository: "Path | None"
    writable: bool

    @property
    def has_a_working_tree(self) -> bool:
        """Tell whether git gives the command a working tree, wherever it lies."""
        return self.work_tree is not None


@dataclass
class Holding:
    """A copy saw owns of a command's repository: the holding directory, its git directory, its
    working tree, the index the folder's files are read into, the tree those files make, the refs,
    HEAD, index entries and operation state before the command, and the commit HEAD named."""

    into: Path
    bare: Path
    work: Path
    files_index: Path
    files_before: str
    refs: dict
    head: str
    index: dict
    state: dict
    base: str
    location: Location
    symbolic_refs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Replayed:
    """What a replayed command changes. `files` lists (path, mode, blob) for each working-tree path
    whose bytes change, with an empty mode and blob for a removed file. `files_after` names the
    commit that holds the written files. `index` lists each changed index path with its entries
    before and after, each a (mode, blob, stage). `refs` lists (ref, new, old). `state_left` and
    `state_removed` name operation state files the command left or removed, and `pseudo_refs` the
    commits it pointed `ORIG_HEAD` and the like at. `finished` is whether git finished the command,
    `said` the end of what it said, `output` what it wrote to its output and to its errors, and
    `fetch_head` what a fetch wrote to `FETCH_HEAD`."""

    holding: Holding
    finished: bool
    said: str
    files: tuple[tuple[str, str, str], ...]
    files_after: str
    index: tuple[tuple[str, tuple, tuple], ...]
    refs: tuple[tuple[str, str, str], ...]
    head: str
    state_left: tuple[str, ...]
    state_removed: tuple[str, ...]
    stash_log: "bytes | None"
    pseudo_refs: tuple[tuple[str, str], ...] = ()
    output: tuple[str, str] = ("", "")
    fetch_head: "bytes | None" = None

    @property
    def changes_nothing_but_refs(self) -> bool:
        """Tell whether the command changes no file, no index entry and no operation state."""
        return not (self.files or self.index or self.state_left or self.state_removed)


def refusal(command: TypedCommand) -> str:
    """Say why saw does not replay a command, or nothing when it does. Takes the command. Returns
    the sentence, or "" when saw replays it."""
    rules = REPLAYED.get(command.sub)
    if rules is None:
        return NOT_REPLAYED
    rest = list(command.rest)
    if runs_other_commands(command.sub, rest):
        return RUNS_OTHER_COMMANDS
    for key, _value in command.settings:
        lowered = key.lower()
        if lowered in RECURSION_KEYS:
            continue
        if (exec_keys.rule_for(key) is not None or lowered in KEYS_A_CALLER_MAY_NOT_SET
                or lowered.startswith(KEY_PREFIXES_A_CALLER_MAY_NOT_SET)):
            return RUNS_OTHER_COMMANDS
    words, options = _split(rest)
    if any(name == "--stdin" or name == "--index-info" or value == "-" for name, value in options):
        return READS_STANDARD_INPUT
    if rules.reads_input_without_a_file and (not words or "-" in words):
        return READS_STANDARD_INPUT
    for name, _value in options:
        if len(name) > 3 and any(option.startswith(name) for option in rules.writes_elsewhere):
            return WRITES_ELSEWHERE
    return ""


def _split(rest: list[str]) -> tuple[list[str], list[tuple[str, "str | None"]]]:
    """Separate words from options up to `--`, joined values kept with their option. Takes the
    arguments. Returns the words and the (option, joined value) pairs."""
    words, options = [], []
    for arg in rest:
        if arg == "--":
            break
        if arg.startswith("--") or (arg.startswith("-") and arg != "-"):
            name, joined, value = arg.partition("=")
            options.append((name, value if joined else None))
        else:
            words.append(arg)
    return words, options


def runs_other_commands(sub: str, args: list[str]) -> bool:
    """Tell whether a git command, as typed, would have git run another program or an editor: an
    exec line, an interactive edit, a merge strategy git does not build in, or a program to fetch
    with. Takes the subcommand and its arguments. Returns the answer."""
    long_options = _LONG_OPTIONS_THAT_RUN_A_PROGRAM.get(sub, ())
    short_options = _SHORT_OPTIONS_THAT_RUN_A_PROGRAM.get(sub, "")
    for name, value in subcommand_options.read(sub, args).options:
        interactive = (value or "").lower().startswith("i")
        if name.startswith("--"):
            if len(name) <= 2:
                continue
            if any(option.startswith(name) for option in long_options):
                return True
            if sub == "pull" and "--rebase".startswith(name) and interactive:
                return True
            if sub in _TAKES_A_STRATEGY and "--strategy".startswith(name) and value not in _BUILT_IN_STRATEGIES:
                return True
        elif name[1] in short_options or (sub == "pull" and name == "-r" and interactive):
            return True
        elif name == "-s" and sub in _TAKES_A_STRATEGY and value not in _BUILT_IN_STRATEGIES:
            return True
    return False


def _location_env(command: TypedCommand) -> dict:
    """Build the environment that names a command's repository the way it does. Takes the command.
    Returns this process's environment with the command's location variables."""
    return {**os.environ, **dict(command.locations)}


def _asking(command: TypedCommand) -> list[str]:
    """List the options to ask git about a command's repository the way the command names it."""
    discovery = [arg for key, value in command.settings if key.lower() in ("core.worktree", "core.bare")
                 and value is not None for arg in ("-c", f"{key}={value}")]
    return discovery + command.location_options()


def locate(folder: Path, command: TypedCommand) -> "Location | str":
    """Find the repository a command acts on, the way git finds it. Takes where the command runs and
    the command. Returns the location, or a sentence when git cannot find one."""
    env, asking = _location_env(command), _asking(command)

    def answer(args: list[str]) -> "list[str] | None":
        done = run(folder, [*asking, "rev-parse", *args], env=env, context=UNTRUSTED)
        return None if done is None or done.returncode != 0 else done.stdout.splitlines()

    found = answer(["--path-format=absolute", "--absolute-git-dir", "--git-common-dir",
                    "--is-inside-work-tree", "--show-object-format"])
    if not found or len(found) != 4:
        return "the folder is not in a git repository saw can read"
    git_dir, common_dir, inside, object_format = found
    placed = answer(["--show-toplevel", "--show-prefix"])
    top = placed[0] if placed else ""
    prefix = placed[1] if placed and len(placed) > 1 and inside == "true" else ""
    if inside == "true" and not top:
        return "the folder is not in a git repository saw can read"
    paths = answer(["--path-format=absolute", "--git-path", "index", "--git-path", "objects"])
    if not paths or len(paths) != 2:
        return "the folder is not in a git repository saw can read"
    alternates = tuple(Path(entry) for entry in dict(command.locations).get(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "").split(os.pathsep) if entry)
    if any(not entry.is_absolute() for entry in alternates):
        return "the object directories the command names cannot be read"
    work_tree = Path(top) if top else None
    folder_repository = _own_repository(work_tree)
    writable = folder_repository is not None and not alternates and _same(
        Path(paths[1]), Path(common_dir) / "objects") and _is_default(folder_repository, Path(git_dir),
                                                                       Path(paths[0]))
    return Location(folder, Path(git_dir), Path(common_dir), work_tree, Path(paths[0]), Path(paths[1]), alternates,
                    prefix, object_format or "sha1", folder_repository, writable)


def _own_repository(work_tree: "Path | None") -> "Path | None":
    """Tell whether a working tree is the top of the repository git finds there by itself. Takes
    the working tree. Returns it when it is, else None."""
    if work_tree is None:
        return None
    top = stdout(work_tree, ["rev-parse", "--show-toplevel"], context=UNTRUSTED).strip()
    return work_tree if top and _same(Path(top), work_tree) else None


def _is_default(repository: Path, git_dir: Path, index_file: Path) -> bool:
    """Tell whether a git directory and index are the ones git finds for a repository by itself.
    Takes the repository top, the git directory and the index file. Returns the answer."""
    found = stdout(repository, ["rev-parse", "--path-format=absolute", "--absolute-git-dir"],
                   context=UNTRUSTED).strip()
    return bool(found) and _same(Path(found), git_dir) and _same(index_file, Path(found) / "index")


def _same(one: Path, other: Path) -> bool:
    """Tell whether two paths name the same place. Takes both. Returns the answer."""
    return os.path.realpath(one) == os.path.realpath(other)


def reproduce(location: Location, into: Path, command: TypedCommand, *, with_files: bool) -> "Holding | str":
    """Make the copy a command replays in: borrowed objects, the refs, HEAD, operation state and
    index of its repository, and a working tree holding the folder's bytes. Takes the location, the
    holding directory, the command and whether the working tree is needed. Returns the copy, or a
    sentence when it could not be made."""
    into = Path(into)
    cleared = holding_directory.clear(into)
    if cleared:
        return cleared
    into.mkdir(parents=True, exist_ok=True)
    bare, work = into / holding_directory.REPOSITORY, into / holding_directory.WORK_TREE
    made = run(None, ["init", "--bare", "--quiet", f"--object-format={location.object_format}", "--template=",
                      str(bare)], context=SAW_OWNED)
    if made is None or made.returncode != 0:
        return "a place to check the update could not be made"
    owned.own(bare)
    stores = [location.objects, *location.alternates]
    if location.folder_repository is not None:
        own_objects = stdout(location.folder_repository, ["rev-parse", "--path-format=absolute",
                                                          "--git-common-dir"], context=UNTRUSTED).strip()
        if own_objects:
            stores.append(Path(own_objects) / "objects")
    try:
        write_alternates(bare, stores)
        shallow = pathsafe.read_regular_no_follow(location.common_dir / "shallow", 64 << 20)
        if shallow is not None:
            (bare / "shallow").write_bytes(shallow)
        attributes = carried_attributes(location.folder_repository or bare, location.folder_repository,
                                        location.common_dir)
        (bare / "info").mkdir(exist_ok=True)
        (bare / "info" / "attributes").write_bytes(attributes + _RAW)
        state = _copy_state(location, bare)
    except OSError:
        return "a place to check the update could not be made"
    refs, symbolic = _refs(location, command)
    if refs is None:
        return "the repository's refs could not be copied"
    if not update_refs(bare, [(ref, oid, "") for ref, oid in refs.items()], context=SAW_OWNED):
        return "the repository's refs could not be copied"
    for ref, target in symbolic.items():
        run_ok(bare, ["symbolic-ref", ref, target], context=SAW_OWNED)
    if not _copy_logs(location, bare):
        return "the repository's refs could not be copied"
    head = _read_text(location.git_dir / "HEAD").strip()
    if not _set_head(bare, head):
        return "a place to check the update could not be made"
    base = stdout(bare, ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], context=SAW_OWNED).strip()
    work.mkdir()
    (into / holding_directory.NO_HOOKS).mkdir()
    (work / ".git").write_text(f"gitdir: {bare}\n", encoding="utf-8")
    owned.own(work)
    for key, value in (("core.bare", "false"), ("core.worktree", str(work)),
                       ("core.hooksPath", str(into / holding_directory.NO_HOOKS)), ("core.precomposeUnicode", "false")):
        if not run_ok(bare, ["config", key, value], context=SAW_OWNED):
            return "a place to check the update could not be made"
    if not _carry_tracking(location, command, bare):
        return "a place to check the update could not be made"
    sparse = _listed(location, command, ["config", "--type=bool", "--get", "core.sparseCheckout"])
    if (sparse or b"").strip() == b"true":
        return "a folder that checks out only part of its files cannot be checked"
    entries = _entries(_listed(location, command, ["ls-files", "-s", "-z"]))
    if entries is None:
        return "the folder's index could not be read"
    files_index = bare / "files.index"
    if with_files and location.work_tree:
        copied = _reproduce_files(location, work, files_index, entries)
        if copied:
            return copied
    if not _load_index(location, work, bare, files_index, entries):
        return "the folder's index could not be read"
    before = _tree_of_files(work, files_index, bare / "before.index")
    if before is None:
        return "the folder's files could not be read"
    if location.prefix:
        (work / location.prefix).mkdir(parents=True, exist_ok=True)
        owned.own(work / location.prefix)
    return Holding(into, bare, work, bare / "before.index", before, dict(refs), head, entries, state, base,
                   location, dict(symbolic))


def _refs(location: Location, command: TypedCommand) -> "tuple[dict | None, dict]":
    """Read every ref of a command's repository, symbolic ones apart. Takes the location and the
    command. Returns the refs by name and the symbolic refs by name with what they name, or None
    when git could not list them."""
    listed = _listed(location, command, ["for-each-ref", "--format=%(objectname) %(refname) %(symref)"])
    if listed is None:
        return None, {}
    refs, symbolic = {}, {}
    for line in listed.decode(errors="surrogateescape").splitlines():
        oid, _, rest = line.partition(" ")
        name, _, target = rest.partition(" ")
        if target:
            symbolic[name] = target
        elif oid and name:
            refs[name] = oid
    return refs, symbolic


def _listed(location: Location, command: TypedCommand, args: list[str]) -> "bytes | None":
    """Run a read-only git command in a command's repository, named the way the command names it.
    Takes the location, the command and the arguments. Returns the output, or None when git could
    not answer."""
    done = run(location.folder, [*command.location_options(), *args], env=_location_env(command),
               context=UNTRUSTED)
    if done is None or done.returncode != 0:
        return None
    return done.stdout.encode(errors="surrogateescape")


def _entries(listing: "bytes | None") -> "dict[bytes, tuple[tuple[bytes, bytes, bytes], ...]] | None":
    """Read `ls-files -s -z` output into each path's entries. Takes the output. Returns
    `{path: ((mode, blob, stage), ...)}`, or None when there is no output."""
    if listing is None:
        return None
    entries: dict[bytes, list] = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        info, _, path = record.partition(b"\t")
        mode, oid, stage = info.split(b" ")
        entries.setdefault(path, []).append((mode, oid, stage))
    return {path: tuple(sorted(found, key=lambda entry: entry[2])) for path, found in entries.items()}


def _index_lines(entries: dict, paths, zero: bytes) -> bytes:
    """Write `update-index --index-info` lines that set each path to its entries. Takes the entries,
    the paths and the null object id. Returns the lines."""
    lines = []
    for path in paths:
        lines.append(b"0 %s\t%s\0" % (zero, path))
        lines += [b"%s %s %s\t%s\0" % (mode, oid, stage, path) for mode, oid, stage in entries.get(path, ())]
    return b"".join(lines)


def _reproduce_files(location: Location, work: Path, files_index: Path, entries: dict) -> "str | None":
    """Write the folder's files into the holding work tree, holding the bytes the folder holds now. Takes
    the location, the holding work tree, the index to read them into and the command's index
    entries. Returns None, or a sentence when they could not be written."""
    top = location.work_tree
    own = location.folder_repository
    if own is None:
        return _copy_tree(top, work)
    listed = entries if location.writable else _entries(stdout_bytes(own, ["ls-files", "-s", "-z"],
                                                                     context=UNTRUSTED))
    if listed is None:
        return "the folder's index could not be read"
    zero = b"0" * (64 if location.object_format == "sha256" else 40)
    staged = {path: tuple(entry for entry in found if entry[2] == b"0") for path, found in listed.items()}
    feed = _index_lines(staged, [path for path, found in staged.items() if found], zero)
    env = {**os.environ, "GIT_INDEX_FILE": str(files_index)}
    if feed and stdout_bytes_fed(work, ["update-index", "-z", "--index-info"], feed, env=env,
                                 context=SAW_OWNED) is None:
        return "the folder's index could not be read"
    if not run_ok(work, ["checkout-index", "-a", "-f", "-u"], env=env, context=SAW_OWNED):
        return "the folder's files could not be copied for the check"
    changed = uncommitted_paths(own)
    if changed is None:
        return "the folder's uncommitted work could not be read"
    return _overlay(top, work, changed)


def _overlay(top: Path, work: Path, changed: list[bytes]) -> "str | None":
    """Copy what the folder holds now at each changed path over the holding work tree. Takes the
    folder, the holding work tree and the paths. Returns None, or a sentence when too much would be
    copied or a copy failed."""
    budget = _LARGEST_OVERLAY
    for rel in changed:
        if rel.endswith(b"/"):
            continue
        source, target = top / os.fsdecode(rel), work / os.fsdecode(rel)
        try:
            found = os.lstat(source)
        except FileNotFoundError:
            found = None
        except OSError:
            return "the folder's uncommitted work could not be read"
        try:
            if os.path.lexists(target) and not (target.is_dir() and not target.is_symlink()):
                target.unlink()
            if found is None:
                continue
            if stat.S_ISLNK(found.st_mode):
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.readlink(source), target)
            elif stat.S_ISREG(found.st_mode):
                budget -= found.st_size
                if budget < 0:
                    return "the folder's uncommitted work is too large to check"
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target, follow_symlinks=False)
                os.chmod(target, stat.S_IMODE(found.st_mode))
        except OSError:
            return "the folder's uncommitted work could not be read"
    return None


def _copy_tree(top: Path, work: Path) -> "str | None":
    """Copy a working tree that is not a repository's own into the holding work tree. Takes the
    folder and the holding work tree. Returns None, or a sentence when it is too large."""
    if not top.exists():
        return None
    count, size = 0, 0
    for root, folders, names in os.walk(top):
        folders[:] = [name for name in folders if not (Path(root) == top and name == ".git")]
        for name in names:
            if Path(root) == top and name == ".git":
                continue
            source = Path(root) / name
            target = work / source.relative_to(top)
            count += 1
            try:
                found = os.lstat(source)
                size += found.st_size
                if count > _MOST_COPIED_FILES or size > _LARGEST_COPIED_TREE:
                    return "the folder is too large to check"
                target.parent.mkdir(parents=True, exist_ok=True)
                if stat.S_ISLNK(found.st_mode):
                    os.symlink(os.readlink(source), target)
                elif stat.S_ISREG(found.st_mode):
                    shutil.copyfile(source, target, follow_symlinks=False)
                    os.chmod(target, stat.S_IMODE(found.st_mode))
            except OSError:
                return "the folder's files could not be read"
    return None


def _load_index(location: Location, work: Path, bare: Path, files_index: Path, entries: dict) -> bool:
    """Write the command's index into the holding copy: the files index, whose stat data is fresh,
    with conflicted entries set to what the command's index holds, or the command's own entries.
    Takes the location, the holding work tree and git directory, the files index and the command's
    entries. Returns whether it was written."""
    zero = b"0" * (64 if location.object_format == "sha256" else 40)
    index = bare / "index"
    try:
        if location.writable and files_index.exists():
            copy_index(files_index, index)
            paths = [path for path, found in entries.items() if any(entry[2] != b"0" for entry in found)]
        else:
            paths = list(entries)
    except OSError:
        return False
    feed = _index_lines(entries, paths, zero)
    return not feed or stdout_bytes_fed(work, ["update-index", "-z", "--index-info"], feed,
                                        env={**os.environ, "GIT_INDEX_FILE": str(index)},
                                        context=SAW_OWNED) is not None


def _tree_of_files(work: Path, files_index: Path, copy: Path) -> "str | None":
    """Record every file of the holding work tree in a copy of the files index and write its tree.
    Takes the holding work tree, the files index and where the copy goes. Returns the tree, or None
    when git could not write it."""
    try:
        if files_index.exists():
            copy_index(files_index, copy)
        elif copy.exists():
            copy.unlink()
    except OSError:
        return None
    env = {**os.environ, "GIT_INDEX_FILE": str(copy)}
    if not run_ok(work, ["add", "-A", "-f"], env=env, context=SAW_OWNED):
        return None
    return _write_tree(work, env)


def _write_tree(work: Path, env: dict) -> "str | None":
    """Write the tree of an index. Takes the holding work tree and the environment naming the
    index. Returns the tree id, or None."""
    done = run(work, ["write-tree"], env=env, context=SAW_OWNED)
    return done.stdout.strip() if done is not None and done.returncode == 0 and done.stdout.strip() else None


def _copy_state(location: Location, bare: Path) -> dict:
    """Copy the operation state files of a command's git directory, and the stash's log, into the
    holding git directory. Takes the location and the holding git directory. Returns each state
    file copied with its bytes."""
    state = {}
    for name in (*_STATE_FILES, *PSEUDO_REFS):
        data = pathsafe.read_regular_no_follow(location.git_dir / name, _LARGEST_STATE_FILE)
        if data is not None:
            (bare / name).write_bytes(data)
            state[name] = data
    for name in _STATE_FOLDERS:
        if os.path.lexists(location.git_dir / name):
            state[name] = None
    return state


def _copy_logs(location: Location, bare: Path) -> bool:
    """Copy the ref logs of a command's repository into the holding copy, in place of what copying
    its refs wrote there, for names such as `@{-1}` and `stash@{1}` to read the same in both.
    Takes the location and the holding git directory. Returns whether they were copied."""
    try:
        if (bare / "logs").exists():
            shutil.rmtree(bare / "logs")
        budget = _LARGEST_LOGS
        sources = [(location.git_dir / "logs" / "HEAD", bare / "logs" / "HEAD")]
        refs_logs = location.common_dir / "logs" / "refs"
        for root, _folders, names in os.walk(refs_logs):
            for name in names:
                source = Path(root) / name
                sources.append((source, bare / "logs" / "refs" / source.relative_to(refs_logs)))
        for source, target in sources:
            data = pathsafe.read_regular_no_follow(source, _LARGEST_STATE_FILE)
            if data is None:
                continue
            budget -= len(data)
            if budget < 0:
                return False
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    except OSError:
        return False
    return True


def _set_head(bare: Path, head: str) -> bool:
    """Point the holding copy's HEAD where the command's repository points it. Takes the holding git
    directory and the HEAD text. Returns whether it was set."""
    if head.startswith("ref: "):
        return run_ok(bare, ["symbolic-ref", "HEAD", head.removeprefix("ref: ").strip()], context=SAW_OWNED)
    return bool(head) and run_ok(bare, ["update-ref", "--no-deref", "HEAD", head], context=SAW_OWNED)


def _carry_tracking(location: Location, command: TypedCommand, copy: Path) -> bool:
    """Copy into the holding repository the remotes, branch tracking, pull settings and identity a
    replay needs, read from the command's repository. Takes the location, the command and the
    holding repository. Returns whether every value was written."""
    listed = _listed(location, command, ["config", "--local", "--null", "--get-regexp",
                                         r"^(remote|branch|pull|user)\."])
    carried: list[tuple[str, str]] = []
    for entry in (listed or b"").decode(errors="surrogateescape").split("\0"):
        key, _, value = entry.partition("\n")
        if key and _carried(key):
            carried.append((key, value))
    present = {key.lower() for key, _ in carried}
    for key in _IDENTITY_KEYS:
        if key not in present:
            value = stdout(None, ["config", "--get", key], context=OPERATOR_CONFIG).strip()
            if value:
                carried.append((key, value))
    try:
        with open(copy / "config", "a", encoding="utf-8") as config:
            config.write("".join(_config_lines(key, value) for key, value in carried))
    except (OSError, UnicodeError):
        return False
    return True


def _config_lines(key: str, value: str) -> str:
    """Write one setting the way git's configuration file holds it. Takes the key, in the form git
    lists it, and the value. Returns the lines."""
    section, _, rest = key.partition(".")
    subsection, _, name = rest.rpartition(".")
    header = f'[{section} "{_quoted(subsection, quote_controls=False)}"]' if subsection else f"[{section}]"
    return f'{header}\n\t{name} = "{_quoted(value, quote_controls=True)}"\n'


def _quoted(text: str, *, quote_controls: bool) -> str:
    """Escape text for a quoted configuration string. Takes the text and whether newlines and tabs
    are escaped too. Returns it."""
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    return text.replace("\n", "\\n").replace("\t", "\\t") if quote_controls else text


def _carried(key: str) -> bool:
    """Tell whether a config key is one a replay needs and that names no program. Takes the key."""
    lowered = key.lower()
    if lowered in _PLAIN_KEYS or lowered in _IDENTITY_KEYS:
        return True
    section, _, rest = lowered.partition(".")
    name = rest.rpartition(".")[2]
    return section in _TRACKING_KEYS and "." in rest and name in _TRACKING_KEYS[section]


def replay(holding: Holding, command: TypedCommand, signing: tuple[str, ...], gh_args: "list[str] | None" = None
           ) -> Replayed:
    """Run a command in its holding copy and read what it changed. Takes the copy, the command, the
    signing settings for commits it makes and, for a gh command, its arguments. Returns what changed."""
    where = holding.work / holding.location.prefix if holding.location.work_tree else holding.work
    if gh_args is not None:
        finished, output = _run_gh(holding.work, gh_args)
    elif command.sub == "pull":
        finished, output = _pull(holding.work, list(command.rest), signing)
    elif command.sub == "fetch":
        if not stdout(holding.work, ["remote"], context=SAW_OWNED).strip():
            return _read_result(holding, False, ("", NO_REMOTE))
        finished, output = _ran(run(holding.work, ["fetch", *command.rest], context=OPERATOR_PUSH))
        return _read_result(holding, finished, output,
                            pathsafe.read_regular_no_follow(holding.bare / "FETCH_HEAD", _LARGEST_STATE_FILE))
    else:
        settings = [arg for key, value in command.settings if key.lower() not in RECURSION_KEYS
                    for arg in ("-c", key if value is None else f"{key}={value}")]
        namespace = [f"--namespace={command.namespace}"] if command.namespace else []
        finished, output = _ran(run(where, [*signing, *settings, "--no-literal-pathspecs", *command.flags, *namespace,
                                            command.sub, *command.rest], context=SAW_OWNED, timeout=LOCAL_TIMEOUT * 5))
    return _read_result(holding, finished, output)


def _ran(done) -> tuple[bool, tuple[str, str]]:
    """Read whether a git command finished and what it wrote. Takes its completed process, None
    when it did not run. Returns whether it finished, and its output and errors."""
    if done is None:
        return False, ("", "")
    return done.returncode == 0, (done.stdout or "", done.stderr or "")


def _read_result(holding: Holding, finished: bool, output: tuple[str, str],
                 fetch_head: "bytes | None" = None) -> Replayed:
    """Read what a replay changed in its holding copy. Takes the copy, whether git finished, what
    it wrote to its output and errors, and what a fetch wrote to `FETCH_HEAD`. Returns what
    changed."""
    bare, work = holding.bare, holding.work
    after_entries = _entries(stdout_bytes(work, ["ls-files", "-s", "-z"], context=SAW_OWNED)) or {}
    index = tuple((os.fsdecode(path), holding.index.get(path, ()), after_entries.get(path, ()))
                  for path in sorted(set(holding.index) | set(after_entries))
                  if holding.index.get(path, ()) != after_entries.get(path, ()))
    after_tree = _tree_of_files(work, holding.files_index, bare / "after.index") or holding.files_before
    commit = _commit(bare, after_tree)
    listed = stdout_bytes(bare, ["diff-tree", "-r", "-z", "--no-renames", holding.files_before, after_tree],
                          context=SAW_OWNED) or b""
    files = []
    fields = listed.split(b"\0")
    for described, path in zip(fields[0::2], fields[1::2]):
        parts = described.split(b" ")
        if len(parts) < 5:
            continue
        new_mode, new_oid, status = parts[1], parts[3], parts[4]
        if _GITLINK in (parts[0].lstrip(b":"), new_mode):
            continue
        removed = status.startswith(b"D")
        files.append((os.fsdecode(path), "" if removed else new_mode.decode(), "" if removed else new_oid.decode()))
    refs_after, symbolic_after = _holding_refs(bare)
    refs = tuple((ref, refs_after.get(ref, ""), holding.refs.get(ref, ""))
                 for ref in sorted(set(holding.refs) | set(refs_after))
                 if refs_after.get(ref, "") != holding.refs.get(ref, ""))
    head = _read_text(bare / "HEAD").strip()
    pseudo = tuple((name, _read_text(bare / name).strip()) for name in PSEUDO_REFS
                   if _read_text(bare / name) != (holding.state.get(name) or b"").decode(errors="replace"))
    present = {name: pathsafe.read_regular_no_follow(bare / name, _LARGEST_STATE_FILE) for name in _STATE_FILES
               if os.path.lexists(bare / name)}
    present.update({name: None for name in _STATE_FOLDERS if os.path.lexists(bare / name)})
    left = tuple(name for name in present if name not in holding.state or present[name] != holding.state[name])
    removed = tuple(name for name in holding.state if name not in present and name not in PSEUDO_REFS)
    log = pathsafe.read_regular_no_follow(bare / _STASH_LOG, _LARGEST_STATE_FILE)
    before_log = pathsafe.read_regular_no_follow(holding.location.common_dir / _STASH_LOG, _LARGEST_STATE_FILE)
    said = (output[1] or output[0]).strip()[-600:]
    return Replayed(holding, finished, said, tuple(files), commit, index, refs, head, left, removed,
                    log if log != before_log else None, pseudo, output, fetch_head)


def _holding_refs(bare: Path) -> tuple[dict, dict]:
    """Read every ref of the holding copy. Takes its git directory. Returns the refs and symbolic
    refs by name."""
    listed = stdout(bare, ["for-each-ref", "--format=%(objectname) %(refname) %(symref)"], context=SAW_OWNED)
    refs, symbolic = {}, {}
    for line in listed.splitlines():
        oid, _, rest = line.partition(" ")
        name, _, target = rest.partition(" ")
        if target:
            symbolic[name] = target
        elif oid and name:
            refs[name] = oid
    return refs, symbolic


def _commit(bare: Path, tree: str) -> str:
    """Make a commit holding a tree, always the same commit for the same tree. Takes the holding git
    directory and the tree. Returns the commit id, or the tree when git could not."""
    done = run(bare, ["commit-tree", "-m", "files", tree], env={**os.environ, **_W_IDENTITY}, context=SAW_OWNED)
    return done.stdout.strip() if done is not None and done.returncode == 0 else tree


def _read_text(path: Path) -> str:
    """Read a small text file without following a link. Takes the path. Returns its text, or ""."""
    data = pathsafe.read_regular_no_follow(path, 4096)
    return data.decode(errors="replace") if data is not None else ""


def _pull(work: Path, args: list[str], signing: tuple[str, ...] = ()) -> tuple[bool, tuple[str, str]]:
    """Fetch, then merge or rebase the way a pull does, in the holding copy. Takes the holding work tree,
    the pull's arguments and the signing settings. Returns whether it finished and what git wrote."""
    if not stdout(work, ["remote"], context=SAW_OWNED).strip():
        return False, ("", NO_REMOTE)
    positionals = list(subcommand_options.read("pull", args).words)
    fetched = run(work, ["fetch", *positionals[:1]], context=OPERATOR_PUSH)
    if fetched is None or fetched.returncode != 0:
        return False, ("", "the fetch did not finish")
    onto = [f"{positionals[0]}/{positionals[1]}"] if len(positionals) >= 2 else ["@{upstream}"]
    rebase = _pull_rebases(work, args)
    if rebase:
        command = ["rebase", *(["--rebase-merges"] if rebase == "merges" else []), *onto]
    else:
        command = ["merge", *_pull_ff(work, args), *onto]
    return _ran(run(work, [*signing, *command], context=SAW_OWNED, timeout=LOCAL_TIMEOUT * 5))


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


def _run_gh(work: Path, args: list[str]) -> tuple[bool, tuple[str, str]]:
    """Run a gh command in the holding work tree. Takes the work tree and the arguments. Returns
    whether it finished and what it wrote."""
    program = shutil.which("gh")
    if not program:
        return False, ("", "gh was not found")
    try:
        result = subprocess.run([program, *args], cwd=work, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired):
        return False, ("", "the GitHub command did not finish")
    return result.returncode == 0, (result.stdout, result.stderr)

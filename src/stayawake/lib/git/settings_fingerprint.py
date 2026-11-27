#!/usr/bin/env python3
"""The fingerprint of the programs a repository's own git settings start: every setting in its own
configuration that `lib/data/git_exec_keys.json` lists as running a program, and every hook file in
the hooks folder git runs hooks from when that folder is the repository's own. The git stand-in reads
the same fingerprint. Nothing in the folder is run."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.exec_keys import ABSOLUTE_PATH, ENABLES_TRANSPORT, HOOKS_DIRECTORY, ExecKey, rule_for
from stayawake.lib.git.run import run

OWN_SCOPES = ("local", "worktree")
HOOKS_KEY = "core.hookspath"
NEVER_RUN_SUFFIX = ".sample"
SETTING = "setting"
HOOKS_FOLDER = "hooks"
HOOK = "hook"
_LOCATE = ["rev-parse", "--path-format=absolute", "--absolute-git-dir", "--git-common-dir",
           "--is-inside-work-tree"]


@dataclass(frozen=True)
class Fingerprint:
    """The programs one repository's own settings start, as sorted entries: `("setting", scope,
    key, value)`, `("hooks", folder)` and `("hook", name, sha256)`. `repository` is its common git
    directory with every link resolved, the key it is kept under; `folder` names it: the top of its
    working tree, or its git directory without one."""

    repository: str
    folder: str
    entries: tuple[tuple[str, ...], ...]

    @property
    def empty(self) -> bool:
        """Whether the repository's own settings start no program at all."""
        return not self.entries

    def digest(self) -> str:
        """Return the sha256 of the entries written as compact JSON, in hex."""
        written = json.dumps([list(entry) for entry in self.entries], ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(written.encode("utf-8")).hexdigest()

    def named(self) -> list[str]:
        """Name what the settings start, the way a person reads them: each setting's key and each
        hook by name. Returns the names in order."""
        names: list[str] = []
        for entry in self.entries:
            name = (entry[2] if entry[0] == SETTING else f"the {entry[1]} hook" if entry[0] == HOOK else None)
            if name is not None and name not in names:
                names.append(name)
        return names

    def hooks_folder(self) -> str | None:
        """Return the hooks folder whose files are in the fingerprint, or None."""
        return next((entry[1] for entry in self.entries if entry[0] == HOOKS_FOLDER), None)


def fingerprint(folder: str | Path) -> Fingerprint | str | None:
    """Read the fingerprint of the repository a folder is in. Takes the folder. Returns it, None when
    the folder is in no repository, or why it cannot be read."""
    located = run(folder, _LOCATE)
    lines = (located.stdout or "").splitlines() if located is not None and located.returncode == 0 else []
    if len(lines) != 3:
        return None
    git_dir, common_dir, inside = lines
    top = None
    if inside == "true":
        shown = run(folder, ["rev-parse", "--show-toplevel"])
        top = (shown.stdout or "").splitlines()[0] if shown is not None and shown.returncode == 0 and shown.stdout else ""
        if not top:
            return f"the working tree of {folder} could not be found"
    listed = run(folder, ["config", "--list", "--show-scope", "-z"])
    if listed is None or listed.returncode != 0:
        return f"the git settings of {folder} did not load"
    return from_listing(listed.stdout or "", git_dir, common_dir, top)


def from_listing(listing: str, git_dir: str, common_dir: str, top: str | None) -> Fingerprint | str:
    """Read the fingerprint from git's listing of every setting with its scope (`git config --list
    --show-scope -z`). Takes the listing, the git directory, the common directory and the top of the
    working tree (None without one). Returns the fingerprint, or why a hook file could not be read."""
    fields = listing.split("\0")
    entries: list[tuple[str, ...]] = []
    hooks_setting: tuple[str, str] | None = None
    for scope, entry in zip(fields[0::2], fields[1::2]):
        key, newline, value = entry.partition("\n")
        if not newline:
            continue
        if key.lower() == HOOKS_KEY and value:
            hooks_setting = (scope, value)
        rule = rule_for(key)
        if scope in OWN_SCOPES and rule is not None and runs_a_program(rule, key, value):
            entries.append((SETTING, scope, key, value))
    folder = _own_hooks_folder(hooks_setting, git_dir, common_dir, top)
    if folder is not None:
        hooks = _hook_files(folder)
        if isinstance(hooks, str):
            return hooks
        if hooks:
            entries.append((HOOKS_FOLDER, os.path.realpath(folder)))
            entries += hooks
    folder_named = top if top is not None else git_dir
    return Fingerprint(os.path.realpath(common_dir), folder_named, tuple(sorted(entries)))


def runs_a_program(rule: ExecKey, key: str, value: str) -> bool:
    """Say whether a setting's value starts a program. Takes its rule, its listed key and its
    value."""
    text = value.strip()
    if rule.runs == HOOKS_DIRECTORY:
        return bool(text)
    if rule.runs == ENABLES_TRANSPORT:
        return bool(text) and text.lower() != "never"
    if rule.runs == ABSOLUTE_PATH:
        return bool(text) and os.path.isabs(expand_home(text))
    return rule.command(key, value) is not None


def expand_home(value: str) -> str:
    """Expand a leading `~` or `~/` to the home folder. Takes the text. Returns the expanded
    text."""
    home = os.environ.get("HOME")
    if home is None:
        return value
    if value == "~":
        return home
    return home.rstrip("/") + value[1:] if value.startswith("~/") else value


def _own_hooks_folder(setting: tuple[str, str] | None, git_dir: str, common_dir: str,
                      top: str | None) -> str | None:
    """Find the hooks folder git runs hooks from when it is the repository's own: the folder its own
    settings name, a relative folder the operator's settings name, or the default under the common
    directory. Takes the last `core.hooksPath` with its scope, the git directory, the common
    directory and the top of the working tree. Returns it, or None when the operator's own folder is
    in force."""
    if setting is None:
        return os.path.join(common_dir, "hooks")
    scope, value = setting
    expanded = expand_home(value)
    if os.path.isabs(expanded):
        return expanded if scope in OWN_SCOPES else None
    return os.path.normpath(os.path.join(top if top is not None else git_dir, expanded))


def _hook_files(folder: str) -> list[tuple[str, ...]] | str:
    """List every file in a hooks folder git may run or a hook may read: each name with the sha256
    of its contents, links followed, the example files git writes left out. Takes the folder.
    Returns the entries, or why a file could not be read."""
    try:
        names = os.listdir(os.fsencode(folder))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as error:
        return f"the hooks folder {folder} could not be read: {error.strerror or error}"
    found: list[tuple[str, ...]] = []
    for raw in names:
        name = raw.decode("utf-8", "replace")
        path = os.path.join(os.fsencode(folder), raw)
        if name.endswith(NEVER_RUN_SUFFIX) or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as hook:
                found.append((HOOK, name, hashlib.sha256(hook.read()).hexdigest()))
        except OSError as error:
            return f"the hook {os.fsdecode(path)} could not be read: {error.strerror or error}"
    return found

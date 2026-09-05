#!/usr/bin/env python3
"""The git hook scripts saw installs: where they live, how they read, and how to tell one apart."""
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

from stayawake.utils import env
from stayawake.lib import git as gitutil

MARKER = "stayawake-scan-on-clone"
HOOKS = ("post-checkout", "post-merge", "post-rewrite")
LOCATION = "git-hook"


def template_dir() -> Path:
    """Return saw's managed git template directory."""
    return Path(env.xdg_config_home()) / "saw" / "git-template"


def hooks_dir() -> Path:
    """Return the hooks directory inside saw's template directory."""
    return template_dir() / "hooks"


def cache_path() -> Path:
    """Return the per-repository last-scanned-SHA cache file."""
    return Path(env.xdg_cache_home()) / "saw" / "hook-scan-cache.json"


def global_template_dir() -> str | None:
    """Return git's global `init.templateDir`, or None when unset."""
    val = gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"]).strip()
    return val or None


def render(event: str, saw: str, config: str | None) -> str:
    """Return the hook script saw installs for `event`, calling the `saw` executable."""
    cfg = f" --config {shlex.quote(config)}" if config else ""
    return (
        "#!/bin/sh\n"
        f"# {MARKER} ({event}) — installed by `saw hook install` (#1195). Must never fail git.\n"
        f'{shlex.quote(saw)} hook run{cfg} {event} "$@" </dev/null || true\n'
        f'_local="$(dirname "$0")/{event}.local"\n'
        '[ -x "$_local" ] && "$_local" "$@" || true\n'
        "exit 0\n"
    )


_QUOTED = r"(?:[\w@%+=:,./-]{1,1024}|'(?:[^'\n]|'\"'\"'){0,1024}')"
_PRISTINE = re.compile(
    r"#!/bin/sh\n"
    rf"# {re.escape(MARKER)} \((?P<event>{'|'.join(map(re.escape, HOOKS))})\) — installed by `saw hook install` \(#1195\)\. Must never fail git\.\n"
    rf"(?P<command>{_QUOTED} hook run(?: --config {_QUOTED})? (?P=event)) \"\$@\" </dev/null \|\| true\n"
    r'_local="\$\(dirname "\$0"\)/(?P=event)\.local"\n'
    r'\[ -x "\$_local" \] && "\$_local" "\$@" \|\| true\n'
    r"exit 0\n"
)


def is_ours(path: Path) -> bool:
    """Return True if the file at `path` carries saw's hook marker."""
    try:
        return MARKER in path.read_text(errors="replace")
    except OSError:
        return False


def claims_ours(text: str) -> bool:
    """Return True if `text` carries saw's hook marker."""
    return MARKER in text


def is_pristine(text: str) -> bool:
    """Return True if `text` is exactly a hook script saw installs, unmodified."""
    return _PRISTINE.fullmatch(text) is not None


def saw_command(text: str) -> list[str] | None:
    """Return the `saw` command an unmodified hook script runs, as argv, or None."""
    m = _PRISTINE.fullmatch(text)
    if m is None:
        return None
    try:
        return shlex.split(m.group("command"))
    except ValueError:
        return None


def seeded_repositories() -> list[Path]:
    """Return the repositories saw's hooks have scanned, from the hook cache."""
    try:
        cache = json.loads(cache_path().read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(cache, dict):
        return []
    return [Path(root) for root in sorted(cache)
            if isinstance(root, str) and os.path.isabs(root) and os.path.isdir(root)]


def hook_dirs() -> list[Path]:
    """Return every hooks directory git runs on this account because of a template saw manages or
    an operator configured: the template directories and the `.git/hooks` of seeded repositories."""
    dirs: list[Path] = [hooks_dir()]
    configured = global_template_dir()
    if configured:
        candidate = Path(os.path.expanduser(configured)) / "hooks"
        if not any(_same(candidate, d) for d in dirs):
            dirs.append(candidate)
    for repo in seeded_repositories():
        dirs.append(repository_hooks_dir(repo))
    return dirs


def repository_hooks_dir(repo: Path) -> Path:
    """Return the directory git runs hooks from for `repo`, honouring its own `core.hooksPath`."""
    configured = gitutil.stdout(repo, ["config", "--get", "core.hooksPath"]).strip()
    if not configured:
        return repo / ".git" / "hooks"
    path = Path(os.path.expanduser(configured))
    return path if path.is_absolute() else repo / path


def in_managed_dir(path: Path) -> bool:
    """Return True if `path` sits directly in the hooks directory saw itself manages."""
    return _same(path.parent, hooks_dir())


_SOURCED_SIBLING = re.compile(
    r"(?:^|[;&|\s])(?:\.|source)\s+\"?(?:\$\(dirname\s+\"?\$0\"?\)|\.)/([\w.-]{1,128})\"?", re.MULTILINE)
_MAX_SIBLING = 64 * 1024


def sourced_siblings(text: str, path: Path) -> list[Path]:
    """Return the files beside `path` that the hook script `text` sources."""
    return [path.parent / name for name in dict.fromkeys(_SOURCED_SIBLING.findall(text))]


def _same(a: Path, b: Path) -> bool:
    try:
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return str(a) == str(b)

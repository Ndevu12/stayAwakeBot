#!/usr/bin/env python3
"""The git hook scripts saw installs: where they live, how they read, and how to tell one apart."""
from __future__ import annotations

import datetime
import json
import os
import re
import shlex
import shutil
import sys
from hashlib import sha256
from pathlib import Path
from typing import Callable

from stayawake.utils import env, pathsafe
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


def declaration_path() -> Path:
    """Return the file where `saw hook install` records what it installed."""
    return Path(env.xdg_config_home()) / "saw" / "hook-install.json"


def saw_executable() -> str:
    """Return the absolute path of the `saw` running now."""
    return shutil.which("saw") or os.path.realpath(sys.argv[0])


def declare(saw: str, config: str | None, hooks: Path | None = None) -> bool:
    """Record the `saw`, operator config and hooks directory the hooks were installed with; True
    if read back. `hooks` defaults to saw's own directory."""
    path = declaration_path()
    where = str(hooks or hooks_dir())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            return False
        path.write_text(json.dumps({"saw": saw, "config": config, "hooks": where}), encoding="utf-8")
        return installed() == (saw, config) and installed_into() == Path(where)
    except OSError:
        return False


def _record() -> dict | None:
    try:
        path = declaration_path()
        if path.is_symlink():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("saw"), str) or not os.path.isabs(data["saw"]):
        return None
    return data


def installed() -> tuple[str, str | None] | None:
    """Return the (`saw`, config) recorded by the last install, or None when nothing is recorded."""
    data = _record()
    if data is None:
        return None
    config = data.get("config")
    return (data["saw"], config if isinstance(config, str) and os.path.isabs(config) else None)


def installed_into() -> Path | None:
    """Return the hooks directory the last install wrote into, or None when nothing is recorded."""
    data = _record()
    where = data.get("hooks") if data else None
    return Path(where) if isinstance(where, str) and os.path.isabs(where) else (hooks_dir() if data else None)


def forget() -> None:
    """Remove the record of what was installed and the list of seeded repositories."""
    for path in (declaration_path(), cache_path()):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            continue


def global_template_dir() -> str | None:
    """Return git's global `init.templateDir`, or None when unset."""
    val = gitutil.stdout(None, ["config", "--global", "--get", "init.templateDir"]).strip()
    return os.path.expanduser(val) if val else None


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
        return pathsafe.is_regular_file(path) and claims_ours(path.read_text(errors="replace"))
    except OSError:
        return False


_HEADER = re.compile(rf"^# {re.escape(MARKER)} \((?:{'|'.join(map(re.escape, HOOKS))})\)", re.MULTILINE)


def claims_ours(text: str) -> bool:
    """Return True if `text` carries the header line of a hook saw installs."""
    return _HEADER.search(text) is not None


def is_pristine(text: str) -> bool:
    """Return True if `text` is exactly a hook script saw installs, unmodified."""
    return _PRISTINE.fullmatch(text) is not None


def event_of(text: str) -> str | None:
    """Return the event an unmodified hook script serves, or None."""
    m = _PRISTINE.fullmatch(text)
    return m.group("event") if m else None


def is_installed(text: str, expected: tuple[str, str | None] | None = None) -> bool:
    """Return True if `text` is exactly the hook saw installs for its event with the recorded
    `saw` and config (`expected`, else what was declared, else the saw running now)."""
    event = event_of(text)
    if event is None:
        return False
    saw, config = expected or installed() or (saw_executable(), None)
    return text == render(event, saw, config)


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
            if isinstance(root, str) and os.path.isabs(root) and os.path.isdir(root)
            and os.path.lexists(os.path.join(root, ".git"))]


def hook_dirs(unread: list | None = None) -> list[Path]:
    """Return every distinct hooks directory git runs on this account because of a template saw
    manages or an operator configured: the template directories and each seeded repository's.
    A seeded repository git cannot answer for is appended to `unread`."""
    dirs: list[Path] = [hooks_dir()]
    configured = global_template_dir()
    candidates = [Path(os.path.expanduser(configured)) / "hooks"] if configured else []
    for repo in seeded_repositories():
        found = repository_hooks_dir(repo)
        if found is not None:
            candidates.append(found)
        elif unread is not None:
            unread.append(repo)
    for candidate in candidates:
        if not any(_same(candidate, d) for d in dirs):
            dirs.append(candidate)
    return dirs


def repository_redirects_hooks(repo: Path) -> bool:
    """Return True if `repo` sets `core.hooksPath`, so git runs its hooks from somewhere other than
    the directory saw's template seeded."""
    return bool(_ask(repo, ["config", "--get", "core.hooksPath"]).strip())


def repository_hooks_dir(repo: Path) -> Path | None:
    """Return the directory git runs hooks from for `repo`, or None when git cannot say."""
    answer = _ask(repo, ["rev-parse", "--git-path", "hooks"]).strip()
    if not answer:
        return None
    path = Path(os.path.expanduser(answer))
    return path if path.is_absolute() else Path(os.path.normpath(repo / path))


def _ask(repo: Path, args: list[str]) -> str:
    """Return git's stdout for `args` in `repo`, with no environment steering it elsewhere."""
    env_ = {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")}
    res = gitutil.run(repo, args, env=env_)
    return res.stdout if res is not None and res.returncode == 0 else ""


def global_hooks_path() -> str | None:
    """Return git's global `core.hooksPath`, or None when unset."""
    val = gitutil.stdout(None, ["config", "--global", "--get", "core.hooksPath"]).strip()
    return val or None


def in_managed_dir(path: Path) -> bool:
    """Return True if `path` sits directly in the hooks directory saw manages for itself alone."""
    return _same(path.parent, hooks_dir())


PRISTINE = "pristine"
STALE = "stale"
ALTERED = "altered"
FOREIGN = "foreign"
ABSENT = "absent"


def verdict(path: Path, expected: tuple[str, str | None] | None = None) -> str:
    """Return what the file at `path` is to saw: `PRISTINE` (exactly the hook saw installs with
    the recorded `saw` and config, and runnable), `STALE` (shaped like one but naming another
    saw or config, or not runnable), `ALTERED` (claims to be one but is not), `FOREIGN` (not
    saw's) or `ABSENT`."""
    try:
        if path.is_symlink() or not path.is_file():
            return ABSENT if not path.is_symlink() and not path.exists() else FOREIGN
        text = path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return FOREIGN
    if is_pristine(text):
        return PRISTINE if is_installed(text, expected) and os.access(path, os.X_OK) else STALE
    return ALTERED if claims_ours(text) else FOREIGN


def quarantine_dir() -> Path:
    """Return the directory saw keeps what it removed from a hooks directory."""
    return Path(env.xdg_state_home()) / "saw" / "quarantine" / "hooks"


def quarantine(path: Path) -> Path | None:
    """Move `path`, a file or directory, whole into a fresh folder under `quarantine_dir()` beside a
    record of where it came from; return that folder, or None if it could not be moved."""
    try:
        stat = path.lstat()
        digest = digest_file(path) if path.is_file() and not path.is_symlink() else None
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
        root = quarantine_dir()
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            return None
        name = _plain_name(path.name)
        for n in range(1000):
            folder = root / f"{stamp}-{name}" if n == 0 else root / f"{stamp}-{name}-{n}"
            try:
                folder.mkdir()
                break
            except FileExistsError:
                continue
        else:
            return None
        record = {"path": str(path), "sha256": digest, "size": stat.st_size,
                  "mode": oct(stat.st_mode), "mtime": stat.st_mtime, "when": stamp,
                  "symlink_target": os.readlink(path) if path.is_symlink() else None}
        (folder / "origin.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        (folder / "kept").mkdir()
        shutil.move(str(path), str(folder / "kept" / path.name))
        moved = os.path.lexists(folder / "kept" / path.name) and not os.path.lexists(path)
        return folder if moved else None
    except (OSError, ValueError):
        return None


def _plain_name(name: str) -> str:
    """Return `name` reduced to letters, digits, dot, dash and underscore, at most 64 long."""
    kept = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return (kept or "file")[:64]


def recorded_saw_runs() -> bool:
    """Return False when the `saw` recorded at install is gone or cannot be executed."""
    recorded = installed()
    return recorded is None or (os.path.isfile(recorded[0]) and os.access(recorded[0], os.X_OK))


def altered_hooks(unread: list | None = None) -> list[Path]:
    """Return every file git runs on this account that saw should have installed and did not, or
    that sits in the directory saw manages for itself alone: altered saw hooks in every hooks
    directory, anything but a pristine saw hook in saw's own, and a saw hook that is gone from
    saw's own directory or from a repository saw seeded."""
    found: list[Path] = []
    recorded = installed()
    expected = recorded or (saw_executable(), None)
    for d in hook_dirs(unread):
        if not d.is_dir():
            continue
        try:
            children = sorted(d.iterdir())
        except OSError:
            if unread is not None:
                unread.append(d)
            continue
        own = _same(d, hooks_dir())
        if own and recorded:
            found += [d / e for e in HOOKS if not os.path.lexists(d / e)]
        for p in children:
            state = verdict(p, expected)
            if state == ALTERED or (own and state not in (PRISTINE, STALE)) or (own and state == STALE and recorded):
                found.append(p)
    if recorded:
        for repo in seeded_repositories():
            d = repository_hooks_dir(repo)
            if d is None or repository_redirects_hooks(repo) or any(_same(d, t) for t in dirs_seen(d)):
                continue
            found += [d / e for e in HOOKS if not os.path.lexists(d / e)]
    return found


def dirs_seen(d: Path) -> list[Path]:
    """Return the template directories a repository's hooks directory must not be counted as."""
    configured = global_template_dir()
    return [hooks_dir()] + ([Path(configured) / "hooks"] if configured else [])


HOOK_NAMES = frozenset((
    "applypatch-msg pre-applypatch post-applypatch pre-commit pre-merge-commit prepare-commit-msg "
    "commit-msg post-commit pre-rebase post-checkout post-merge pre-push pre-receive update "
    "proc-receive post-receive post-update reference-transaction push-to-checkout pre-auto-gc "
    "post-rewrite sendemail-validate fsmonitor-watchman post-index-change p4-changelist "
    "p4-prepare-changelist p4-post-changelist p4-pre-submit").split())


def runs_as_hook(name: str) -> bool:
    """Return True if git, or a hook saw installed, runs a file of this name."""
    return name in HOOK_NAMES or (name.endswith(".local") and name[:-len(".local")] in HOOKS)


MAX_SUPPORT_FILE = 1 << 20
MAX_SUPPORT_TOTAL = 16 << 20
MAX_SUPPORT_FILES = 4096
MAX_DIGEST_FILE = 64 << 20
MAX_DIGEST_TOTAL = 256 << 20
HEAD_BYTES = 1024
_SHELL_SUFFIXES = frozenset({".sh", ".bash", ".zsh", ".ksh", ".dash"})
_PROGRAM_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py", ".rb", ".pl", ".php", ".lua",
                               ".tcl", ".awk", ".ps1"})


def read_head(path: Path, limit: int = HEAD_BYTES) -> bytes | None:
    """Return the first `limit` bytes of a regular file, or None if it cannot be read."""
    try:
        if not pathsafe.is_regular_file(path):
            return None
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def digest_file(path: Path, limit: int | None = None) -> str | None:
    """Return `sha256:size` over the whole of a regular file of at most `limit` bytes (default
    `MAX_DIGEST_FILE`), else None."""
    limit = MAX_DIGEST_FILE if limit is None else limit
    try:
        if not pathsafe.is_regular_file(path) or path.stat().st_size > limit:
            return None
        h = sha256()
        size = 0
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
                size += len(chunk)
        return f"{h.hexdigest()}:{size}"
    except OSError:
        return None


def honours_exec_bit(hooks: Path) -> bool:
    """Return False when git records that the filesystem holding `hooks` cannot keep an executable bit."""
    answer = gitutil.stdout(hooks, ["config", "--type=bool", "--get", "core.fileMode"])
    return answer.strip().lower() != "false"


def support_kind(path: Path, exec_bit_meaningful: bool, shebang_is_shell: Callable[[str], bool]) -> str:
    """Return "binary", "shell", "program" or "notes" for a support file, from its head, name and
    mode; `shebang_is_shell` judges a `#!` line."""
    head = read_head(path)
    if head is None or b"\x00" in head:
        return "binary"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"#!"):
        return "shell" if shebang_is_shell(head.decode("utf-8", "replace")) else "program"
    suffix = path.suffix.lower()
    if suffix in _SHELL_SUFFIXES:
        return "shell"
    if suffix in _PROGRAM_SUFFIXES:
        return "program"
    if not suffix and exec_bit_meaningful and os.access(path, os.X_OK):
        return "shell"
    return "notes"


def is_entry(hooks: Path, path: Path) -> bool:
    """Return True if `path` is a hook git runs from `hooks`: a runnable name, executable, at the root."""
    return path.parent == hooks and runs_as_hook(path.name) and os.access(path, os.X_OK)


def support_files(hooks: Path, unread: list) -> list[Path]:
    """Return every file under `hooks` that is not a hook git runs, shallowest first, up to one past
    `MAX_SUPPORT_FILES`, appending every directory that could not be listed to `unread`."""
    found: list[Path] = []
    pending = [hooks]
    while pending and len(found) <= MAX_SUPPORT_FILES:
        d = pending.pop(0)
        try:
            children = sorted(d.iterdir())
        except OSError:
            unread.append(d)
            continue
        for p in children:
            if p.is_dir():
                pending.append(p)
            elif p.is_file() and not is_entry(hooks, p):
                found.append(p)
    return found


def _same(a: Path, b: Path) -> bool:
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
        return os.path.realpath(a) == os.path.realpath(b)
    except OSError:
        return str(a) == str(b)

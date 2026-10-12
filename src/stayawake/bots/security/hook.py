#!/usr/bin/env python3
"""`saw hook` — scan a repository the moment its code lands on the machine.

Installs, removes and reports on the global git hooks, and runs the scan they trigger, so a clone or
pull is checked before anything in it is executed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import atomicwrite, env

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.utils import textsafe
from stayawake.utils.streaming import Streamer, busy, status as spin_status, stream_enabled
from stayawake.lib import git as gitutil
from stayawake.lib.git.contexts import empty_hooks_dir
from stayawake.bots.security import checkout_record, hookscript, outbound, push_record
from stayawake.lib.git.run import stdout_bytes
from stayawake.lib.git.write.working_tree import uncommitted_paths
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.hook_report import BRAND as _BRAND, command as _cmd, paint_at as _paint
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.config import resolve_config

_MARKER = hookscript.MARKER
_HOOKS = hookscript.HOOKS
_YIELDS_TO_THE_OPERATOR = frozenset({"pre-push"})
_NULL_REV = "0" * 40
_HEAD_MOVED_BY_A_CLONE = "clone: "
_FILES_WRITTEN = "files"
_AVOID = ("install its dependencies (`npm install` / `pip install` / `yarn` / `pnpm`), open it in "
          "your editor/IDE (auto-run tasks & extensions fire on open), or build or run it")





class HookError(Exception):
    """A hook saw would have to overwrite; the install stops and names it."""



# ── paths (XDG, mirroring dependencies.db / lib.github_app) ─────────────────────────────

template_dir = hookscript.template_dir
_hooks_dir = hookscript.hooks_dir
_cache_path = hookscript.cache_path


_saw_executable = hookscript.saw_executable


# ── install / uninstall / status ────────────────────────────────────────────────────────

_hook_script = hookscript.render
_is_ours = hookscript.is_ours


def _hookspath_git_uses() -> tuple[bool, str | None]:
    """Read the folder git runs every repository's hooks from, as git sees it outside any
    repository: system and global configuration, their includes, and the caller's environment.
    Returns whether the setting could be read, and the folder, "" when it is set empty, or None
    when it is not set."""
    res = gitutil.run(None, ["config", "-z", "--includes", "--show-scope", "--get-all",
                             "core.hooksPath"], context=gitutil.OPERATOR_CONFIG)
    if res is None or res.returncode not in (0, 1):
        return False, None
    fields = res.stdout.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        return False, None
    values = [value for scope, value in zip(fields[::2], fields[1::2])
              if not (scope == "command" and _same_path(value, empty_hooks_dir()))]
    read, from_environment = _hookspath_from_environment(os.environ)
    if not read:
        return False, None
    if from_environment is not None:
        values.append(from_environment)
    return True, values[-1] if values else None


_MOST_ENVIRONMENT_ENTRIES = 10_000


def _hookspath_from_environment(environ) -> tuple[bool, str | None]:
    """Read a hooks folder set through git's configuration environment variables. Takes the
    environment. Returns whether it could be read, and the last folder set there, or None."""
    value = None
    count = environ.get("GIT_CONFIG_COUNT")
    if count is not None:
        try:
            entries = int(count)
        except ValueError:
            return False, None
        if not 0 <= entries <= _MOST_ENVIRONMENT_ENTRIES:
            return False, None
        for i in range(entries):
            if environ.get(f"GIT_CONFIG_KEY_{i}", "").lower() == "core.hookspath":
                value = environ.get(f"GIT_CONFIG_VALUE_{i}", "")
    if "hookspath" in environ.get("GIT_CONFIG_PARAMETERS", "").lower():
        return False, None
    return True, value


def _tape(no_stream: bool, dest=None):
    """A stdout stand-in that typewrites when streaming is on, so install/status/repair match
    the other live commands."""
    dest = dest or sys.stdout
    prog = Streamer(enabled=stream_enabled(dest, force_off=no_stream), out=dest)

    class Tape:
        def write(self, s):
            if s:
                prog.write(s)

        def flush(self):
            dest.flush()

        def isatty(self):
            try:
                return dest.isatty()
            except Exception:
                return False

    return Tape()


_FIRST_GIT_RUNNING_SETTINGS_HOOKS = (2, 54)


def git_runs_settings_hooks() -> bool:
    """Tell whether the git on PATH runs hooks set in its settings. Returns True for 2.54 and later."""
    import re
    res = gitutil.run(None, ["version"], context=gitutil.OPERATOR_CONFIG)
    found = re.search(r"(\d+)\.(\d+)", res.stdout) if res is not None and res.returncode == 0 else None
    return bool(found) and (int(found.group(1)), int(found.group(2))) >= _FIRST_GIT_RUNNING_SETTINGS_HOOKS


def _settings_hook_state(event: str) -> tuple[str | None, list[str], str | None]:
    """Read saw's hook for an event from the global git settings. Takes the event. Returns its command,
    its events and its enabled setting, each as git reads them, None when unset."""
    name = hookscript.settings_hook(event)

    def get(*args: str) -> list[str] | None:
        res = gitutil.run(None, ["config", "--includes", *args], context=gitutil.OPERATOR_CONFIG)
        if res is None or res.returncode not in (0, 1):
            raise HookError(f"git's settings for hook.{name} could not be read")
        return res.stdout.split("\n")[:-1] if res.returncode == 0 else None

    command = get("--get", f"hook.{name}.command")
    events = get("--get-all", f"hook.{name}.event") or []
    enabled = get("--type=bool", "--get", f"hook.{name}.enabled")
    return (command[0] if command else None), events, (enabled[0] if enabled else None)


_NOT_IN_SETTINGS = "could not be set in your git settings, so saw's scan runs where its folder hooks do"


def _settle_hooks_folder(saw: str, config: str | None) -> tuple[Path | None, list[Action]]:
    """Put saw's hooks in the folder git runs every repository's hooks from, when that folder is the
    operator's alone. Takes the saw executable and the operator config. Returns the folder saw's hooks
    are in, or None, and what was done."""
    read, hp = _hookspath_git_uses()
    if not read or not hp or _same_path(os.path.expanduser(hp), _hooks_dir()):
        return None, []
    folder = os.path.expanduser(hp)
    problem = _hooks_folder_problem(folder)
    if problem is not None:
        return None, [Action(NOTED, Path(folder), f"{problem}, so saw's hooks were not put there")]
    return Path(folder), _settle(Path(folder), saw, config, own=False)


def _hooks_folders_to_record(settled: Path | None) -> list[Path]:
    """List every folder git runs every repository's hooks from that saw has installed into. Takes the
    one settled now, or None. Returns them, the earlier ones first."""
    held = hookscript.installed_hooks_folders()
    if settled is not None and not any(_same_path(settled, f) for f in held):
        held.append(settled)
    return held


def _settle_settings_hooks(saw: str, config: str | None) -> list[Action]:
    """Set saw's scan as a hook in the global git settings for each event saw serves, unless one has
    been switched off there. Takes the saw executable and the operator config. Returns what was done."""
    actions: list[Action] = []
    for event in _HOOKS:
        name = hookscript.settings_hook(event)
        where = Path(f"hook.{name}")
        wanted = hookscript.settings_command(event, saw, config)
        try:
            command, events, enabled = _settings_hook_state(event)
        except HookError:
            actions.append(Action(NOTED, where, _NOT_IN_SETTINGS))
            continue
        if enabled == "false":
            actions.append(Action(NOTED, where, "switched off in your git settings, so it was left off"))
            continue
        if command == wanted and events == [event]:
            actions.append(Action(IN_PLACE, where, "saw's scan, run by git 2.54 and later"))
            continue
        if not (gitutil.run_ok(None, ["config", "--global", f"hook.{name}.command", wanted],
                               context=gitutil.OPERATOR_CONFIG)
                and gitutil.run_ok(None, ["config", "--global", "--replace-all", f"hook.{name}.event", event],
                                   context=gitutil.OPERATOR_CONFIG)):
            actions.append(Action(NOTED, where, _NOT_IN_SETTINGS))
            continue
        try:
            command, events, _ = _settings_hook_state(event)
        except HookError:
            command, events = None, []
        actions.append(Action(UPDATED, where, "saw's scan, run by git 2.54 and later")
                       if command == wanted and events == [event] else Action(NOTED, where, _NOT_IN_SETTINGS))
    return actions


def _settings_hooks_set() -> bool:
    """Tell whether saw's scan is set in git's settings for every event saw serves, switched on, with
    the recorded saw a runnable file and a git that runs settings hooks. Returns the answer; False when
    that could not be read."""
    recorded = hookscript.installed()
    if (recorded is None or not os.path.isfile(recorded[0]) or not os.access(recorded[0], os.X_OK)
            or not git_runs_settings_hooks()):
        return False
    try:
        for event in _HOOKS:
            command, events, enabled = _settings_hook_state(event)
            if (command != hookscript.settings_command(event, *recorded) or events != [event]
                    or enabled == "false" or _event_switched_off(event)):
                return False
    except HookError:
        return False
    return True


def _event_switched_off(event: str) -> bool:
    """Tell whether git's settings switch off every hook for an event. Takes the event. Returns the
    answer; True when it could not be read."""
    res = gitutil.run(None, ["config", "-z", "--includes", "--show-scope", "--type=bool", "--get-all",
                             f"hook.{event}.enabled"], context=gitutil.OPERATOR_CONFIG)
    if res is None or res.returncode not in (0, 1):
        return True
    fields = res.stdout.split("\0")
    values = [value for scope, value in zip(fields[0::2], fields[1::2]) if scope != "command"]
    return bool(values) and values[-1] == "false"


def why_saws_hooks_may_not_run() -> str | None:
    """Say why saw's hooks will not run, or may not. Returns the sentence, or None when nothing stands
    in their way."""
    also = " saw's scan in your git settings still runs." if _settings_hooks_set() else ""
    read, hp = _hookspath_git_uses()
    if not read:
        return "git's hooks setting could not be read, so whether saw's hooks run is NOT verified."
    if hp == "":
        return "git is set to run every repository's hooks from its top folder, so saw's hooks will not run." + also
    if hp is not None and not _is_saws_hooks_folder(hp):
        return (f"git is set to run every repository's hooks from {textsafe.plain(hp, limit=4096)}, "
                "so saw's hooks will not run." + (also or ("" if git_runs_settings_hooks() else
                                                           " Update git to 2.54 or later.")))
    template = os.environ.get("GIT_TEMPLATE_DIR")
    if template is not None and not _same_path(os.path.expanduser(template), template_dir()):
        return (f"GIT_TEMPLATE_DIR in this shell gives new clones {textsafe.plain(template, limit=4096)}, "
                "so clones made here do not get saw's hooks." + also)
    return None


_OLDER_GIT = "  update git to 2.54 or later so the repositories you already have are scanned too."


def _advise_git_update(stream) -> None:
    """Tell the operator to update git when it does not run saw's scan from its settings. Takes the
    stream to print to."""
    if not git_runs_settings_hooks():
        print(_paint(_OLDER_GIT, "warn", stream), file=stream)


def _warn_hookspath(stream) -> None:
    """Warn that saw's hooks will not run, or may not. Takes the stream to print to."""
    why = why_saws_hooks_may_not_run()
    if why is not None:
        print(_paint(f"  ⚠ {why}", "warn", stream), file=stream)


def _is_saws_hooks_folder(folder: str) -> bool:
    """Tell whether a hooks folder git is set to use is saw's own, or one saw installed its hooks
    into. Takes the folder. Returns the answer; an empty setting is never saw's."""
    for installed_into in hookscript.installed_hooks_folders() if folder else []:
        if _same_path(os.path.expanduser(folder), installed_into):
            recorded = hookscript.installed()
            return all(hookscript.verdict(installed_into / event, recorded) == hookscript.PRISTINE
                       for event in _HOOKS)
    return folder != "" and _same_path(os.path.expanduser(folder), _hooks_dir())


def _same_path(a: str | Path, b: str | Path) -> bool:
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except OSError:
        return str(a) == str(b)


IN_PLACE = "in place"
NOTED = "noted"
UPDATED = "updated"
RESTORED = "restored"
REPAIRED = "repaired"
SET_ASIDE = "set aside"
PRESERVED = "preserved"
LEFT = "left"
CHAINED = "chained"
UNVERIFIED = "could not verify"
UNREAD = "could not read"
_SETTLED = frozenset({IN_PLACE, NOTED, UPDATED, RESTORED, REPAIRED, SET_ASIDE, PRESERVED, LEFT, CHAINED})


@dataclass(frozen=True)
class Action:
    """One thing `saw hook` did, or could not do, to one path."""
    state: str
    path: Path
    detail: str = ""


def _write_verified(dest: Path, text: str, hooks_dir: Path) -> bool:
    """Write `text` to `dest` as an executable file in one step and return True only if reading it
    back gives `text`."""
    if hooks_dir.is_symlink() or not is_safe_write_target(dest, hooks_dir):
        return False
    return atomicwrite.replace(dest, text, mode=0o755) and os.access(dest, os.X_OK)


def _runnable_as_your_own(preserved: Path) -> bool:
    """Make a hook set aside as the operator's own run as it did. Takes it. Returns False when its mode
    had to change and could not."""
    try:
        if preserved.is_symlink() or os.lstat(preserved).st_mode & 0o777 == 0o755:
            return True
        atomicwrite.set_mode(preserved, 0o755)
    except OSError:
        return False
    return True


def _settle(hooks_dir: Path, saw: str, config: str | None, *, own: bool) -> list[Action]:
    """Make `hooks_dir` carry the hooks saw installs, moving aside whatever stands in their way, and
    return what was done to each path. In saw's own directory (`own`) nothing foreign stays."""
    actions: list[Action] = []
    expected = (saw, config)
    if hooks_dir.is_symlink() or hooks_dir.parent.is_symlink():
        return [Action(UNVERIFIED, hooks_dir, "is a link, so nothing was written through it")]
    if not own and _inside_what_saw_keeps(hooks_dir):
        return [Action(UNVERIFIED, hooks_dir, "lies inside what saw keeps for itself, so nothing was written")]
    atomicwrite.make_folder(hooks_dir)
    if not hooks_dir.is_dir():
        return [Action(UNVERIFIED, hooks_dir, "is not a directory")]
    if own:
        for p in sorted(hooks_dir.iterdir()):
            if p.name in _HOOKS:
                continue
            folder = hookscript.set_aside(p)
            actions.append(Action(SET_ASIDE, p, f"not a hook saw installs, kept at {folder}") if folder
                           else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    yielded: set[str] = set()
    if not own:
        for event in _HOOKS:
            dest = hooks_dir / event
            if hookscript.verdict(dest, expected) == hookscript.FOREIGN and (hooks_dir / f"{event}.local").exists():
                if event in _YIELDS_TO_THE_OPERATOR:
                    yielded.add(event)
                    continue
                raise HookError(
                    f"{hooks_dir / f'{event}.local'} already exists — refusing to overwrite a preserved "
                    "hook. Resolve it by hand, then re-run `saw hook install`.")
    for event in _HOOKS:
        dest = hooks_dir / event
        if event in yielded:
            actions.append(Action(LEFT, dest, f"your {event} and {event}.local are both here, so "
                                              "saw's check was not added"))
            continue
        wanted = _hook_script(event, saw, config)
        state = hookscript.verdict(dest, expected)
        if state == hookscript.PRISTINE:
            actions.append(Action(IN_PLACE, dest))
            continue
        outcome, detail = UPDATED, "a hook saw installs"
        if state in (hookscript.ALTERED, hookscript.STALE) or (state == hookscript.FOREIGN and own):
            folder = hookscript.set_aside(dest)
            if folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                continue
            outcome, detail = _kept(state, folder)
        elif state == hookscript.FOREIGN and dest.is_symlink() and not dest.is_file():
            folder = hookscript.set_aside(dest)
            if folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                continue
            outcome, detail = SET_ASIDE, f"a link to nothing, kept at {folder}"
        elif state == hookscript.FOREIGN:
            preserved = hooks_dir / f"{event}.local"
            try:
                atomicwrite.rename_in(hooks_dir, dest.name, preserved.name)
            except OSError:
                actions.append(Action(UNVERIFIED, dest, "could not be set aside as your own, so it was left as it is"))
                continue
            if not _runnable_as_your_own(preserved):
                try:
                    atomicwrite.rename_in(hooks_dir, preserved.name, dest.name)
                except OSError:
                    actions.append(Action(UNVERIFIED, preserved, "was set aside as your own but could not be made to run"))
                    continue
                actions.append(Action(UNVERIFIED, dest, "could not be set aside as your own, so it was left as it is"))
                continue
            actions.append(Action(PRESERVED, preserved, "your hook, now run after saw's"))
        if not _write_verified(dest, wanted, hooks_dir):
            actions.append(Action(UNVERIFIED, dest, "written but could not be read back as written"))
            continue
        actions.append(Action(outcome, dest, detail))
    return actions


def _kept(state: str, folder: Path) -> tuple[str, str]:
    """Return the outcome and detail for a hook of `state` moved aside into `folder`."""
    if state == hookscript.ALTERED:
        return REPAIRED, f"altered saw hook, kept at {folder}"
    if state == hookscript.STALE:
        return UPDATED, f"a hook saw installs naming another saw or config, or not runnable, kept at {folder}"
    return SET_ASIDE, f"not a hook saw installs, kept at {folder}"


def _print_actions(actions: list[Action], stream) -> None:
    for a in actions:
        level = "ok" if a.state in (IN_PLACE, NOTED, UPDATED, LEFT) else "warn" if a.state in (UNVERIFIED, UNREAD) else "dim"
        line = (f"  {a.state}: {textsafe.plain(str(a.path), limit=4096)}"
                + (f" — {textsafe.plain(a.detail, limit=4096)}" if a.detail else ""))
        print(_paint(line, level, stream), file=stream)


_global_template_dir = hookscript.global_template_dir


@dataclass
class Settling:
    """What settling the hooks did, for a caller that reports it in its own words."""
    actions: list = field(default_factory=list)
    target: str | None = None
    problem: str | None = None
    code: int = 0
    may_not_run: str | None = None

    @property
    def settled(self) -> bool:
        return (not self.problem and not self.may_not_run
                and all(a.state in _SETTLED for a in self.actions))

    @property
    def changed(self) -> bool:
        """Whether anything on the machine is different for having run this."""
        return any(a.state not in (IN_PLACE, NOTED) for a in self.actions)

    @property
    def repaired(self) -> bool:
        """Whether something that was not saw's hook was found in place of one, and moved aside.

        Distinct from a first install: this one means a hook was changed under the operator, which
        is a thing that happened to their machine rather than a thing this command set up.
        """
        return any(a.state in (SET_ASIDE, PRESERVED, RESTORED, REPAIRED) for a in self.actions)


def settle_hooks(config_path: str | None = None, *, repositories: list[Path] | None = None) -> Settling:
    """Put saw's hooks in place for new clones, the repositories named, every repository saw knows
    and the folder git runs every repository's hooks from when it is the operator's alone. Takes the
    operator config and the repository roots. Returns what was done."""
    saw = _saw_executable()
    config = os.path.abspath(config_path) if config_path else None
    if config and resolve_config(config_path) is None:
        return Settling(problem="the named config could not be read", code=2)

    existing = _global_template_dir()
    if existing and not os.path.isabs(existing):
        return Settling(code=2, problem=(
            f"git's template folder is set to a relative path ({textsafe.plain(existing, limit=4096)}); "
            "make it absolute, then install."))
    try:
        if existing and not _same_path(existing, template_dir()):
            actions = _settle(Path(existing) / "hooks", saw, config, own=False)
            actions += [a for a in _settle_own_only() if a.state != IN_PLACE]
            target = existing
        else:
            actions = _settle(_hooks_dir(), saw, config, own=True)
            if not gitutil.run_ok(None, ["config", "--global", "init.templateDir",
                                         str(template_dir())], context=gitutil.OPERATOR_CONFIG):
                return Settling(code=2, problem="could not set git to give new clones saw's hooks.")
            target = str(template_dir())
        actions += _settle_settings_hooks(saw, config)
        hooks_folder, folder_actions = _settle_hooks_folder(saw, config)
        actions += folder_actions
    except HookError as exc:
        return Settling(code=2, problem=str(exc))
    except OSError as exc:
        return Settling(code=3, problem=textsafe.plain(str(exc)))
    if not hookscript.declare(saw, config, Path(target) / "hooks", _hooks_folders_to_record(hooks_folder)):
        actions.append(Action(UNVERIFIED, hookscript.declaration_path(),
                              "the record of what was installed could not be written"))
    handled = [Path(target) / "hooks", _hooks_dir()]
    try:
        actions += _seed_repositories(repositories or [], saw, config, handled)
        actions += _keep_seeded_current(saw, config, handled)
    except OSError as exc:
        return Settling(code=3, problem=textsafe.plain(str(exc)))
    return Settling(actions=actions, target=target, may_not_run=why_saws_hooks_may_not_run())


def _repositories_named(patterns: list[str]) -> list[Path]:
    """Find the repositories some paths or globs name, the way `saw scan` finds them. Takes the
    patterns. Returns each repository root once."""
    from stayawake.bots.security.resolution import resolve_local_targets
    roots: list[Path] = []
    for found in resolve_local_targets(patterns, ScanOptions()):
        if os.path.lexists(found.root / ".git") and not any(_same_path(found.root, r) for r in roots):
            roots.append(found.root)
    return roots


def _seed_repositories(roots: list[Path], saw: str, config: str | None,
                       handled: list[Path]) -> list[Action]:
    """Give repositories that already exist saw's hooks. Takes the repository roots, the saw
    executable, the operator config and the hooks directories already handled, which it extends.
    Returns what was done in each."""
    actions: list[Action] = []
    for root in roots:
        hooks_dir = hookscript.repository_hooks_dir(root)
        if hooks_dir is None:
            actions.append(Action(UNREAD, root, "git could not say where this repository's hooks are"))
            continue
        if any(_same_path(hooks_dir, t) for t in handled):
            continue
        handled.append(hooks_dir)
        if hookscript.repository_redirects_hooks(root):
            actions.append(Action(LEFT, root, "its hooks path runs hooks from elsewhere, so saw's do not run here"))
        else:
            try:
                actions += _settle(hooks_dir, saw, config, own=False)
            except HookError as exc:
                actions.append(Action(UNVERIFIED, root, str(exc)))
    return actions


def install(config_path: str | None = None, *, no_stream: bool = False,
            repositories: list[str] | None = None, standing_in: bool = False) -> int:
    """Install the scan-on-clone hooks globally, give them to repositories that already exist, and
    report what happened. Takes the operator config, the paths or globs naming existing
    repositories, and whether the repository the command runs in counts when none are named.
    Returns the exit status."""
    configured = ((resolve_config(config_path) or {}).get("targets", {}) or {}).get("local", []) \
        if config_path else []
    here = _repo_root() if standing_in else None
    patterns = list(repositories or configured or ([str(here)] if here else []))
    with busy("installing scan-on-clone…", no_stream=no_stream):
        done = settle_hooks(config_path, repositories=_repositories_named(patterns))
    if done.problem is not None:
        print(f"error: {done.problem}", file=sys.stderr)
        return done.code
    config = os.path.abspath(config_path) if config_path else None
    actions, target = done.actions, done.target
    settled = done.settled

    out = _tape(no_stream)
    if settled:
        print(_paint("✓ scan-on-clone installed", "ok", out)
              + " — future `git clone` / `git pull` will be scanned automatically.", file=out)
    else:
        print(_paint("scan-on-clone is NOT fully installed — see below.", "warn", out), file=out)
    if config:
        print(f"  scanning with operator config: {config}", file=out)
    _print_actions(actions, out)
    print(_paint("  repositories you clone or create from now on get the hooks too.", "dim", out),
          file=out)
    print(_paint("  remove: saw hook uninstall", "dim", out), file=out)
    _warn_hookspath(out)
    _advise_git_update(out)
    return 0 if settled else 3


def _settle_own_only() -> list[Action]:
    """Move aside whatever is not a hook saw installs in saw's own directory, writing no hook."""
    own = _hooks_dir()
    if not own.is_dir() or own.is_symlink():
        return []
    actions: list[Action] = []
    for p in sorted(own.iterdir()):
        if p.name in _HOOKS and hookscript.verdict(p, hookscript.installed()) == hookscript.PRISTINE:
            continue
        folder = hookscript.set_aside(p)
        actions.append(Action(SET_ASIDE, p, f"not a hook saw installs, kept at {folder}") if folder
                       else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    return actions


def _installed_hooks_dirs(*, with_hooks_folders: bool = False) -> list[tuple[Path, bool]]:
    """Return the hooks directories saw installs into: its own and the operator's template directory
    the record names, and with `with_hooks_folders` every folder git runs every repository's hooks
    from that saw installed into. Each comes with whether it is saw's own."""
    dirs = [(_hooks_dir(), True)]
    recorded = hookscript.installed_into()
    if recorded is not None and not _same_path(recorded, _hooks_dir()):
        dirs.append((recorded, False))
    for folder in hookscript.installed_hooks_folders() if with_hooks_folders else []:
        if not any(_same_path(folder, d) for d, _ in dirs):
            dirs.append((folder, False))
    return dirs


def _hooks_folder_problem(folder: str) -> str | None:
    """Say why saw may not put its hooks in a folder git runs every repository's hooks from. Takes the
    folder. Returns the reason, or None when it is an absolute, real folder of the operator's that no
    one else can write and that lies outside any git working tree."""
    import stat as _stat
    path = Path(folder)
    if not path.is_absolute():
        return "is not an absolute path"
    try:
        found = os.lstat(path)
    except OSError:
        return "does not exist"
    if _stat.S_ISLNK(found.st_mode):
        return "is a link"
    if not _stat.S_ISDIR(found.st_mode):
        return "is not a folder"
    if found.st_uid != os.geteuid():
        return "is not yours"
    if found.st_mode & 0o022:
        return "can be written by others"
    if any(os.path.lexists(above / ".git") for above in (path, *path.parents)):
        return "lies inside a git working tree"
    inside = gitutil.run(path, ["rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.returncode == 0:
        return "lies inside a git repository"
    return None


def repair(*, no_stream: bool = False) -> int:
    """Put back every hook saw installs, wherever git runs it on this account, and move aside what
    was found in its place or in saw's own directory."""
    recorded = hookscript.installed()
    if recorded is None:
        if not any(d.is_dir() for d, _ in _installed_hooks_dirs()) and not hookscript.seeded_repositories():
            print("scan-on-clone has not seeded anything on this account; nothing to repair.",
                  file=_tape(no_stream))
            return 0
        print("error: saw has no record of what it installed here. Run `saw hook install` once "
              "(with -c if you used one) so it knows what to put back, then repair.", file=sys.stderr)
        return 2
    saw = recorded[0] if os.path.isfile(recorded[0]) else _saw_executable()
    config = recorded[1]
    if config and resolve_config(config) is None:
        print(f"error: the config recorded at install, {textsafe.plain(config, limit=4096)}, is gone. "
              "Run `saw hook install -c` with its new location, then repair.", file=sys.stderr)
        return 2
    template_dirs = _installed_hooks_dirs()
    actions: list[Action] = []
    seeded_by = [d for d, _ in template_dirs]
    try:
        with busy("putting the hooks back…", no_stream=no_stream):
            for d, own in template_dirs:
                if own or d.is_dir():
                    actions += _settle(d, saw, config, own=own)
            configured = _global_template_dir()
            if configured and os.path.isabs(configured) and not any(_same_path(Path(configured) / "hooks", t) for t in seeded_by):
                seeded_by.append(Path(configured) / "hooks")
                actions += _repair_repository(Path(configured) / "hooks", saw, config, restore=False)
            actions += _keep_seeded_current(saw, config, seeded_by)
            actions += _settle_settings_hooks(saw, config)
            hooks_folder, folder_actions = _settle_hooks_folder(saw, config)
            actions += folder_actions
    except HookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {textsafe.plain(str(exc))}", file=sys.stderr)
        return 3
    if not hookscript.declare(saw, config, hookscript.installed_into(), _hooks_folders_to_record(hooks_folder)):
        actions.append(Action(UNVERIFIED, hookscript.declaration_path(), "the record of what was installed could not be written"))
    out = _tape(no_stream)
    settled = all(a.state in _SETTLED for a in actions)
    print(_paint("✓ every hook saw installs is in place.", "ok", out) if settled
          else _paint("Not every hook could be put back — see below. Nothing was deleted.", "warn", out),
          file=out)
    _print_actions(actions, out)
    if any(a.state in (REPAIRED, SET_ASIDE) for a in actions):
        print(_paint(f"  moved-aside files are kept under {hookscript.set_aside_dir()}", "dim", out),
              file=out)
    return 0 if settled else 3


def _keep_seeded_current(saw: str, config: str | None, seeded_by: list[Path]) -> list[Action]:
    """Bring every repository saw's hooks have run in up to the full, current set, each hook written
    for its own event; what is not saw's stays. Takes the saw executable, the operator config and
    the hooks directories already handled, which it extends. Returns what was done."""
    actions: list[Action] = []
    for repo in hookscript.seeded_repositories():
        d = hookscript.repository_hooks_dir(repo)
        if d is None:
            actions.append(Action(UNREAD, repo, "git could not say where this repository's hooks are"))
            continue
        if any(_same_path(d, t) for t in seeded_by):
            continue
        seeded_by.append(d)
        if hookscript.repository_redirects_hooks(repo):
            actions.append(Action(LEFT, repo, "its hooks path runs hooks from elsewhere, so saw's do not run here"))
            continue
        actions += _repair_repository(d, saw, config)
    return actions


def _keep_current(root: Path) -> list[Action]:
    """Bring the repository a hook is running in up to the full, current set of saw's hooks, as
    recorded at install. Takes the repository root. Returns what changed; nothing when there is no
    record, or the repository runs its hooks from elsewhere."""
    recorded = hookscript.installed()
    if recorded is None or hookscript.repository_redirects_hooks(root):
        return []
    hooks_dir = hookscript.repository_hooks_dir(root)
    if hooks_dir is None or _inside_what_saw_keeps(hooks_dir):
        return []
    saw = recorded[0] if os.path.isfile(recorded[0]) else _saw_executable()
    return [a for a in _repair_repository(hooks_dir, saw, recorded[1])
            if a.state not in (IN_PLACE, CHAINED, LEFT)]


def _bring_up_to_date() -> None:
    """Keep the repository a hook runs in current with saw's hooks, and say so in one line when
    anything changed. Never stops the hook."""
    root = _repo_root()
    if root is None:
        return
    err = sys.stderr
    try:
        changed = _keep_current(root)
    except OSError as exc:
        print(_paint(f"{_BRAND}: could not bring this repository's hooks up to date — "
                     f"{textsafe.plain(str(exc))}", "warn", err), file=err)
        return
    failed = sorted({a.path.name for a in changed if a.state == UNVERIFIED})
    done = sorted({a.path.name for a in changed if a.state != UNVERIFIED})
    if done:
        print(_paint(f"{_BRAND}: brought this repository's hooks up to date ({', '.join(done)})",
                     "dim", err), file=err)
    if failed:
        print(_paint(f"{_BRAND}: could not bring {', '.join(failed)} up to date here; "
                     "run `saw hook repair`", "warn", err), file=err)


def _inside_what_saw_keeps(hooks_dir: Path) -> bool:
    """Return True if `hooks_dir` is, or lies under, saw's set-aside or template directory."""
    target = os.path.realpath(hooks_dir)
    for kept in (hookscript.set_aside_dir(), template_dir()):
        root = os.path.realpath(kept)
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def _repair_repository(hooks_dir: Path, saw: str, config: str | None, *, restore: bool = True) -> list[Action]:
    """Put back the hooks saw seeded into one hooks directory; what is not saw's stays. With
    `restore`, a hook of saw's that is gone is written again."""
    actions: list[Action] = []
    if (hooks_dir.is_symlink() or hooks_dir.parent.is_symlink()
            or (os.path.lexists(hooks_dir) and not hooks_dir.is_dir())):
        return [Action(UNVERIFIED, hooks_dir, "is not a directory of its own, so nothing was written")]
    if _inside_what_saw_keeps(hooks_dir):
        return [Action(UNVERIFIED, hooks_dir, "lies inside what saw keeps for itself, so nothing was written")]
    if restore:
        atomicwrite.make_folder(hooks_dir)
    elif not hooks_dir.is_dir():
        return []
    for event in _HOOKS:
        dest = hooks_dir / event
        state = hookscript.verdict(dest, (saw, config))
        if state == hookscript.PRISTINE:
            actions.append(Action(IN_PLACE, dest))
        elif state in (hookscript.ABSENT, hookscript.FOREIGN) and not restore:
            continue
        elif state in (hookscript.ALTERED, hookscript.STALE, hookscript.ABSENT):
            folder = hookscript.set_aside(dest) if state != hookscript.ABSENT else None
            if state != hookscript.ABSENT and folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
            elif _write_verified(dest, _hook_script(event, saw, config), hooks_dir):
                outcome, detail = (RESTORED, "a hook saw installs was not here") if state == hookscript.ABSENT \
                    else _kept(state, folder)
                actions.append(Action(outcome, dest, detail))
            else:
                actions.append(Action(UNVERIFIED, dest, "written but could not be read back as written"))
        elif state == hookscript.FOREIGN:
            actions.append(Action(LEFT, dest, "not a hook saw installs; this repository's own"))
        chained = hooks_dir / f"{event}.local"
        if restore and chained.exists():
            actions.append(Action(CHAINED, chained, "runs after saw's hook; not saw's, left as it is"))
    return actions


def uninstall(*, no_stream: bool = False) -> int:
    """Remove saw's hooks, restore any hook of the operator's they ran before, and stop giving new
    clones saw's hooks. Returns the exit status."""
    removed = False
    existing = _global_template_dir()
    actions: list[Action] = []
    expected = hookscript.installed()
    try:
        with busy("removing scan-on-clone…", no_stream=no_stream):
            for hooks_dir, own in _installed_hooks_dirs(with_hooks_folders=True):
                if hooks_dir.is_symlink() or not hooks_dir.is_dir():
                    continue
                for event in _HOOKS:
                    dest = hooks_dir / event
                    state = hookscript.verdict(dest, expected)
                    gone = False
                    if state == hookscript.PRISTINE:
                        dest.unlink()
                        removed = gone = True
                    elif state in (hookscript.ALTERED, hookscript.STALE):
                        folder = hookscript.set_aside(dest)
                        what = "altered saw hook" if state == hookscript.ALTERED else "a hook saw installs naming another saw or config"
                        actions.append(Action(SET_ASIDE, dest, f"{what}, kept at {folder}") if folder
                                       else Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                        removed = removed or folder is not None
                        gone = folder is not None
                    preserved = hooks_dir / f"{event}.local"
                    if os.path.lexists(preserved) and not own and gone:
                        preserved.rename(dest)          # restore the foreign hook we chained to
                if own:
                    for p in sorted(hooks_dir.iterdir()):
                        folder = hookscript.set_aside(p)
                        actions.append(Action(SET_ASIDE, p, f"not a hook saw installs, kept at {folder}") if folder
                                       else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    except OSError as exc:
        print(f"error: {textsafe.plain(str(exc))}", file=sys.stderr)
        return 3
    if existing and _same_path(existing, template_dir()):
        gitutil.run_ok(None, ["config", "--global", "--unset", "init.templateDir"],
                       context=gitutil.OPERATOR_CONFIG)
        removed = True
    for event in _HOOKS:
        name = hookscript.settings_hook(event)
        if gitutil.run_ok(None, ["config", "--global", "--remove-section", f"hook.{name}"],
                          context=gitutil.OPERATOR_CONFIG):
            removed = True
        try:
            still_set = _settings_hook_state(event)[0] is not None
        except HookError:
            still_set = True
        if still_set:
            actions.append(Action(UNVERIFIED, Path(f"hook.{name}"), "is still set in your git settings; remove it "
                                  f"with `git config --global --remove-section hook.{name}`"))
    if not any(a.state == UNVERIFIED and str(a.path).startswith("hook.saw-") for a in actions):
        hookscript.forget()
    out = _tape(no_stream)
    print(_paint("✓ scan-on-clone uninstalled.", "ok", out) if removed
          else "scan-on-clone was not installed.", file=out)
    _print_actions(actions, out)
    print(_paint("  note: repos already cloned keep the hook in their .git/hooks — remove per-repo "
                 "if wanted.", "dim", out), file=out)
    return 0 if all(a.state in _SETTLED for a in actions) else 3


def status(*, no_stream: bool = False) -> int:
    """Report whether scan-on-clone is active and where its state lives."""
    with busy("checking scan-on-clone…", no_stream=no_stream):
        existing = _global_template_dir()
        ours = existing and _same_path(existing, template_dir())
        hooks_dir = Path(existing) / "hooks" if existing else _hooks_dir()
        present = [e for e in _HOOKS if _is_ours(hooks_dir / e)]
        recorded = hookscript.installed()
        recorded_runs = hookscript.recorded_saw_runs()
        config_gone = bool(recorded and recorded[1] and resolve_config(recorded[1]) is None)
        altered = hookscript.altered_hooks()
        disabled = env.hook_disabled()
        settings_hooks_set = _settings_hooks_set()
    out = _tape(no_stream)
    if present:
        print(_paint("scan-on-clone: INSTALLED", "ok", out) + f" ({', '.join(present)})", file=out)
    else:
        print(_paint("scan-on-clone: not installed", "dim", out)
              + "  ·  enable with `saw hook install`", file=out)
    if present and settings_hooks_set:
        print(_paint("  saw's scan is also set in your git settings.", "dim", out), file=out)
    if present:
        _advise_git_update(out)
    if present and recorded is None:
        print(_paint("  saw has no record of what it installed here; run `saw hook install` once "
                     "(with -c if you used one) so `saw hook repair` knows what to put back.", "warn", out),
              file=out)
    if not recorded_runs:
        print(_paint(f"  ⚠ the saw recorded at install, {textsafe.plain(recorded[0], limit=4096)}, is gone or "
                     "cannot run; clones are not scanned until `saw hook repair` points the hooks at this "
                     "saw.", "warn", out), file=out)
    if config_gone:
        print(_paint(f"  ⚠ the config recorded at install, {textsafe.plain(recorded[1], limit=4096)}, is gone; "
                     "clones are scanned without your allowlist until `saw hook install -c` records its "
                     "new location.", "warn", out), file=out)
    if altered:
        print(_paint(f"  ⚠ {len(altered)} file(s) are not what saw installs, where saw's hooks run "
                     "— see `saw audit`; put them back with `saw hook repair`.", "warn", out), file=out)
    print(f"  hooks for new clones: {textsafe.plain(existing or '(none)', limit=4096)}"
          f"{'  (saw)' if ours else ''}", file=out)
    print(f"  hooks dir: {textsafe.plain(str(hooks_dir), limit=4096)}", file=out)
    print(f"  scan cache: {_cache_path()}", file=out)
    if disabled:
        print(_paint("  SAW_HOOK_DISABLED is set — the hook is currently a no-op.", "warn", out),
              file=out)
    _warn_hookspath(out)
    return 0


# ── the hook body: scan what just landed ────────────────────────────────────────────────

def _repo_root() -> Path | None:
    """The working-tree root git runs the hook in (`rev-parse --show-toplevel`)."""
    root = gitutil.stdout(Path.cwd(), ["rev-parse", "--show-toplevel"]).strip()
    return Path(root) if root else None


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text())
    except (OSError, ValueError):
        return {}


def _policy_digest(config_path: str | None) -> str:
    """Name the policy a hook scan judges under. Takes the operator config. Returns the digest of its
    signatures, allowlist, file size limit and the folders a walk of the tree reads or skips."""
    policy = operator_policy(config_path)
    opts = policy.opts
    digest = push_record.policy_digest(policy.signatures, policy.allowlist,
                                       getattr(opts, "max_file_bytes", 0))
    walked = json.dumps([sorted(getattr(opts, "exclude_dirs", ())), sorted(getattr(opts, "keep_dirs", ())),
                         bool(getattr(opts, "scan_build_outputs", False))])
    return f"{digest}:{hashlib.sha256(walked.encode()).hexdigest()}"


def _clean_key(head: str, config_path: str | None) -> str:
    """Name a complete clean scan of a repository's tree. Takes the commit and the operator config.
    Returns the commit joined to the digest of the policy it was judged under."""
    return f"{head}:{_policy_digest(config_path)}"


def _settings_scans() -> dict:
    """Read the clean scans a run from git's settings remembers. Returns them by repository."""
    try:
        held = json.loads(hookscript.settings_scan_path().read_text())
    except (OSError, ValueError):
        return {}
    return held if isinstance(held, dict) else {}


def _remember_settings_scan(root: Path, key: str) -> None:
    """Remember a clean scan a run from git's settings made, apart from saw's list of repositories it
    keeps current. Takes the root and the clean key. A write that fails is skipped."""
    held = {r: k for r, k in _settings_scans().items() if os.path.isdir(r)}
    held[os.path.realpath(root)] = key
    atomicwrite.replace(hookscript.settings_scan_path(), json.dumps(held))


def _remember(root: Path, key: str) -> None:
    """Record a scanned repository, and the clean scan it may skip next time. Takes the root and
    the clean key, or "" when the scan was not clean. A write that fails is skipped."""
    try:
        cache = {r: s for r, s in _load_cache().items() if os.path.isdir(r)}
        cache[os.path.realpath(root)] = key
        atomicwrite.replace(_cache_path(), json.dumps(cache), mode=atomicwrite.AS_A_PLAIN_WRITE, at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK)
    except OSError:
        pass


def _scanned_clean(root: Path, key: str) -> bool:
    """Tell whether saw remembers a complete clean scan of a repository. Takes the root and the clean
    key. Returns the answer."""
    return key in (_load_cache().get(os.path.realpath(root)), _settings_scans().get(os.path.realpath(root)))


def _scan_scope(event: str, argv: list[str], root: Path, config_path: str | None = None):
    """Decide what a hook event scans. Takes the event, its arguments, the repository root and the
    operator config. Returns `(include_only, label)`: `None` for the whole tree, a tuple of paths, or
    `(False, None)` when there is nothing to scan."""
    if event == "post-checkout":
        old, new, flag = (argv + ["", "", ""])[:3]
        if flag != "1":
            return _file_checkout_scope(root, config_path)[:2]
        if old == _NULL_REV or (_first_checkout_after_a_clone(root)
                                and not _scanned_clean(root, _clean_key(old, config_path))):
            return None, "clone"
        changed = _changed_files(root, old, new)
        if changed is None:
            return None, "checkout"
        return (changed, "checkout") if changed else (False, None)
    if event == "post-merge":
        if not gitutil.run_ok(root, ["rev-parse", "--verify", "ORIG_HEAD"]):
            return None, "pull"
        changed = _changed_files(root, "ORIG_HEAD", "HEAD")
        if changed is None:
            return None, "pull"
        return (changed, "pull") if changed else (False, None)
    if event == "post-rewrite":
        if not gitutil.run_ok(root, ["rev-parse", "--verify", "ORIG_HEAD"]):
            return False, None
        changed = _changed_files(root, "ORIG_HEAD", "HEAD")
        if changed is None:
            return None, "rewrite"
        return (changed, "rewrite") if changed else (False, None)
    return False, None


def _is_a_file_checkout(event: str, argv: list[str]) -> bool:
    """Tell whether a hook event is a file checkout rather than a branch checkout. Takes the event and
    its arguments. Returns the answer."""
    return event == "post-checkout" and (argv + ["", "", ""])[2] != "1"


def _file_checkout_scope(root: Path, config_path: str | None):
    """Decide what a file checkout scans. Takes the root and the operator config. Returns
    `(include_only, label, look, plan)`: the files on disk saw has not judged as they now are, the
    whole tree with no look when the tree could not be looked at, or `(False, None, look, plan)`
    when every file is as saw judged it."""
    now = checkout_record.look(root, operator_policy(config_path).opts)
    if now is None:
        return None, _FILES_WRITTEN, None, None
    laid_out = checkout_record.plan(root, now, checkout_record.load(root, _policy_digest(config_path)))
    if not laid_out.to_scan:
        return False, None, now, laid_out
    return laid_out.to_scan, _FILES_WRITTEN, now, laid_out


def _holds_its_commit(root: Path, head: str) -> bool:
    """Tell whether a working tree holds every file of its commit as the commit records it. Takes the
    root and the commit. Returns the answer, False when git could not say."""
    differing = uncommitted_paths(root)
    listed = stdout_bytes(root, ["ls-tree", "-r", "--name-only", "-z", head])
    if differing is None or listed is None:
        return False
    committed = set(listed.split(b"\0"))
    return not any(path in committed for path in differing)


def _first_checkout_after_a_clone(root: Path) -> bool:
    """Tell whether HEAD has moved at most once, by this checkout, since the repository was cloned.
    Takes the root. Returns the answer, False when git could not say."""
    moves = gitutil.head_moves(root, 2)
    if not moves:
        return False
    return moves[0].startswith(_HEAD_MOVED_BY_A_CLONE) or (
        len(moves) == 2 and moves[1].startswith(_HEAD_MOVED_BY_A_CLONE))


def _changed_files(root: Path, base: str, head: str) -> tuple[str, ...] | None:
    """List the repo-relative paths that changed `base..head` and still exist as regular files.
    Takes the root and the two commits. Returns them, or None when git could not list them."""
    diff = stdout_bytes(root, ["diff", "--name-only", "-z", base, head])
    if diff is None:
        return None
    names = (os.fsdecode(raw) for raw in diff.split(b"\0") if raw)
    return tuple(name for name in names if (root / name).is_file())


def _operator_scan(root: Path, include, config_path: str | None, display: str, merges=None):
    """Scan what just landed with the operator's policy: saw's signatures and the allowlist from the
    config named at install, never the repository's own config. Takes the root, the files to read or
    None for the whole tree, the operator config, the name to show and the merges the history check
    reads, None for all of them. Returns the scan result."""
    policy = operator_policy(config_path)
    with LocalRepoTarget(str(root), display, policy.opts, include_only=include) as target:
        if merges is not None:
            target.merge_scope = list(merges)
        return scan_target(target, policy.signatures, policy.allowlist)


_TIMED_OUT = object()


def _scan_within_budget(root: Path, include, config_path: str | None, display: str, merges=None):
    """Run the scan within the hook's time budget (`SAW_HOOK_TIMEOUT`). Takes what `_operator_scan`
    takes. Returns the scan result, `_TIMED_OUT` when the budget ran out, or re-raises the scan's
    error."""
    budget = env.hook_timeout()
    if budget <= 0:                                  # cap disabled → run inline
        return _operator_scan(root, include, config_path, display, merges)
    box: dict = {}

    def work():
        try:
            box["result"] = _operator_scan(root, include, config_path, display, merges)
        except BaseException as exc:                 # noqa: BLE001 — surfaced on the calling thread
            box["error"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(budget)
    if t.is_alive():
        return _TIMED_OUT
    if "error" in box:
        raise box["error"]
    return box["result"]


def _warn_infected(display: str, quoted_root: str, result) -> None:
    """Warn that freshly landed code is infected. Takes the repository as shown, the repository
    quoted for a shell command, and the scan result."""
    err = sys.stderr
    print("\n" + _paint(f"⚠  {_BRAND}: WORM DETECTED in freshly-landed code — {display}",
                        "warn", err), file=err)
    for f in result.findings[:5]:
        loc = textsafe.plain(f"{f.path}:{f.line}" if f.line else f.path)
        print("     " + _paint("•", "warn", err) + f" {f.signature_id}  —  {loc}", file=err)
    extra = len(result.findings) - 5
    if extra > 0:
        print(_paint(f"     • …and {extra} more", "dim", err), file=err)
    print(_paint(f"   Until it is cleaned, do NOT {_AVOID}.", "warn", err), file=err)
    print("   " + _paint("Inspect:", "dim", err) + " " + _cmd(f"saw scan {quoted_root}", err)
          + _paint("   ·   Remediate:", "dim", err) + " "
          + _cmd(f"saw fix --path {quoted_root}", err)
          + "\n", file=err)


def run_event(event: str, argv: list[str], config_path: str | None = None,
              *, no_stream: bool = False, from_settings: bool = False) -> int:
    """Run the check for one git hook event. Takes the event, its arguments, the operator config and
    whether git ran it from its settings. Returns 0 clean or skipped, 1 infected, 2 not verified."""
    try:
        if event == outbound.EVENT:
            if env.hook_disabled():
                return 0
            refs_text = "" if sys.stdin.isatty() else sys.stdin.read()
            if not from_settings:
                _bring_up_to_date()
            return outbound.check_push(argv, refs_text, config_path, no_stream=no_stream)
        return _run_event(event, argv, config_path, no_stream=no_stream, from_settings=from_settings)
    except BaseException:                   # noqa: BLE001 — last-resort: never break/confuse git
        print(_paint(f"⚠  {_BRAND}: the scan did not complete — NOT verified. Run `saw scan` in "
                     "this repository.", "warn", sys.stderr), file=sys.stderr)
        return 2


def _run_event(event: str, argv: list[str], config_path: str | None,
               *, no_stream: bool = False, from_settings: bool = False) -> int:
    if env.hook_disabled():
        return 0
    root = _repo_root()
    if root is None:
        return 0
    if not from_settings:
        _bring_up_to_date()
    if _is_a_file_checkout(event, argv):
        include, label, now, laid_out = _file_checkout_scope(root, config_path)
    else:
        (include, label), now, laid_out = _scan_scope(event, argv, root, config_path), None, None
    if label is None:
        if laid_out is not None:
            _record_judgements(root, now, laid_out, set(), config_path)
        return 0

    display = str(root).replace(os.path.expanduser("~"), "~")
    shown = textsafe.plain(display, limit=4096)
    quoted_root = shlex.quote(textsafe.plain(str(root), limit=4096))
    rescan = "saw scan " + quoted_root
    head = gitutil.stdout(root, ["rev-parse", "HEAD"]).strip()
    whole_tree = include is None and label != _FILES_WRITTEN
    clean_key = _clean_key(head, config_path) if head and whole_tree else None
    if clean_key and _scanned_clean(root, clean_key):
        return 0
    if whole_tree:
        now = checkout_record.look(root, operator_policy(config_path).opts)
        laid_out = checkout_record.whole_read(now) if now is not None else None

    err = sys.stderr
    with spin_status(f"{_BRAND}: scanning {shown} for supply-chain worms…",
                     enabled=stream_enabled(err, force_off=no_stream)):
        scanned = _scan_within_budget(root, include, config_path, display,
                                      [] if label == _FILES_WRITTEN else None)
    if scanned is _TIMED_OUT:
        budget = env.hook_timeout()
        print(_paint(f"⚠  {_BRAND}: scan of {shown} aborted after {budget:.0f}s (large tree) — "
                     "NOT verified.", "warn", err), file=err)
        print("   " + _paint("Scan it yourself:", "dim", err) + " " + _cmd(rescan, err),
              file=err)
        return 2
    result = scanned
    if clean_key and not from_settings:
        _remember(root, "")
    found = _tell(result, shown, rescan, quoted_root)
    if found is None:
        found = 0
        if clean_key and _holds_its_commit(root, head):
            if from_settings:
                _remember_settings_scan(root, clean_key)
            else:
                _remember(root, clean_key)
            if label == "clone":
                print(_paint(f"✓ {_BRAND}: {shown} scanned clean.", "ok", err), file=err)
    if laid_out is not None and not result.error:
        _record_judgements(root, now, laid_out, {f.path for f in result.findings}, config_path)
    return found


def _tell(result, shown: str, rescan: str, quoted_root: str) -> int | None:
    """Print what a hook scan found. Takes the result, the repository as shown, the command that
    rescans it and the repository quoted for a shell. Returns 1 infected, 2 not verified, 0 for a
    finding to review, or None when it found nothing."""
    err = sys.stderr
    if result.infected:
        _warn_infected(shown, quoted_root, result)
        return 1
    if result.error:
        print(_paint(f"⚠  {_BRAND}: {shown} could not be scanned — NOT verified "
                     f"({textsafe.plain(result.error, limit=200)}).", "warn", err), file=err)
        print("   " + _paint("Scan it yourself:", "dim", err) + " " + _cmd(rescan, err),
              file=err)
        return 2
    if result.suspicious:
        print(_paint(f"⚠  {_BRAND}: {shown} — {len(result.findings)} suspicious signal(s). "
                     f"Until you've reviewed it, do NOT {_AVOID}.", "warn", err), file=err)
        print("   " + _paint("Review:", "dim", err) + " " + _cmd(rescan, err), file=err)
        return 0
    if result.residue:
        print(_paint(f"⚠  {_BRAND}: {shown} — nothing here runs, but it holds what the project "
                     "would not carry.", "warn", err), file=err)
        print("   " + _paint("Review:", "dim", err) + " " + _cmd(rescan, err), file=err)
        return 0
    return None


def _record_judgements(root: Path, now, laid_out, flagged: set[str], config_path: str | None) -> None:
    """Record what a file checkout or a whole read judged in a working tree. Takes the root, the
    look, the plan, the paths of the findings and the operator config. A record that cannot be
    written is skipped."""
    try:
        checkout_record.remember(root, now, laid_out, flagged, _policy_digest(config_path))
    except (OSError, ValueError):
        pass

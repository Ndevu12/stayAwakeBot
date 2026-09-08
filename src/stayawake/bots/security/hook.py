#!/usr/bin/env python3
"""`saw hook` — scan a repository the moment its code lands on the machine.

Installs, removes and reports on the global git hooks, and runs the scan they trigger, so a clone or
pull is checked before anything in it is executed.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.utils import env
from stayawake.utils.config import load_yaml
from stayawake.utils import pathsafe
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.utils import textsafe
from stayawake.utils.render import LINK, SEVERITY, paint
from stayawake.utils.streaming import status as spin_status, stream_enabled
from stayawake.utils.terminal import supports_color
from stayawake.lib import git as gitutil
from stayawake.bots.security import hookscript
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.config import resolve_config
from stayawake.bots.security.service.config import _options

_MARKER = hookscript.MARKER
_HOOKS = hookscript.HOOKS
_NULL_REV = "0" * 40
_BRAND = "StayAwakeBot"
_AVOID = ("install its dependencies (`npm install` / `pip install` / `yarn` / `pnpm`), open it in "
          "your editor/IDE (auto-run tasks & extensions fire on open), or build or run it")


class HookError(Exception):
    """A refusal that must NOT proceed (e.g. clobbering a foreign hook) — surfaced to the CLI."""


_LEVELS = {"ok": SEVERITY["ok"], "warn": SEVERITY["warning"], "dim": SEVERITY["info"]}


def _paint(text: str, level: str, stream) -> str:
    """Colour `text` at a shared level (ok/warn/dim) iff the stream supports it — so a piped/CI/
    NO_COLOR run degrades to clean text, exactly like the rest of the CLI."""
    return paint(text, _LEVELS.get(level), on=supports_color(stream))


def _cmd(text: str, stream) -> str:
    """A runnable command, rendered in the shared LINK colour (bold cyan) so remediation commands
    stand out distinctly from the prose — the same treatment `saw audit`/`saw auth` give commands."""
    return paint(text, LINK, on=supports_color(stream))


# ── paths (XDG, mirroring dependencies.db / lib.github_app) ─────────────────────────────

template_dir = hookscript.template_dir
_hooks_dir = hookscript.hooks_dir
_cache_path = hookscript.cache_path


_saw_executable = hookscript.saw_executable


# ── install / uninstall / status ────────────────────────────────────────────────────────

_hook_script = hookscript.render
_is_ours = hookscript.is_ours


def _global_hookspath() -> str | None:
    """A global `core.hooksPath`, if set — it OVERRIDES every repo's `.git/hooks`, so our
    template-seeded hooks would silently never run. Detected so install/status can warn."""
    val = gitutil.stdout(None, ["config", "--global", "--get", "core.hooksPath"]).strip()
    return val or None


def _warn_hookspath(stream) -> None:
    hp = _global_hookspath()
    if hp and not _same_path(os.path.expanduser(hp), _hooks_dir()):
        print(_paint(f"  ⚠ heads-up: your global core.hooksPath ({textsafe.plain(hp, limit=4096)}) overrides per-repo "
                     ".git/hooks, so scan-on-clone's hooks WON'T run. Point that hooksPath at "
                     "saw's, or unset it.", "warn", stream))


def _same_path(a: str | Path, b: str | Path) -> bool:
    try:
        if os.path.exists(a) and os.path.exists(b):
            return os.path.samefile(a, b)
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except OSError:
        return str(a) == str(b)


IN_PLACE = "in place"
UPDATED = "updated"
RESTORED = "restored"
REPAIRED = "repaired"
QUARANTINED = "quarantined"
PRESERVED = "preserved"
LEFT = "left"
CHAINED = "chained"
UNVERIFIED = "could not verify"
UNREAD = "could not read"
_SETTLED = frozenset({IN_PLACE, UPDATED, RESTORED, REPAIRED, QUARANTINED, PRESERVED, LEFT, CHAINED})


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
    staging = None
    try:
        fd, staging = tempfile.mkstemp(prefix=".saw-", dir=hooks_dir)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            os.fchmod(fh.fileno(), 0o755)
        os.replace(staging, dest)
        staging = None
        if dest.is_symlink() or not pathsafe.is_regular_file(dest):
            return False
        return dest.read_bytes().decode("utf-8", "replace") == text and os.access(dest, os.X_OK)
    except OSError:
        return False
    finally:
        if staging is not None:
            try:
                os.unlink(staging)
            except OSError:
                pass


def _settle(hooks_dir: Path, saw: str, config: str | None, *, own: bool) -> list[Action]:
    """Make `hooks_dir` carry the hooks saw installs, moving aside whatever stands in their way, and
    return what was done to each path. In saw's own directory (`own`) nothing foreign stays."""
    actions: list[Action] = []
    expected = (saw, config)
    if hooks_dir.is_symlink() or hooks_dir.parent.is_symlink():
        return [Action(UNVERIFIED, hooks_dir, "is a link, so nothing was written through it")]
    if not own and _inside_what_saw_keeps(hooks_dir):
        return [Action(UNVERIFIED, hooks_dir, "lies inside what saw keeps for itself, so nothing was written")]
    hooks_dir.mkdir(parents=True, exist_ok=True)
    if not hooks_dir.is_dir():
        return [Action(UNVERIFIED, hooks_dir, "is not a directory")]
    if own:
        for p in sorted(hooks_dir.iterdir()):
            if p.name in _HOOKS:
                continue
            folder = hookscript.quarantine(p)
            actions.append(Action(QUARANTINED, p, f"not a hook saw installs, kept at {folder}") if folder
                           else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    if not own:
        for event in _HOOKS:
            dest = hooks_dir / event
            if hookscript.verdict(dest, expected) == hookscript.FOREIGN and (hooks_dir / f"{event}.local").exists():
                raise HookError(
                    f"{hooks_dir / f'{event}.local'} already exists — refusing to overwrite a preserved "
                    "hook. Resolve it by hand, then re-run `saw hook install`.")
    for event in _HOOKS:
        dest = hooks_dir / event
        wanted = _hook_script(event, saw, config)
        state = hookscript.verdict(dest, expected)
        if state == hookscript.PRISTINE:
            actions.append(Action(IN_PLACE, dest))
            continue
        outcome, detail = UPDATED, "a hook saw installs"
        if state in (hookscript.ALTERED, hookscript.STALE) or (state == hookscript.FOREIGN and own):
            folder = hookscript.quarantine(dest)
            if folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                continue
            outcome, detail = _kept(state, folder)
        elif state == hookscript.FOREIGN and dest.is_symlink() and not dest.is_file():
            folder = hookscript.quarantine(dest)
            if folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                continue
            outcome, detail = QUARANTINED, f"a link to nothing, kept at {folder}"
        elif state == hookscript.FOREIGN:
            preserved = hooks_dir / f"{event}.local"
            try:
                dest.rename(preserved)
                if not preserved.is_symlink():
                    os.chmod(preserved, 0o755)
            except OSError:
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
    return QUARANTINED, f"not a hook saw installs, kept at {folder}"


def _print_actions(actions: list[Action], stream) -> None:
    for a in actions:
        level = "ok" if a.state in (IN_PLACE, UPDATED, LEFT) else "warn" if a.state in (UNVERIFIED, UNREAD) else "dim"
        line = (f"  {a.state}: {textsafe.plain(str(a.path), limit=4096)}"
                + (f" — {textsafe.plain(a.detail, limit=4096)}" if a.detail else ""))
        print(_paint(line, level, stream))


_global_template_dir = hookscript.global_template_dir


@dataclass
class Settling:
    """What settling the hooks did, for a caller that reports it in its own words."""
    actions: list = field(default_factory=list)
    target: str | None = None
    problem: str | None = None
    code: int = 0

    @property
    def settled(self) -> bool:
        return not self.problem and all(a.state in _SETTLED for a in self.actions)

    @property
    def changed(self) -> bool:
        """Whether anything on the machine is different for having run this."""
        return any(a.state != IN_PLACE for a in self.actions)


def settle_hooks(config_path: str | None = None) -> Settling:
    """Put the scan-on-clone hooks in place and say what that did.

    Doing this twice changes nothing the second time: a hook already in place reads as such and is
    not rewritten. Chains into an existing `init.templateDir` rather than replacing it, because git
    holds only one.
    """
    saw = _saw_executable()
    config = os.path.abspath(config_path) if config_path else None
    if config and resolve_config(config_path) is None:
        return Settling(problem="the named config could not be read", code=2)

    existing = _global_template_dir()
    if existing and not os.path.isabs(existing):
        return Settling(code=2, problem=(
            f"git's init.templateDir is relative ({textsafe.plain(existing, limit=4096)}); "
            "make it absolute, then install."))
    try:
        if existing and not _same_path(existing, template_dir()):
            actions = _settle(Path(existing) / "hooks", saw, config, own=False)
            actions += [a for a in _settle_own_only() if a.state != IN_PLACE]
            target = existing
        else:
            actions = _settle(_hooks_dir(), saw, config, own=True)
            if not gitutil.run_ok(None, ["config", "--global", "init.templateDir",
                                         str(template_dir())]):
                return Settling(code=2, problem="could not set git's global init.templateDir.")
            target = str(template_dir())
    except HookError as exc:
        return Settling(code=2, problem=str(exc))
    except OSError as exc:
        return Settling(code=3, problem=textsafe.plain(str(exc)))
    if not hookscript.declare(saw, config, Path(target) / "hooks"):
        actions.append(Action(UNVERIFIED, hookscript.declaration_path(),
                              "the record of what was installed could not be written"))
    return Settling(actions=actions, target=target)


def install(config_path: str | None = None) -> int:
    """Install the scan-on-clone hooks globally and report what happened."""
    done = settle_hooks(config_path)
    if done.problem is not None:
        print(f"error: {done.problem}", file=sys.stderr)
        return done.code
    config = os.path.abspath(config_path) if config_path else None
    actions, target = done.actions, done.target

    out = sys.stdout
    settled = done.settled
    if settled:
        print(_paint("✓ scan-on-clone installed", "ok", out)
              + " — future `git clone` / `git pull` will be scanned automatically.")
    else:
        print(_paint("scan-on-clone is NOT fully installed — see below.", "warn", out))
    print(f"  template dir: {textsafe.plain(str(target), limit=4096)}")
    if config:
        print(f"  scanning with operator config: {config}")
    _print_actions(actions, out)
    print(_paint("  note: applies to repos cloned/created AFTER now (git init.templateDir); "
                 "existing repos are unaffected.", "dim", out))
    print(_paint("  disable for one shell: SAW_HOOK_DISABLED=1   ·   remove: saw hook uninstall",
                 "dim", out))
    _warn_hookspath(out)                     # a global core.hooksPath would silently override us
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
        folder = hookscript.quarantine(p)
        actions.append(Action(QUARANTINED, p, f"not a hook saw installs, kept at {folder}") if folder
                       else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    return actions


def _template_dirs() -> list[tuple[Path, bool]]:
    """Return the hooks directories saw installs into: its own, and the one the record names when
    that is the operator's template directory."""
    dirs = [(_hooks_dir(), True)]
    recorded = hookscript.installed_into()
    if recorded is not None and not _same_path(recorded, _hooks_dir()):
        dirs.append((recorded, False))
    return dirs


def repair() -> int:
    """Put back every hook saw installs, wherever git runs it on this account, and move aside what
    was found in its place or in saw's own directory."""
    recorded = hookscript.installed()
    if recorded is None:
        if not any(d.is_dir() for d, _ in _template_dirs()) and not hookscript.seeded_repositories():
            print("scan-on-clone has not seeded anything on this account; nothing to repair.")
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
    template_dirs = _template_dirs()
    actions: list[Action] = []
    seeded_by = [d for d, _ in template_dirs]
    try:
        for d, own in template_dirs:
            if own or d.is_dir():
                actions += _settle(d, saw, config, own=own)
        configured = _global_template_dir()
        if configured and os.path.isabs(configured) and not any(_same_path(Path(configured) / "hooks", t) for t in seeded_by):
            seeded_by.append(Path(configured) / "hooks")
            actions += _repair_repository(Path(configured) / "hooks", saw, config, restore=False)
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
    except HookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {textsafe.plain(str(exc))}", file=sys.stderr)
        return 3
    if not hookscript.declare(saw, config, hookscript.installed_into()):
        actions.append(Action(UNVERIFIED, hookscript.declaration_path(), "the record of what was installed could not be written"))
    out = sys.stdout
    settled = all(a.state in _SETTLED for a in actions)
    print(_paint("✓ every hook saw installs is in place.", "ok", out) if settled
          else _paint("Not every hook could be put back — see below. Nothing was deleted.", "warn", out))
    _print_actions(actions, out)
    if any(a.state in (REPAIRED, QUARANTINED) for a in actions):
        print(_paint(f"  moved-aside files are kept under {hookscript.quarantine_dir()}", "dim", out))
    return 0 if settled else 3


def _inside_what_saw_keeps(hooks_dir: Path) -> bool:
    """Return True if `hooks_dir` is, or lies under, saw's quarantine or template directory."""
    target = os.path.realpath(hooks_dir)
    for kept in (hookscript.quarantine_dir(), template_dir()):
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
        hooks_dir.mkdir(parents=True, exist_ok=True)
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
            folder = hookscript.quarantine(dest) if state != hookscript.ABSENT else None
            if state != hookscript.ABSENT and folder is None:
                actions.append(Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
            elif _write_verified(dest, _hook_script(event, saw, config), hooks_dir):
                outcome, detail = (RESTORED, "a hook saw seeded here was gone") if state == hookscript.ABSENT \
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


def uninstall() -> int:
    """Reverse `install`: remove our hooks (restoring any preserved `<event>.local`) and, when the
    global `init.templateDir` points at OUR managed dir, unset it. In saw's own directory an altered
    hook, and anything that is not saw's, is moved aside rather than restored."""
    removed = False
    existing = _global_template_dir()
    actions: list[Action] = []
    expected = hookscript.installed()
    try:
        for hooks_dir, own in _template_dirs():
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
                    folder = hookscript.quarantine(dest)
                    what = "altered saw hook" if state == hookscript.ALTERED else "a hook saw installs naming another saw or config"
                    actions.append(Action(QUARANTINED, dest, f"{what}, kept at {folder}") if folder
                                   else Action(UNVERIFIED, dest, "could not be moved aside, so it was left as it is"))
                    removed = removed or folder is not None
                    gone = folder is not None
                preserved = hooks_dir / f"{event}.local"
                if os.path.lexists(preserved) and not own and gone:
                    preserved.rename(dest)          # restore the foreign hook we chained to
            if own:
                for p in sorted(hooks_dir.iterdir()):
                    folder = hookscript.quarantine(p)
                    actions.append(Action(QUARANTINED, p, f"not a hook saw installs, kept at {folder}") if folder
                                   else Action(UNVERIFIED, p, "could not be moved aside, so it was left as it is"))
    except OSError as exc:
        print(f"error: {textsafe.plain(str(exc))}", file=sys.stderr)
        return 3
    if existing and _same_path(existing, template_dir()):
        gitutil.run_ok(None, ["config", "--global", "--unset", "init.templateDir"])
        removed = True
    hookscript.forget()
    out = sys.stdout
    print(_paint("✓ scan-on-clone uninstalled.", "ok", out) if removed
          else "scan-on-clone was not installed.")
    _print_actions(actions, out)
    print(_paint("  note: repos already cloned keep the hook in their .git/hooks — remove per-repo "
                 "if wanted.", "dim", out))
    return 0 if all(a.state in _SETTLED for a in actions) else 3


def status() -> int:
    """Report whether scan-on-clone is active and where its state lives."""
    existing = _global_template_dir()
    ours = existing and _same_path(existing, template_dir())
    hooks_dir = Path(existing) / "hooks" if existing else _hooks_dir()
    out = sys.stdout
    present = [e for e in _HOOKS if _is_ours(hooks_dir / e)]
    if present:
        print(_paint("scan-on-clone: INSTALLED", "ok", out) + f" ({', '.join(present)})")
    else:
        print(_paint("scan-on-clone: not installed", "dim", out)
              + "  ·  enable with `saw hook install`")
    recorded = hookscript.installed()
    if present and recorded is None:
        print(_paint("  saw has no record of what it installed here; run `saw hook install` once "
                     "(with -c if you used one) so `saw hook repair` knows what to put back.", "warn", out))
    if not hookscript.recorded_saw_runs():
        print(_paint(f"  ⚠ the saw recorded at install, {textsafe.plain(recorded[0], limit=4096)}, is gone or "
                     "cannot run; clones are not scanned until `saw hook repair` points the hooks at this "
                     "saw.", "warn", out))
    if recorded and recorded[1] and resolve_config(recorded[1]) is None:
        print(_paint(f"  ⚠ the config recorded at install, {textsafe.plain(recorded[1], limit=4096)}, is gone; "
                     "clones are scanned without your allowlist until `saw hook install -c` records its "
                     "new location.", "warn", out))
    altered = hookscript.altered_hooks()
    if altered:
        print(_paint(f"  ⚠ {len(altered)} file(s) are not what saw installs, where saw's hooks run "
                     "— see `saw audit`; put them back with `saw hook repair`.", "warn", out))
    print(f"  init.templateDir: {textsafe.plain(existing or '(unset)', limit=4096)}{'  (saw-managed)' if ours else ''}")
    print(f"  hooks dir: {textsafe.plain(str(hooks_dir), limit=4096)}")
    print(f"  scan cache: {_cache_path()}")
    if env.hook_disabled():
        print(_paint("  SAW_HOOK_DISABLED is set — the hook is currently a no-op.", "warn", out))
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


def _remember(root: Path, sha: str) -> None:
    """Record the scanned SHA (best-effort — a cache write must never break the hook)."""
    try:
        cache = {r: s for r, s in _load_cache().items() if os.path.isdir(r)}
        cache[os.path.realpath(root)] = sha
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache))
    except OSError:
        pass


def _scan_scope(event: str, argv: list[str], root: Path):
    """Decide what to scan for this event, as `(include_only, label)`:
      * `(None, label)`  → full-tree scan (a fresh clone / a pull with no ORIG_HEAD),
      * `(tuple, label)` → scan only those changed files — a pull or branch switch,
      * `(False, None)`  → skip (a file checkout, or nothing changed). The caller skips on label None."""
    if event == "post-checkout":
        old, new, flag = (argv + ["", "", ""])[:3]
        if flag != "1":                     # a FILE checkout (`git checkout -- path`), not a ref move
            return False, None
        if old == _NULL_REV:                # a fresh clone → everything is new
            return None, "clone"
        changed = _changed_files(root, old, new)
        return (changed, "checkout") if changed else (False, None)
    if event == "post-merge":               # a pull/merge → scan only what the merge brought in
        if not gitutil.run_ok(root, ["rev-parse", "--verify", "ORIG_HEAD"]):
            return None, "pull"             # no ORIG_HEAD (rare) → fall back to a full scan
        changed = _changed_files(root, "ORIG_HEAD", "HEAD")
        return (changed, "pull") if changed else (False, None)
    if event == "post-rewrite":             # a rebase (incl `git pull --rebase`) or `commit --amend`
        # Rebase sets ORIG_HEAD to the pre-rewrite HEAD, so ORIG_HEAD..HEAD is exactly the code now
        # in the tree (the replayed upstream commits). No ORIG_HEAD (some amends) → skip rather than
        # full-scan on every amend. We read ORIG_HEAD, not the rewritten-pairs stdin (`</dev/null`).
        if not gitutil.run_ok(root, ["rev-parse", "--verify", "ORIG_HEAD"]):
            return False, None
        changed = _changed_files(root, "ORIG_HEAD", "HEAD")
        return (changed, "rewrite") if changed else (False, None)
    return False, None


def _changed_files(root: Path, base: str, head: str) -> tuple[str, ...]:
    """Repo-relative paths that changed `base..head` and still exist as regular files."""
    diff = gitutil.stdout(root, ["diff", "--name-only", base, head])
    return tuple(f for f in diff.splitlines() if f and (root / f).is_file())


def _operator_scan(root: Path, include, config_path: str | None, display: str):
    """Scan the just-landed tree with the OPERATOR's policy — packaged signatures + the operator's
    allowlist (from an explicit `--config` baked in at install), NEVER the cloned repo's own config."""
    cfg = load_yaml(config_path) if (config_path and Path(config_path).is_file()) else {}
    settings = cfg.get("settings", {}) if isinstance(cfg, dict) else {}
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = (cfg.get("allowlist") if isinstance(cfg, dict) else None) or []
    with LocalRepoTarget(str(root), display, opts, include_only=include) as target:
        return scan_target(target, sigs, allowlist)


_TIMED_OUT = object()


def _scan_within_budget(root: Path, include, config_path: str | None, display: str):
    """Run the scan under `SAW_HOOK_TIMEOUT` (default 60s) so a giant clone can NEVER hang git.
    Returns the ScanResult, `_TIMED_OUT` if the budget elapsed, or re-raises a scan exception. The
    scan runs in a daemon thread; on timeout we abandon it (it dies with the hook process) and the
    caller reports the tree as UNVERIFIED — never as clean."""
    budget = env.hook_timeout()
    if budget <= 0:                                  # cap disabled → run inline
        return _operator_scan(root, include, config_path, display)
    box: dict = {}

    def work():
        try:
            box["result"] = _operator_scan(root, include, config_path, display)
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


def _warn_infected(display: str, result) -> None:
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
    print("   " + _paint("Inspect:", "dim", err) + " " + _cmd(f"saw scan {display}", err)
          + _paint("   ·   Remediate:", "dim", err) + " " + _cmd(f"saw fix --path {display}", err)
          + "\n", file=err)


def run_event(event: str, argv: list[str], config_path: str | None = None) -> int:
    """Invoked BY the installed git hook. Scan what just landed and warn. Returns 0 clean/skipped,
    1 infected, 2 scan-error/unverified — but the hook wrapper forces exit 0 so git is never broken.
    The ENTIRE body is guarded: a hook must never emit a traceback mid-clone."""
    try:
        return _run_event(event, argv, config_path)
    except BaseException as exc:            # noqa: BLE001 — last-resort: never break/confuse git
        print(_paint(f"{_BRAND}: scan-on-clone error — {exc}", "warn", sys.stderr), file=sys.stderr)
        return 2


def _run_event(event: str, argv: list[str], config_path: str | None) -> int:
    if env.hook_disabled():
        return 0
    root = _repo_root()
    if root is None:
        return 0
    include, label = _scan_scope(event, argv, root)
    if label is None:                       # nothing worth scanning for this event
        return 0

    display = str(root).replace(os.path.expanduser("~"), "~")
    head = gitutil.stdout(root, ["rev-parse", "HEAD"]).strip()
    if head and include is None and _load_cache().get(os.path.realpath(root)) == head:
        return 0                            # already scanned this exact full tree

    err = sys.stderr
    # A live spinner on stderr while we scan, so a `git clone` never LOOKS stuck (the scan can take a
    # moment on a big tree). Transient — it clears before the verdict; a no-op when piped / CI.
    with spin_status(f"{_BRAND}: scanning {display} for supply-chain worms…",
                     enabled=stream_enabled(err)):
        scanned = _scan_within_budget(root, include, config_path, display)
    if scanned is _TIMED_OUT:
        budget = env.hook_timeout()
        print(_paint(f"⚠  {_BRAND}: scan of {display} aborted after {budget:.0f}s (large tree) — "
                     "NOT verified.", "warn", err), file=err)
        print("   " + _paint("Scan it yourself:", "dim", err) + " " + _cmd(f"saw scan {display}", err),
              file=err)
        return 2
    result = scanned

    if head and include is None:            # only a full-tree scan is safe to cache by HEAD
        _remember(root, head)
    if result.error:
        print(_paint(f"{_BRAND}: scan-on-clone hit an error scanning {display} — "
                     f"{textsafe.plain(result.error)}",
                     "warn", err), file=err)
        return 2
    if result.infected:
        _warn_infected(display, result)
        return 1
    if result.suspicious:
        print(_paint(f"⚠  {_BRAND}: {display} — {len(result.findings)} suspicious signal(s). "
                     f"Until you've reviewed it, do NOT {_AVOID}.", "warn", err), file=err)
        print("   " + _paint("Review:", "dim", err) + " " + _cmd(f"saw scan {display}", err), file=err)
        return 0
    if label == "clone":                    # a fresh clone: confirm it's clean (a pull stays quiet)
        print(_paint(f"✓ {_BRAND}: {display} scanned clean.", "ok", err), file=err)
    return 0

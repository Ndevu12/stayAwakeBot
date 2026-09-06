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
import threading
from pathlib import Path

from stayawake.utils import env
from stayawake.utils.config import load_yaml
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


def _saw_executable() -> str:
    """Absolute path to the `saw` CLI, baked into the hook script so it works when the hook runs
    outside an activated venv / with a bare PATH."""
    return shutil.which("saw") or os.path.realpath(sys.argv[0])


# ── install / uninstall / status ────────────────────────────────────────────────────────

_hook_script = hookscript.render
_is_ours = hookscript.is_ours


def _write_hooks(hooks_dir: Path, saw: str, config: str | None) -> None:
    """Write our `post-checkout`/`post-merge` into `hooks_dir`, never clobbering a foreign hook —
    a pre-existing non-saw hook is preserved as `<event>.local` (which our script then chains to).

    Pre-flighted: if ANY event can't be installed safely we raise BEFORE writing anything, so a
    failed install never leaves one hook rewritten and the other untouched (all-or-nothing)."""
    hooks_dir.mkdir(parents=True, exist_ok=True)
    for event in _HOOKS:                                     # pre-flight: refuse conflicts up front
        dest = hooks_dir / event
        if dest.exists() and not _is_ours(dest) and (hooks_dir / f"{event}.local").exists():
            raise HookError(
                f"{hooks_dir / f'{event}.local'} already exists — refusing to overwrite a preserved "
                "hook. Resolve it by hand, then re-run `saw hook install`.")
    for event in _HOOKS:                                     # then commit the writes
        dest = hooks_dir / event
        if dest.exists() and not _is_ours(dest):
            preserved = hooks_dir / f"{event}.local"
            dest.rename(preserved)
            os.chmod(preserved, 0o755)
        if not is_safe_write_target(dest, hooks_dir):        # never write THROUGH a symlink
            raise HookError(f"refusing to write {dest} — it is a symlink or escapes {hooks_dir}")
        dest.write_text(_hook_script(event, saw, config), encoding="utf-8")
        os.chmod(dest, 0o755)


_global_template_dir = hookscript.global_template_dir


def _global_hookspath() -> str | None:
    """A global `core.hooksPath`, if set — it OVERRIDES every repo's `.git/hooks`, so our
    template-seeded hooks would silently never run. Detected so install/status can warn."""
    val = gitutil.stdout(None, ["config", "--global", "--get", "core.hooksPath"]).strip()
    return val or None


def _warn_hookspath(stream) -> None:
    hp = _global_hookspath()
    if hp:
        print(_paint(f"  ⚠ heads-up: your global core.hooksPath ({hp}) overrides per-repo "
                     ".git/hooks, so scan-on-clone's hooks WON'T run. Point that hooksPath at "
                     "saw's, or unset it.", "warn", stream))


def _same_path(a: str | Path, b: str | Path) -> bool:
    try:
        return os.path.realpath(str(a)) == os.path.realpath(str(b))
    except OSError:
        return str(a) == str(b)


def install(config_path: str | None = None) -> int:
    """Install the scan-on-clone hooks globally. If the operator already has an `init.templateDir`,
    chain our hooks INTO it (we can't set two); otherwise point `init.templateDir` at ours."""
    saw = _saw_executable()
    config = os.path.abspath(config_path) if config_path else None
    if config and resolve_config(config_path) is None:
        return 2

    existing = _global_template_dir()
    try:
        if existing and not _same_path(existing, template_dir()):
            # The operator owns a template dir already — coexist by writing our hooks into it.
            _write_hooks(Path(existing) / "hooks", saw, config)
            target = existing
        else:
            _write_hooks(_hooks_dir(), saw, config)
            if not gitutil.run_ok(None, ["config", "--global", "init.templateDir",
                                         str(template_dir())]):
                print("error: could not set git's global init.templateDir.", file=sys.stderr)
                return 2
            target = str(template_dir())
    except HookError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = sys.stdout
    print(_paint("✓ scan-on-clone installed", "ok", out)
          + " — future `git clone` / `git pull` will be scanned automatically.")
    print(f"  template dir: {target}")
    if config:
        print(f"  scanning with operator config: {config}")
    print(_paint("  note: applies to repos cloned/created AFTER now (git init.templateDir); "
                 "existing repos are unaffected.", "dim", out))
    print(_paint("  disable for one shell: SAW_HOOK_DISABLED=1   ·   remove: saw hook uninstall",
                 "dim", out))
    _warn_hookspath(out)                     # a global core.hooksPath would silently override us
    return 0


def uninstall() -> int:
    """Reverse `install`: remove our hooks (restoring any preserved `<event>.local`) and, when the
    global `init.templateDir` points at OUR managed dir, unset it."""
    removed = False
    existing = _global_template_dir()
    dirs = {_hooks_dir()}
    if existing:
        dirs.add(Path(existing) / "hooks")
    for hooks_dir in dirs:
        for event in _HOOKS:
            dest = hooks_dir / event
            if dest.exists() and _is_ours(dest):
                dest.unlink()
                removed = True
                preserved = hooks_dir / f"{event}.local"
                if preserved.exists():
                    preserved.rename(dest)          # restore the foreign hook we chained to
    if existing and _same_path(existing, template_dir()):
        gitutil.run_ok(None, ["config", "--global", "--unset", "init.templateDir"])
        removed = True
    out = sys.stdout
    print(_paint("✓ scan-on-clone uninstalled.", "ok", out) if removed
          else "scan-on-clone was not installed.")
    print(_paint("  note: repos already cloned keep the hook in their .git/hooks — remove per-repo "
                 "if wanted.", "dim", out))
    return 0


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
    print(f"  init.templateDir: {existing or '(unset)'}{'  (saw-managed)' if ours else ''}")
    print(f"  hooks dir: {hooks_dir}")
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

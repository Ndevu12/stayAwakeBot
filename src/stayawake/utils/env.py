#!/usr/bin/env python3
"""The one place stayawake reads the process environment."""
from __future__ import annotations

import os

GH_SECURITY_TOKEN = "GH_SECURITY_TOKEN"
GITHUB_TOKEN = "GITHUB_TOKEN"
GITHUB_REPOSITORY = "GITHUB_REPOSITORY"
SLACK_WEBHOOK_URL = "SLACK_WEBHOOK_URL"
STAYAWAKE_REPORTS_DIR = "STAYAWAKE_REPORTS_DIR"
SAW_ADVISORY_CACHE_DIR = "SAW_ADVISORY_CACHE_DIR"
XDG_CACHE_HOME = "XDG_CACHE_HOME"
XDG_CONFIG_HOME = "XDG_CONFIG_HOME"
XDG_STATE_HOME = "XDG_STATE_HOME"
SAW_AUTORUN_BASELINE = "SAW_AUTORUN_BASELINE"
SAW_HOOK_DISABLED = "SAW_HOOK_DISABLED"
SAW_HOOK_TIMEOUT = "SAW_HOOK_TIMEOUT"
NO_COLOR = "NO_COLOR"
CLICOLOR_FORCE = "CLICOLOR_FORCE"
CI = "CI"
GITHUB_ACTIONS = "GITHUB_ACTIONS"
GITLAB_CI = "GITLAB_CI"
CIRCLECI = "CIRCLECI"
BUILDKITE = "BUILDKITE"
RUNNER_OS = "RUNNER_OS"
_RUNNER_MARKERS = (GITHUB_ACTIONS, GITLAB_CI, CIRCLECI, BUILDKITE, RUNNER_OS)
TERM = "TERM"
COLORTERM = "COLORTERM"
PAGER = "PAGER"
NO_STREAM = ("STAYAWAKE_NO_STREAM", "NO_STREAM")


def get(name: str, default: str | None = None) -> str | None:
    """Read one variable — the ONLY place `os.environ` is touched for app config. Strips
    surrounding whitespace and treats an empty/whitespace value as unset (→ `default`)."""
    val = os.environ.get(name)
    if val is None:
        return default
    val = val.strip()
    return val or default


def any_set(names) -> bool:
    """True when any of `names` holds a non-empty value (e.g. the NO_STREAM group)."""
    return any(get(n) for n in names)


def is_ephemeral_runner() -> bool:
    """True only when the host is clearly an EPHEMERAL CI runner. FAILS TOWARD WORKSTATION (False) when
    ambiguous or absent: the CI signal is attacker-forgeable, so it may only ever ADD runner
    context to an impact finding — never soften its severity/verdict/exit. Requires a runner-specific
    marker AND the absence of a persistent home, so container-on-a-workstation (real `$HOME`/SSH mounted
    through) stays 'workstation'."""
    return any_set(_RUNNER_MARKERS) and not _has_persistent_home()


def _has_persistent_home() -> bool:
    """A real workstation home carries private SSH keys an ephemeral runner image does not — the safe
    direction: a runner can't fake real keys, and if it somehow did the only effect is dropping a note.
    Lists names only, never reads key bytes."""
    from pathlib import Path
    home = get("HOME") or os.path.expanduser("~")
    try:
        return any(p.name.startswith("id_") and not p.name.endswith(".pub")
                   for p in (Path(home) / ".ssh").iterdir())
    except OSError:
        return False


# ── GitHub / Slack context (reused across the alerters + the remediator) ───────────────
def github_token() -> str | None:
    return get(GITHUB_TOKEN)


def github_repository() -> str | None:
    return get(GITHUB_REPOSITORY)


def github_slug() -> tuple[str, str] | None:
    """`(owner, name)` parsed from `GITHUB_REPOSITORY`, or None when unset or malformed — the
    single home for the `owner, name = repo.split('/', 1)` split several callers duplicated."""
    repo = github_repository()
    if repo and "/" in repo:
        owner, name = repo.split("/", 1)
        if owner and name:
            return owner, name
    return None


def slack_webhook() -> str | None:
    return get(SLACK_WEBHOOK_URL)


# ── behaviour toggles ──────────────────────────────────────────────────────────────────
def _truthy(value: str | None) -> bool:
    """A conventional on/off flag: on unless empty or an explicit off word (0/false/no/off)."""
    return (value or "").lower() not in ("", "0", "false", "no", "off")


def no_color() -> bool:
    """The NO_COLOR convention: any non-empty value disables colour output."""
    return bool(get(NO_COLOR))


def clicolor_force() -> bool:
    """CLICOLOR_FORCE: force colour on even when the stream is not a TTY (0/false/no/off = off)."""
    return _truthy(get(CLICOLOR_FORCE))


def is_ci() -> bool:
    """Running under a CI runner — suppress colour so captured logs stay plain text."""
    return _truthy(get(CI))


def stream_disabled() -> bool:
    """Live streaming is off when any NO_STREAM variable is set."""
    return any_set(NO_STREAM)


def hook_disabled() -> bool:
    """The scan-on-clone git hook is a no-op when SAW_HOOK_DISABLED is set to a truthy value —
    a per-shell kill-switch (e.g. bulk-cloning) that doesn't require `saw hook uninstall`."""
    return _truthy(get(SAW_HOOK_DISABLED))


def hook_timeout() -> float:
    """Wall-clock budget (seconds) for one scan-on-clone scan, so a giant clone can never hang git.
    `SAW_HOOK_TIMEOUT` overrides the 60s default; `0`/negative/invalid means no cap."""
    raw = get(SAW_HOOK_TIMEOUT)
    if raw is None:
        return 60.0
    try:
        val = float(raw)
    except ValueError:
        return 60.0
    return val if val > 0 else 0.0


def xdg_config_home() -> str:
    """`$XDG_CONFIG_HOME`, else `~/.config` (the XDG default) — base for saw's git-template dir."""
    return get(XDG_CONFIG_HOME) or os.path.join(os.path.expanduser("~"), ".config")


def xdg_cache_home() -> str:
    """`$XDG_CACHE_HOME`, else `~/.cache` (the XDG default) — base for saw's hook scan cache."""
    return get(XDG_CACHE_HOME) or os.path.join(os.path.expanduser("~"), ".cache")


def xdg_state_home() -> str:
    """`$XDG_STATE_HOME`, else `~/.local/state` (the XDG default) — base for saw's cross-run state
    (the autorun baseline). State, not cache: losing it degrades gracefully but it is meant
    to persist longitudinally on a workstation."""
    return get(XDG_STATE_HOME) or os.path.join(os.path.expanduser("~"), ".local", "state")


def autorun_baseline_path() -> str | None:
    """Explicit override for the autorun baseline file (`SAW_AUTORUN_BASELINE`), else None → the
    caller composes the default under `xdg_state_home()`."""
    return get(SAW_AUTORUN_BASELINE)

#!/usr/bin/env python3
"""Remediator service — `saw fix` and `saw discard`.

`saw fix` (default) PREPARES the fix on a local `security/auto-clean` branch and stops —
no push, no PR, no network — leaving the branch for the user to review and push. `saw fix
--pr` additionally pushes and opens/updates one rolling PR per repo; `saw fix --remote`
sweeps the configured GitHub targets (clone → fix → PR). `saw discard` is the inverse:
`--branch` deletes the auto-clean branch (local + remote, git only), `--pr` closes its PR.

Scope is LOCAL by default; `--remote` targets the configured GitHub repositories. Anything
that touches the GitHub API (publish/remote, `discard --pr`) is PRE-FLIGHTED once — a broken
env (e.g. SSL) or bad token fails fast instead of force-pushing branches. Each repo's outcome
streams live, and one repo's failure never aborts the run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core import auth
from stayawake.core import git as gitutil
from stayawake.core.adapters import github_api
from stayawake.core.streaming import Streamer, stream_enabled, status
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.service import (
    discover_local_repos, _enclosing_repo_root, _resolve_remote, DEFAULT_CONFIG)
from stayawake.bots.security.targets import ScanOptions
from stayawake.bots.security import pr as pr_submit


def _options(settings: dict) -> ScanOptions:
    base = ScanOptions()
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", base.exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
    )


def _resolve_config(config_path: str | None):
    """Load the config without ever crashing on a missing file (#1054). None → the packaged
    default if it exists, else an empty config — so `saw fix`/`saw discard` work on the
    current repo with no config. An explicit --config that is missing is a clear error."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it "
              "to act on the current repository.", file=sys.stderr)
        return None
    return load_yaml(config_path)


def _safe(fn, display: str) -> str:
    """Run one repo's operation, never raising — one repo's failure must not abort the run."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — isolate a single repo, keep the run going
        return f"{display}: error — {exc}"


def _preflight(token: str | None) -> str | None:
    """Verify the GitHub API is reachable AND the token is valid BEFORE any push/close, so a
    broken env (e.g. SSL) or bad token fails fast instead of force-pushing branches to every
    repo. Returns an error message, or None when good to go."""
    if not token:
        return (auth.no_credential_hint("opening pull requests")
                + " A token with repo + pull-request write scope is required.")
    if github_api.get_authenticated_user(token) is None:
        return ("GitHub API unreachable or token rejected — nothing pushed. Check connectivity "
                "and token scope; on macOS a missing CA bundle causes this (the `certifi` "
                "dependency fixes it; reinstall if needed).")
    return None


def _local_repos(cfg: dict, opts: ScanOptions, paths) -> list[Path]:
    cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
    patterns = list(paths) if paths else (list(cfg_local) or [str(_enclosing_repo_root())])
    return discover_local_repos(patterns, opts)


def _disp(repo: Path) -> str:
    return str(repo).replace(os.path.expanduser("~"), "~")


# ── saw fix ──────────────────────────────────────────────────────────────────────

def _fix_local(cfg, opts, sigs, allowlist, paths, prog: Streamer, *, publish: bool) -> list[str]:
    """Fix LOCAL repositories. Default: PREPARE a `security/auto-clean` branch per repo (no
    push, no network). `publish` (`--pr`): also push + open/update a PR (pre-flighted)."""
    token = None
    if publish:
        token, _ = auth.resolve_token()
        err = _preflight(token)
        if err:
            prog.line(err)
            return []
    repos = _local_repos(cfg, opts, paths)
    if not repos:
        return []
    verb = "Opening PRs for" if publish else "Preparing fixes for"
    prog.line(f"{verb} {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, repo in enumerate(repos, 1):
        display = _disp(repo)
        prog.line(f"  [{i}/{len(repos)}] {display}")
        # No wrapping spinner here — pr.{prepare_fix,submit_fix_pr} drive their OWN
        # phase-accurate spinners (scanning → fixing → opening PR), so the label always
        # reflects what's actually happening.
        outcome = _safe(
            (lambda r=repo: pr_submit.submit_fix_pr(r, opts, sigs, allowlist, token, spin=prog.enabled))
            if publish else
            (lambda r=repo: pr_submit.prepare_fix(r, opts, sigs, allowlist, spin=prog.enabled)), display)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def _fix_remote(cfg, opts, sigs, allowlist, prog: Streamer) -> list[str]:
    """Fix REMOTE repositories: clone each configured GitHub target and open/update its PR
    (no local copy exists, so a PR is the only output). Unchanged from the original sweep."""
    slugs, token, _source = _resolve_remote(cfg, opts)
    err = _preflight(token)
    if err:
        prog.line(err)
        return []
    if not slugs:
        prog.line("No GitHub targets configured (targets.github.users/orgs or a GitHub App install).")
        return []
    prog.line(f"Sweeping {len(slugs)} GitHub repositor{'y' if len(slugs) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, slug in enumerate(slugs, 1):
        prog.line(f"  [{i}/{len(slugs)}] {slug}")
        tmp = Path(tempfile.mkdtemp(prefix="sab-fix-"))
        clone = tmp / "repo"
        try:
            with status(f"cloning {slug}…", enabled=prog.enabled):   # phase 0: clone only
                with gitutil.github_https_auth(token) as (prefix, env):
                    r = subprocess.run(["git", "clone", "--quiet", "--depth", "50",
                                        f"{prefix}{slug}.git", str(clone)],
                                       capture_output=True, text=True, check=False, env=env)
            # submit_fix_pr then drives its own scanning → fixing → opening-PR spinners.
            outcome = (f"{slug}: clone failed (check token access)" if r.returncode != 0
                       else _safe(lambda: pr_submit.submit_fix_pr(clone, opts, sigs, allowlist,
                                                                  token, spin=prog.enabled), slug))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def fix(config_path: str | None = None, *, pr: bool = False, remote: bool = False,
        paths: list[str] | None = None, no_stream: bool = False) -> int:
    """`saw fix`: prepare a `security/auto-clean` branch per infected repo (no push). With
    `pr=True` (`--pr`) also push + open/update one rolling PR each; with `remote=True`
    (`--remote`) sweep the configured GitHub targets. Streams each repo's outcome. Returns 2
    if an explicit --config is missing, 1 if any repo needs manual review, else 0."""
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)

    outcomes = (_fix_remote(cfg, opts, sigs, allowlist, prog) if remote
                else _fix_local(cfg, opts, sigs, allowlist, paths, prog, publish=pr))
    if not outcomes:
        prog.line("No repositories to fix.")
        return 0
    needs_review = sum(1 for o in outcomes if "ABORTED" in o or ": error" in o)
    n = len(outcomes)
    plural = "y" if n == 1 else "ies"
    prog.line(f"\nProcessed {n} repositor{plural}"
              + (f"; {needs_review} need manual review." if needs_review else "."))
    return 1 if needs_review else 0


# ── saw discard ──────────────────────────────────────────────────────────────────

def _discard_local(cfg, opts, branch: bool, pr: bool, paths, prog: Streamer) -> list[str]:
    token = None
    if pr:
        token, _ = auth.resolve_token()
        err = _preflight(token)
        if err:
            prog.line(err)
            if not branch:
                return []
            pr = False   # can't close PRs, but --branch (pure git) can still run
    repos = _local_repos(cfg, opts, paths)
    if not repos:
        return []
    prog.line(f"Discarding in {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, repo in enumerate(repos, 1):
        display = _disp(repo)
        prog.line(f"  [{i}/{len(repos)}] {display}")
        parts: list[str] = []
        with status(f"discarding in {display}…", enabled=prog.enabled):
            if branch:
                parts.append(_safe(lambda r=repo: pr_submit.discard_branch(r), display))
            if pr:
                parts.append(_safe(lambda r=repo: pr_submit.discard_pr(r, token), display))
        outcome = "  ·  ".join(parts)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def _discard_remote(cfg, opts, branch: bool, pr: bool, prog: Streamer) -> list[str]:
    slugs, token, _source = _resolve_remote(cfg, opts)
    err = _preflight(token)
    if err:
        prog.line(err)
        return []
    if not slugs:
        prog.line("No GitHub targets configured (targets.github.users/orgs or a GitHub App install).")
        return []
    prog.line(f"Discarding across {len(slugs)} GitHub repositor{'y' if len(slugs) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, slug in enumerate(slugs, 1):
        prog.line(f"  [{i}/{len(slugs)}] {slug}")
        parts: list[str] = []
        with status(f"discarding {slug}…", enabled=prog.enabled):
            if branch:
                parts.append(_safe(lambda s=slug: pr_submit.discard_remote_branch(s, token), slug))
            if pr:
                parts.append(_safe(lambda s=slug: pr_submit.discard_remote_pr(s, token), slug))
        outcome = "  ·  ".join(parts)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def discard(config_path: str | None = None, *, branch: bool = False, pr: bool = False,
            remote: bool = False, paths: list[str] | None = None, no_stream: bool = False) -> int:
    """`saw discard`: remove what `fix` produced — the `security/auto-clean` branch
    (`--branch`: local + remote, pure git, SSL-immune) and/or its PR (`--pr`: API). LOCAL by
    default; `--remote` sweeps the configured GitHub targets. Requires at least one of
    `--branch`/`--pr`. Returns 2 on a usage/config error, else 0."""
    if not (branch or pr):
        print("Nothing to discard: pass --branch (delete the fix branch) and/or --pr "
              "(close the fix PR).", file=sys.stderr)
        return 2
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    opts = _options(cfg.get("settings", {}))
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)

    outcomes = (_discard_remote(cfg, opts, branch, pr, prog) if remote
                else _discard_local(cfg, opts, branch, pr, paths, prog))
    if not outcomes:
        prog.line("No repositories to discard.")
        return 0
    n = len(outcomes)
    prog.line(f"\nProcessed {n} repositor{'y' if n == 1 else 'ies'}.")
    return 0

#!/usr/bin/env python3
"""Remediator service — `saw fix`.

Remediation is delivered as a PULL REQUEST, never an in-place edit: for each INFECTED
repository, `fix()` opens (or updates) one rolling `security/auto-clean` PR via
`pr.submit_fix_pr`. The PR is the review gate, so there is no separate apply/preview step —
opening the proposal IS the action, and nothing reaches a default branch until a human
merges it. Scope is LOCAL by default (current repo / configured globs / explicit paths);
`--remote` targets the configured GitHub repositories instead. Each repo's outcome streams
live, and one repo's failure never aborts the run.
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
    """Load the remediation config without ever crashing on a missing file (#1054).
    None → the packaged default if it exists, else an empty config — so `saw fix` works on
    the current repo with no config, mirroring `saw scan`. An explicitly-passed --config
    that is missing prints a clear, actionable error and returns None (the caller exits
    non-zero) instead of a raw FileNotFoundError."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it "
              "to fix the current repository.", file=sys.stderr)
        return None
    return load_yaml(config_path)


def _safe_pr(repo: Path, display: str, opts, sigs, allowlist, token) -> str:
    """Open/update one repo's rolling fix PR, never raising — one repo's failure (an
    unreadable history, a transient git/API error) must not abort the whole run."""
    try:
        return pr_submit.submit_fix_pr(repo, opts, sigs, allowlist, token)
    except Exception as exc:  # noqa: BLE001 — isolate a single repo, keep the sweep going
        return f"{display}: error — could not fix ({exc})"


def _fix_local(cfg, opts, sigs, allowlist, paths, prog: Streamer) -> list[str]:
    """Fix LOCAL repositories: explicit `paths`, the configured local globs, or — failing
    both — the current repository. Each repo's cleanup lands as a PR on its own origin."""
    token, _ = auth.resolve_token()
    if not token:
        prog.line(auth.no_credential_hint("opening pull requests")
                  + " Where a repo can't be PR'd, the fix is saved as a patch instead.")
    cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
    patterns = list(paths) if paths else (list(cfg_local) or [str(_enclosing_repo_root())])
    repos = discover_local_repos(patterns, opts)
    if not repos:
        return []
    prog.line(f"Fixing {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, repo in enumerate(repos, 1):
        display = str(repo).replace(os.path.expanduser("~"), "~")
        prog.line(f"  [{i}/{len(repos)}] {display}")
        with status(f"opening PR for {display}…", enabled=prog.enabled):
            outcome = _safe_pr(repo, display, opts, sigs, allowlist, token)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def _fix_remote(cfg, opts, sigs, allowlist, prog: Streamer) -> list[str]:
    """Fix REMOTE repositories: enumerate the configured GitHub users/orgs (or a GitHub
    App's installation), clone each to a tempdir, and open/update its rolling fix PR."""
    slugs, token, _source = _resolve_remote(cfg, opts)
    if not token:
        prog.line(auth.no_credential_hint("remote remediation PRs")
                  + " The token needs repo + pull-request write scope.")
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
            with status(f"cloning + fixing {slug}…", enabled=prog.enabled):
                # Token via GIT_ASKPASS (env), never in the clone URL/argv.
                with gitutil.github_https_auth(token) as (prefix, env):
                    r = subprocess.run(["git", "clone", "--quiet", "--depth", "50",
                                        f"{prefix}{slug}.git", str(clone)],
                                       capture_output=True, text=True, check=False, env=env)
                outcome = (f"{slug}: clone failed (check token access)" if r.returncode != 0
                           else _safe_pr(clone, slug, opts, sigs, allowlist, token))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def fix(config_path: str | None = None, *, remote: bool = False,
        paths: list[str] | None = None, no_stream: bool = False) -> int:
    """`saw fix`: open/update one rolling cleanup PR per INFECTED repository.

    LOCAL by default; `remote=True` sweeps the configured GitHub targets. Auto-remediates —
    the PR is the review gate, so there is no apply/preview flag. Streams each repo's outcome
    live (progress on stderr). Returns 2 if an explicit --config is missing, 1 if any repo
    needs manual review (couldn't be auto-cleaned), else 0."""
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)

    outcomes = (_fix_remote(cfg, opts, sigs, allowlist, prog) if remote
                else _fix_local(cfg, opts, sigs, allowlist, paths, prog))
    if not outcomes:
        prog.line("No repositories to fix.")
        return 0
    # A repo "needs review" when no PR could clean it: an abort (residual infection) or an
    # error. submit_fix_pr's success strings ("opened PR", "updated", "already clean") don't
    # contain these markers, so this is a stable signal for a CI gate.
    needs_review = sum(1 for o in outcomes if "ABORTED" in o or ": error" in o)
    n = len(outcomes)
    plural = "y" if n == 1 else "ies"
    prog.line(f"\nProcessed {n} repositor{plural}"
              + (f"; {needs_review} need manual review." if needs_review else "."))
    return 1 if needs_review else 0

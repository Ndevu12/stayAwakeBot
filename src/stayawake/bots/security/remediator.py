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
import sys
from pathlib import Path

from stayawake.utils.config import load_yaml
from stayawake.lib import auth
from stayawake.utils import env
from stayawake.lib import git as gitutil
from stayawake.lib.adapters import github_api
from stayawake.utils.streaming import Streamer, stream_enabled, status
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security import resolution
from stayawake.bots.security.resolution import (
    discover_local_repos, invalid_slugs, REMOTE_EMPTY_HINT, DEFAULT_CONFIG,
    enclosing_repo_root as _enclosing_repo_root, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)
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


def _preflight(token: str | None, intent=None) -> str | None:
    """Authorize BEFORE any push/close via core.identity — never start privileged work on a
    dead/under-scoped credential. Returns an error message, or None when good to go."""
    from stayawake.core.identity import Intent, require
    from stayawake.core.identity.capabilities import (
        capabilities_from_app_permissions, capabilities_from_oauth_scopes,
    )
    from stayawake.core.identity.session import Session

    intent = intent or Intent.OPEN_FIX_PR
    if not token:
        sess = Session(token=None, source=None, kind="none", live=False)
    else:
        # Use this module's `github_api` / `env` so tests can patch remediator.github_api.*.
        live = github_api.token_is_valid(token, env.github_repository())
        scopes = github_api.oauth_scopes(token)
        caps = capabilities_from_oauth_scopes(scopes) if scopes is not None else None
        perms = github_api.installation_permissions(token)
        if perms is not None:
            caps = capabilities_from_app_permissions(perms)
        user = github_api.get_authenticated_user(token, quiet=True) or {}
        sess = Session(token=token, source="preflight", kind="user",
                       actor=user.get("login"), capabilities=caps, scopes=scopes, live=live)
    decision = require(intent, session=sess)
    return None if decision.allowed else decision.message


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
    token = source = None
    if publish:
        token, source = auth.resolve_token()
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
        if publish:
            # A GitHub App mints the token of the installation that owns THIS repo (multi-account).
            tok, aerr = auth.act_token(token, source, gitutil.origin_slug(repo))
            # ": error" marks it needs-review so `fix()` exits non-zero (a repo no credential can
            # reach was NOT fixed — never report it as success).
            outcome = f"{display}: error — {aerr}" if aerr else _safe(
                lambda r=repo, t=tok: pr_submit.submit_fix_pr(r, opts, sigs, allowlist, t,
                                                              spin=prog.enabled), display)
        else:
            outcome = _safe(
                lambda r=repo: pr_submit.prepare_fix(r, opts, sigs, allowlist, spin=prog.enabled),
                display)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def _fix_remote(cfg, opts, sigs, allowlist, prog: Streamer, *,
                users=None, orgs=None, slugs=None) -> list[str]:
    """Fix REMOTE repositories: resolve targets via the #1075 ladder (ad-hoc `--user`/`--org`
    /`owner/repo` selectors → config → your own repos), clone each, and open/update its PR
    (no local copy exists, so a PR is the only output)."""
    bad = invalid_slugs(slugs)
    if bad:
        prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
        return []
    resolved, token, source = _resolve_remote(cfg, opts, users=users, orgs=orgs, slugs=slugs)
    err = _preflight(token)
    if err:
        prog.line(err)
        return []
    if not resolved:
        prog.line(REMOTE_EMPTY_HINT)
        return []
    prog.line(f"Sweeping {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'} "
              f"({_remote_scope(cfg, users, orgs, slugs)})…")
    outcomes: list[str] = []
    for i, slug in enumerate(resolved, 1):
        prog.line(f"  [{i}/{len(resolved)}] {slug}")
        # A GitHub App mints the token of the installation that owns THIS repo (multi-account).
        tok, aerr = auth.act_token(token, source, slug)
        if aerr:
            outcome = f"{slug}: {aerr}"
        else:
            with status(f"cloning {slug}…", enabled=prog.enabled), \
                    resolution.cloned_repo(slug, tok) as clone:    # phase 0: clone (shared helper)
                # submit_fix_pr then drives its own scanning → fixing → opening-PR spinners.
                outcome = (f"{slug}: clone failed (check token access)" if clone is None
                           else _safe(lambda c=clone, t=tok: pr_submit.submit_fix_pr(
                               c, opts, sigs, allowlist, t, spin=prog.enabled), slug))
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def fix(config_path: str | None = None, *, pr: bool = False, remote: bool = False,
        paths: list[str] | None = None, users: list[str] | None = None,
        orgs: list[str] | None = None, slugs: list[str] | None = None,
        no_stream: bool = False) -> int:
    """`saw fix`: prepare a `security/auto-clean` branch per infected repo (no push). With
    `pr=True` (`--pr`) also push + open/update one rolling PR each; with `remote=True`
    (`--remote`) sweep GitHub targets resolved by the #1075 ladder (ad-hoc `users`/`orgs`/
    `slugs` → config → your own repos). Streams each repo's outcome. Returns 2 if an explicit
    --config is missing, 1 if any repo needs manual review, else 0."""
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)
    prog.line(f"Security fix — {now_iso()}")
    prog.line("")

    outcomes = (_fix_remote(cfg, opts, sigs, allowlist, prog, users=users, orgs=orgs, slugs=slugs)
                if remote
                else _fix_local(cfg, opts, sigs, allowlist, paths, prog, publish=pr))
    if not outcomes:
        prog.line("No repositories to fix.")
        return 0
    # A PARTIAL fix (#1183) shipped SOME safe changes but confirmed findings remain — the tree is
    # not clean, so it counts as needs-review and the run exits non-zero (invariant #1).
    needs_review = sum(1 for o in outcomes if "ABORTED" in o or ": error" in o or "PARTIAL" in o)
    n = len(outcomes)
    plural = "y" if n == 1 else "ies"
    prog.line(f"\nProcessed {n} repositor{plural}"
              + (f"; {needs_review} need manual review." if needs_review else "."))
    return 1 if needs_review else 0


# ── saw discard ──────────────────────────────────────────────────────────────────

def _discard_local(cfg, opts, branch: bool, pr: bool, paths, prog: Streamer) -> list[str]:
    token = source = None
    if pr:
        token, source = auth.resolve_token()
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
        # Closing a PR hits the API → a GitHub App needs THIS repo's installation token (multi-account).
        tok, aerr = auth.act_token(token, source, gitutil.origin_slug(repo)) if pr else (None, None)
        with status(f"discarding in {display}…", enabled=prog.enabled):
            if branch:
                parts.append(_safe(lambda r=repo: pr_submit.discard_branch(r), display))
            if pr:
                parts.append(f"PR: {aerr}" if aerr
                             else _safe(lambda r=repo, t=tok: pr_submit.discard_pr(r, t), display))
        outcome = "  ·  ".join(parts)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def _discard_remote(cfg, opts, branch: bool, pr: bool, prog: Streamer, *,
                    users=None, orgs=None, slugs=None) -> list[str]:
    bad = invalid_slugs(slugs)
    if bad:
        prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
        return []
    resolved, token, source = _resolve_remote(cfg, opts, users=users, orgs=orgs, slugs=slugs)
    err = _preflight(token)
    if err:
        prog.line(err)
        return []
    if not resolved:
        prog.line(REMOTE_EMPTY_HINT)
        return []
    prog.line(f"Discarding across {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'} "
              f"({_remote_scope(cfg, users, orgs, slugs)})…")
    outcomes: list[str] = []
    for i, slug in enumerate(resolved, 1):
        prog.line(f"  [{i}/{len(resolved)}] {slug}")
        parts: list[str] = []
        # A GitHub App mints the token of the installation that owns THIS repo (multi-account).
        tok, aerr = auth.act_token(token, source, slug)
        with status(f"discarding {slug}…", enabled=prog.enabled):
            if aerr:
                parts.append(aerr)
            else:
                if branch:
                    parts.append(_safe(lambda s=slug, t=tok: pr_submit.discard_remote_branch(s, t), slug))
                if pr:
                    parts.append(_safe(lambda s=slug, t=tok: pr_submit.discard_remote_pr(s, t), slug))
        outcome = "  ·  ".join(parts)
        prog.line(f"      → {outcome}")
        outcomes.append(outcome)
    return outcomes


def discard(config_path: str | None = None, *, branch: bool = False, pr: bool = False,
            remote: bool = False, paths: list[str] | None = None, users: list[str] | None = None,
            orgs: list[str] | None = None, slugs: list[str] | None = None,
            no_stream: bool = False) -> int:
    """`saw discard`: remove what `fix` produced — the `security/auto-clean` branch
    (`--branch`: local + remote, pure git, SSL-immune) and/or its PR (`--pr`: API). LOCAL by
    default; `--remote` sweeps GitHub targets resolved by the #1075 ladder (ad-hoc selectors →
    config → your own repos). Requires at least one of `--branch`/`--pr`. Returns 2 on a
    usage/config error, else 0."""
    if not (branch or pr):
        print("Nothing to discard: pass --branch (delete the fix branch) and/or --pr "
              "(close the fix PR).", file=sys.stderr)
        return 2
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    opts = _options(cfg.get("settings", {}))
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)
    prog.line(f"Security discard — {now_iso()}")
    prog.line("")

    outcomes = (_discard_remote(cfg, opts, branch, pr, prog, users=users, orgs=orgs, slugs=slugs)
                if remote
                else _discard_local(cfg, opts, branch, pr, paths, prog))
    if not outcomes:
        prog.line("No repositories to discard.")
        return 0
    n = len(outcomes)
    prog.line(f"\nProcessed {n} repositor{'y' if n == 1 else 'ies'}.")
    return 0

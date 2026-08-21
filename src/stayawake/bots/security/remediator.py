#!/usr/bin/env python3
"""Remediator service — `saw fix` and `saw discard`."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib import auth
from stayawake.utils import env, parallel
from stayawake.lib import git as gitutil
from stayawake.lib.adapters import github_api
from stayawake.utils.streaming import Streamer, stream_enabled, status
from stayawake.utils.sweep import run_sweep
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security import resolution
from stayawake.bots.security.config import resolve_config
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


def _resolve_config(config_path: str | None) -> dict | None:
    return resolve_config(config_path)


@dataclass(frozen=True)
class FixOutcome:
    """One repo's result. `needs_review` is decided WHERE the failure is known, never re-read from
    the summary: the remote arm's auth and clone failures said nothing a substring test matched, so
    a repo no credential could reach exited 0."""
    summary: str
    needs_review: bool = False

    def __str__(self) -> str:
        return self.summary


def _reviewed(fn, display: str) -> FixOutcome:
    """Wrap a submit/prepare result, grading it by the markers OUR OWN renderer writes."""
    text = _safe(fn, display)
    return FixOutcome(text, _needs_review(text))


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


def _needs_review(text: str) -> bool:
    """A repo needs manual review when its outcome is an error, an abort, or a PARTIAL fix —
    the tree isn't provably clean, so `fix` must exit non-zero for it (invariant #1). This is the ONE
    predicate the board tag and the final `fix()` tally both use, so they can never disagree."""
    return "ABORTED" in text or ": error" in text or "PARTIAL" in text


def _board_detail(label: str, text: str) -> str:
    """The outcome string starts with the repo label (`f"{slug}: …"`); drop that prefix so the
    board's per-repo line doesn't print the label twice."""
    return text[len(label):].lstrip(": ").strip() or text if text.startswith(label) else text


def _run_fix_sweep(items, labels, make_outcome, prog: Streamer, *, jobs,
                   verb: str) -> list[FixOutcome]:
    """Run one repo's operation over each item, returning outcomes in SUBMISSION order (so
    `fix()`'s needs-review tally is deterministic at any `-j`). `make_outcome(item, spin=…)` does the
    repo's work and never raises (it wraps its work in `_safe`).

    Two presentation modes, NO downgrade to either:
      * ONE worker (a single repo, or `-j 1`) → run inline with the FULL per-repo streaming — the
        live phase spinners (`spin=prog.enabled`) and the `[i/N] … → outcome` lines, exactly as
        before. There's a single writer, so nothing is lost.
      * MANY workers → run on the shared concurrency seam (`utils.sweep`, THREAD backend: git + API
        is I/O-bound, GIL released, no token crosses a process boundary) with the live board. Here
        per-repo spinners MUST be off (`spin=False`) — N concurrent workers can't each drive the one
        terminal — so the board is the reporter instead. One repo's failure stays isolated; a dead
        worker maps to a needs-review error string so the run still fails closed."""
    workers = parallel.resolve_jobs(jobs, len(items))
    if workers == 1:
        outcomes: list[FixOutcome] = []
        for i, item in enumerate(items):
            prog.line(f"  [{i + 1}/{len(items)}] {labels[i]}")
            outcome = make_outcome(item, spin=prog.enabled)
            prog.line(f"      → {outcome}")
            outcomes.append(outcome)
        return outcomes
    swept = run_sweep(
        lambda item: make_outcome(item, spin=False), items, jobs=workers,
        backend=parallel.THREAD, labels=labels,
        describe=lambda o: (("[review  ]" if o.error or o.value.needs_review
                             else "[fixed   ]"), "",
                            f"      → {_board_detail(labels[o.index], str(o.value or o.error))}"),
        progress_on=prog.enabled, verb=verb)
    return [o.value if not o.error
            else FixOutcome(f"{labels[o.index]}: error — {o.error}", needs_review=True)
            for o in swept]


# ── saw fix ──────────────────────────────────────────────────────────────────────

def _fix_local(cfg, opts, sigs, allowlist, paths, prog: Streamer, *, publish: bool,
               jobs=None) -> list[FixOutcome]:
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

    # `spin` is on only in the sequential single-writer path; the concurrent path passes spin=False
    # and shows in-flight state on the board instead (see `_run_fix_sweep`). pr.{prepare_fix,
    # submit_fix_pr} drive their OWN phase-accurate spinners (scanning → fixing → opening PR).
    def make_outcome(repo, *, spin):
        display = _disp(repo)
        if publish:
            tok, aerr = auth.act_token(token, source, gitutil.origin_slug(repo))
            if aerr:      # a repo no credential can reach was NOT fixed
                return FixOutcome(f"{display}: error — {aerr}", needs_review=True)
            return _reviewed(lambda: pr_submit.submit_fix_pr(repo, opts, sigs, allowlist, tok,
                                                            spin=spin), display)
        return _reviewed(lambda: pr_submit.prepare_fix(repo, opts, sigs, allowlist, spin=spin),
                         display)

    return _run_fix_sweep(repos, [_disp(r) for r in repos], make_outcome, prog, jobs=jobs,
                          verb="Fixing")


def _fix_remote(cfg, opts, sigs, allowlist, prog: Streamer, *,
                users=None, orgs=None, slugs=None, jobs=None) -> list[FixOutcome]:
    """Fix REMOTE repositories: resolve targets via the ladder (ad-hoc `--user`/`--org`
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

    def make_outcome(slug, *, spin):
        tok, aerr = auth.act_token(token, source, slug)
        if aerr:
            return FixOutcome(f"{slug}: {aerr}", needs_review=True)
        # `status` shows a live "cloning…" spinner in the sequential path; off under concurrency
        # (the board reports in-flight state). submit_fix_pr then drives its own phase spinners.
        with status(f"cloning {slug}…", enabled=spin), \
                resolution.cloned_repo(slug, tok) as clone:        # phase 0: clone (shared helper)
            if clone is None:
                return FixOutcome(f"{slug}: clone failed (check token access)", needs_review=True)
            return _reviewed(lambda: pr_submit.submit_fix_pr(clone, opts, sigs, allowlist, tok,
                                                            spin=spin), slug)

    return _run_fix_sweep(resolved, list(resolved), make_outcome, prog, jobs=jobs, verb="Fixing")


def fix(config_path: str | None = None, *, pr: bool = False, remote: bool = False,
        paths: list[str] | None = None, users: list[str] | None = None,
        orgs: list[str] | None = None, slugs: list[str] | None = None,
        no_stream: bool = False, jobs: int | None = None) -> int:
    """`saw fix`: prepare a `security/auto-clean` branch per infected repo (no push). With
    `pr=True` (`--pr`) also push + open/update one rolling PR each; with `remote=True`
    (`--remote`) sweep GitHub targets resolved by the ladder (ad-hoc `users`/`orgs`/
    `slugs` → config → your own repos). A multi-repo sweep runs up to `jobs` repos at once
    (AUTO by default; `-j 1` forces sequential). Streams each repo's outcome. Returns 2 if an
    explicit --config is missing, 1 if any repo needs manual review, else 0."""
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

    outcomes = (_fix_remote(cfg, opts, sigs, allowlist, prog, users=users, orgs=orgs, slugs=slugs,
                            jobs=jobs)
                if remote
                else _fix_local(cfg, opts, sigs, allowlist, paths, prog, publish=pr, jobs=jobs))
    if not outcomes:
        prog.line("No repositories to fix.")
        return 0
    needs_review = sum(1 for o in outcomes if o.needs_review)
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
            pr = False
    repos = _local_repos(cfg, opts, paths)
    if not repos:
        return []
    prog.line(f"Discarding in {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
    outcomes: list[str] = []
    for i, repo in enumerate(repos, 1):
        display = _disp(repo)
        prog.line(f"  [{i}/{len(repos)}] {display}")
        parts: list[str] = []
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
    default; `--remote` sweeps GitHub targets resolved by the ladder (ad-hoc selectors →
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

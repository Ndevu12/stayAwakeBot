#!/usr/bin/env python3
"""Remediator service — `saw fix` and `saw discard`."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib import auth
from stayawake.utils import env, exitcodes, parallel, prompt
from stayawake.lib import git as gitutil
from stayawake.lib.adapters import github_api
from stayawake.utils.streaming import Streamer, stream_enabled, status
from stayawake.utils.sweep import run_sweep
from stayawake.utils.timeutil import now_iso
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.host_note import fix_host_note
from stayawake.bots.security import resolution
from stayawake.bots.security.config import resolve_config
from stayawake.bots.security.service.config import _options
from stayawake.bots.security.resolution import (
    discover_local_repos, invalid_slugs, REMOTE_EMPTY_HINT, DEFAULT_CONFIG,
    enclosing_repo_root as _enclosing_repo_root, remote_scope as _remote_scope,
    resolve_remote as _resolve_remote)
from stayawake.bots.security.targets import ScanOptions
from stayawake.bots.security import pr as pr_submit
from stayawake.bots.security.pr.fix_verdict import Checkout, FixVerdict, Grade, render_fix_verdict


def _resolve_config(config_path: str | None, targets: list[str] | None = None) -> dict | None:
    return resolve_config(config_path, targets=targets)


@dataclass(frozen=True)
class FixOutcome:
    """One repo's result. The grade is decided WHERE the failure is known, never re-read from
    the summary: the remote arm's auth and clone failures said nothing a substring test matched, so
    a repo no credential could reach exited 0. `acted` is whether the run changed something."""
    summary: str
    grade: Grade = Grade.NEEDS_REVIEW
    acted: bool = False

    @property
    def needs_review(self) -> bool:
        return self.grade is Grade.NEEDS_REVIEW

    def __str__(self) -> str:
        return self.summary


def _review(summary: str) -> FixOutcome:
    """An outcome a person has to look at."""
    return FixOutcome(summary, Grade.NEEDS_REVIEW)


def _graded_fix(fn, display: str) -> FixOutcome:
    """One repo's fix, graded from its verdict. An exception, or anything that is not a verdict,
    needs review."""
    try:
        verdict = fn()
    except Exception as exc:  # noqa: BLE001 — isolate a single repo, keep the run going
        return _review(f"{display}: error — {exc}")
    if not isinstance(verdict, FixVerdict):
        return _review(f"{display}: error — the run returned no verdict")
    acted = verdict.checkout is not Checkout.CLEAN or bool(verdict.base_fix.branch)
    return FixOutcome(render_fix_verdict(verdict, prompt.attended()), verdict.grade, acted)


def _safe(fn, display: str) -> str:
    """Run one repo's operation, never raising — one repo's failure must not abort the run."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — isolate a single repo, keep the run going
        return f"{display}: error — {exc}"


def _amend_outcome(fn, display: str) -> FixOutcome:
    """One repo's amend, as a structure. `needs_review` comes from the act itself rather than from
    reading its own sentence back, and an exception is never a clean result."""
    from stayawake.bots.security.pr.outcome import render_amend_line
    try:
        outcome = fn()
    except Exception as exc:  # noqa: BLE001 — isolate a single repo, keep the run going
        return _review(f"{display}: error — {exc}")
    return FixOutcome(render_amend_line(outcome),
                      Grade.NEEDS_REVIEW if outcome.needs_review else Grade.DONE)


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


def named_but_absent(paths) -> list[str]:
    """The named paths that are not on disk. A glob is not named: it may legitimately match none."""
    return sorted(p for p in (paths or [])
                  if not any(c in p for c in "*?[")
                  and not Path(p).expanduser().exists())


def _local_repos(cfg: dict, opts: ScanOptions, paths) -> list[Path]:
    cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
    patterns = list(paths) if paths else (list(cfg_local) or [str(_enclosing_repo_root())])
    return discover_local_repos(patterns, opts)


def _disp(repo: Path) -> str:
    return str(repo).replace(os.path.expanduser("~"), "~")


def _board_detail(label: str, text: str) -> str:
    """The outcome string starts with the repo label (`f"{slug}: …"`); drop that prefix so the
    board's per-repo line doesn't print the label twice."""
    return text[len(label):].lstrip(": ").strip() or text if text.startswith(label) else text


_FIX_TAGS = {Grade.NEEDS_REVIEW: "[review  ]", Grade.HISTORY_REMAINS: "[history ]"}


def fix_tag(outcome: FixOutcome) -> str:
    """The board tag for one repository's fix, read from its grade."""
    if outcome.grade in _FIX_TAGS:
        return _FIX_TAGS[outcome.grade]
    return "[cleaned ]" if outcome.acted else "[clean   ]"


def _amend_tag(outcome: FixOutcome) -> str:
    return "[review  ]" if outcome.needs_review else "[fixed   ]"


def _run_fix_sweep(items, labels, make_outcome, prog: Streamer, *, jobs,
                   verb: str, tag=_amend_tag) -> list[FixOutcome]:
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
        describe=lambda o: (("[review  ]" if o.error else tag(o.value)), "",
                            f"      → {_board_detail(labels[o.index], str(o.value or o.error))}"),
        progress_on=prog.enabled, verb=verb)
    return [o.value if not o.error
            else _review(f"{labels[o.index]}: error — {o.error}")
            for o in swept]


def _bases_for(repo, branches) -> tuple[list[str | None], list[str]]:
    """One base per requested branch, or `[None]` (the repository default).

    Returns the bases and the names of any that do not exist, so a typo is refused rather than
    silently fixing the default instead.
    """
    if not branches:
        return [None], []
    missing = [b for b in branches
               if not (gitutil.ref_exists(repo, f"refs/heads/{b}")
                       or gitutil.ref_exists(repo, f"origin/{b}"))]
    return [b for b in branches if b not in missing], missing


def _item_label(display: str, base: str | None) -> str:
    return display if base is None else f"{display}@{base}"


# ── saw fix ──────────────────────────────────────────────────────────────────────

def _fix_local(cfg, opts, sigs, allowlist, paths, prog: Streamer, *, publish: bool,
               jobs=None, branches=None, resolver=None) -> list[FixOutcome]:
    """Fix LOCAL repositories. Default: PREPARE a `security/auto-clean` branch per repo (no
    push, no network). `publish` (`--pr`): also push + open/update a PR (pre-flighted). The
    resolver asks the operator only when one repository and one branch are fixed."""
    missing = named_but_absent(paths)
    if missing:
        prog.line(f"error: no such path: {', '.join(missing)}")
        return []
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
    items: list[tuple] = []
    refused: list[FixOutcome] = []
    for repo in repos:
        bases, missing = _bases_for(repo, branches)
        for name in missing:      # a named branch that isn't there is an error, not a silent default
            line = (f"{_disp(repo)}: error — no branch '{name}'. "
                    f"Check the name, or omit --branch to fix the repository default.")
            prog.line(f"      → {line}")     # the sweep only prints what it PROCESSES
            refused.append(_review(line))
        items += [(repo, base) for base in bases]
    if not items:
        return refused
    verb = "Opening PRs for" if publish else "Preparing fixes for"
    prog.line(f"{verb} {len(items)} target{'' if len(items) == 1 else 's'}…")
    asking = resolver if len(items) == 1 else None

    # `spin` is on only in the sequential single-writer path; the concurrent path passes spin=False
    # and shows in-flight state on the board instead (see `_run_fix_sweep`). pr.{prepare_fix,
    # submit_fix_pr} drive their OWN phase-accurate spinners (scanning → fixing → opening PR).
    def make_outcome(item, *, spin):
        repo, base = item
        display = _item_label(_disp(repo), base)
        if publish:
            tok, aerr = auth.act_token(token, source, gitutil.origin_slug(repo))
            if aerr:      # a repo no credential can reach was NOT fixed
                return _review(f"{display}: error — {aerr}")
            return _graded_fix(lambda: pr_submit.submit_fix_pr(
                repo, opts, sigs, allowlist, tok, base=base, spin=spin and asking is None,
                resolver=asking), display)
        return _graded_fix(lambda: pr_submit.prepare_fix(
            repo, opts, sigs, allowlist, base=base, spin=spin and asking is None,
            resolver=asking), display)

    labels = [_item_label(_disp(r), b) for r, b in items]
    return refused + _run_fix_sweep(items, labels, make_outcome, prog, jobs=jobs, verb="Fixing",
                                    tag=fix_tag)


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
              f"({_remote_scope(cfg, None, None, slugs)})…")

    def make_outcome(slug, *, spin):
        tok, aerr = auth.act_token(token, source, slug)
        if aerr:
            return _review(f"{slug}: {aerr}")
        # `status` shows a live "cloning…" spinner in the sequential path; off under concurrency
        # (the board reports in-flight state). submit_fix_pr then drives its own phase spinners.
        with status(f"cloning {slug}…", enabled=spin), \
                resolution.cloned_repo(slug, tok) as clone:        # phase 0: clone (shared helper)
            if clone is None:
                return _review(f"{slug}: clone failed (check token access)")
            return _graded_fix(lambda: pr_submit.submit_fix_pr(clone, opts, sigs, allowlist, tok,
                                                               spin=spin), slug)

    return _run_fix_sweep(resolved, list(resolved), make_outcome, prog, jobs=jobs, verb="Fixing",
                          tag=fix_tag)


def amend(config_path: str | None = None, *, paths: list[str] | None = None,
          remote: bool = False, slugs: list[str] | None = None,
          no_stream: bool = False, jobs=None, resolver=None) -> int:
    """`saw fix amend`: replace past commits that still carry the payload and force-update
    each branch they sat on. `--remote` clones the named GitHub targets and does the same.
    Never `--pr`. A local rewrite that does not update the remote is not a fix.

    There is deliberately no account-wide form. `--user`/`--org` resolve their target list at run
    time, so the operator names a set whose members they have not seen; that is acceptable for a
    scan and not for a verb that force-updates branches. Each repository is named.
    """
    cfg = _resolve_config(config_path, targets=None if remote else paths)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    prog = Streamer(enabled=stream_enabled(sys.stderr, force_off=no_stream), out=sys.stderr)
    prog.line(f"Security amend — {now_iso()}")
    prog.line("")
    if remote:
        outcomes = _amend_remote(cfg, opts, sigs, allowlist, prog, slugs=slugs, jobs=jobs)
    else:
        outcomes = _amend_local(cfg, opts, sigs, allowlist, paths, prog, jobs=jobs,
                                resolver=resolver)
    if not outcomes:
        # Nothing was examined. The four paths that reach here — a denied preflight, a malformed
        # slug, an empty resolution, a named path that matched no repository — all printed an
        # error and did no work; reporting success would let a CI gate read "no credential" as
        # "no payload".
        return 2
    needs_review = sum(1 for o in outcomes if o.needs_review)
    n = len(outcomes)
    plural = "y" if n == 1 else "ies"
    prog.line(f"\nProcessed {n} repositor{plural}"
              + (f"; {needs_review} need review." if needs_review else "."))
    return 1 if needs_review else 0





def _amend_local(cfg, opts, sigs, allowlist, paths, prog: Streamer, *,
                 jobs=None, resolver=None) -> list[FixOutcome]:
    from stayawake.core.identity import Intent
    missing = named_but_absent(paths)
    if missing:
        prog.line(f"error: no such path: {', '.join(missing)}")
        return []
    token, source = auth.resolve_token()
    err = _preflight(token, intent=Intent.AMEND_REFS)
    if err:
        prog.line(err)
        return []
    repos = _local_repos(cfg, opts, paths)
    if not repos:
        prog.line("No repositories to amend.")
        return []
    prog.line(f"Amending {len(repos)} repositor{'y' if len(repos) == 1 else 'ies'}…")

    # A local checkout is already the operator's config context; only the identity fallback is
    # needed (for when a GitHub App token cannot name itself), resolved once for the sweep.
    ident_fallback = auth._gh_fallback() if source == "github-app" else None
    gated_resolver = resolver if len(repos) == 1 else None

    def make_outcome(repo, *, spin):
        display = _disp(repo)
        tok, aerr = auth.act_token(token, source, gitutil.origin_slug(repo))
        if aerr:
            tok = None
        from stayawake.bots.security.pr.amend import amend_outcome
        return _amend_outcome(lambda r=repo, t=tok: amend_outcome(
            r, display, opts, sigs, allowlist, t,
            identity_fallback=ident_fallback, resolver=gated_resolver,
            operator_checkout=True), display)

    labels = [_disp(r) for r in repos]
    return _run_fix_sweep(repos, labels, make_outcome, prog, jobs=jobs, verb="Amending")


def _amend_remote(cfg, opts, sigs, allowlist, prog: Streamer, *,
                  slugs=None, jobs=None) -> list[FixOutcome]:
    bad = invalid_slugs(slugs)
    if bad:
        prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
        return []
    resolved, token, source = _resolve_remote(cfg, opts, slugs=slugs)
    from stayawake.core.identity import Intent
    err = _preflight(token, intent=Intent.AMEND_REFS)
    if err:
        prog.line(err)
        return []
    if not resolved:
        prog.line(REMOTE_EMPTY_HINT)
        return []
    prog.line(f"Sweeping {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'} "
              f"({_remote_scope(cfg, None, None, slugs)})…")

    # The operator's signer (their config context) and identity fallback (their session, for when a
    # GitHub App token cannot name itself), resolved ONCE for the sweep, not re-spawned per repo.
    operator_ctx = _enclosing_repo_root()
    ident_fallback = auth._gh_fallback() if source == "github-app" else None

    def make_outcome(slug, *, spin):
        tok, aerr = auth.act_token(token, source, slug)
        if aerr:
            return _review(f"{slug}: {aerr}")
        with status(f"cloning {slug}…", enabled=spin), \
                resolution.cloned_repo(slug, tok, depth=None) as clone:
            if clone is None:
                return _review(f"{slug}: clone failed (check token access)")
            from stayawake.bots.security.pr.amend import amend_outcome
            return _amend_outcome(lambda c=clone, t=tok: amend_outcome(
                c, slug, opts, sigs, allowlist, t,
                identity_fallback=ident_fallback, operator_context=operator_ctx), slug)

    return _run_fix_sweep(resolved, list(resolved), make_outcome, prog, jobs=jobs, verb="Amending")


def fix(config_path: str | None = None, *, pr: bool = False, remote: bool = False,
        paths: list[str] | None = None, users: list[str] | None = None,
        orgs: list[str] | None = None, slugs: list[str] | None = None,
        no_stream: bool = False, jobs: int | None = None,
        branches: list[str] | None = None, resolver=None) -> int:
    """`saw fix`: prepare a `security/auto-clean` branch per infected repo (no push). With
    `pr=True` (`--pr`) also push + open/update one rolling PR each; with `remote=True`
    (`--remote`) sweep GitHub targets resolved by the ladder (ad-hoc `users`/`orgs`/
    `slugs` → config → your own repos). A multi-repo sweep runs up to `jobs` repos at once
    (AUTO by default; `-j 1` forces sequential). `resolver` asks the operator about the files added
    beside a payload when one local repository is fixed. Streams each repo's outcome. Returns
    INCOMPLETE if
    an explicit --config is missing or any repo needs review, FINDINGS if any history still stores
    what was cleared, else CLEAN."""
    cfg = _resolve_config(config_path, targets=None if remote else paths)
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
                else _fix_local(cfg, opts, sigs, allowlist, paths, prog, publish=pr, jobs=jobs,
                                branches=branches, resolver=resolver))
    if not outcomes:
        prog.line("No repositories to fix.")
        return 0
    prog.line(fix_tally(outcomes))
    prog.line(fix_host_note())
    return fix_status(outcomes)


def fix_tally(outcomes) -> str:
    """The closing line of a fix run, counted from each repository's grade."""
    review = sum(1 for o in outcomes if o.grade is Grade.NEEDS_REVIEW)
    history = sum(1 for o in outcomes if o.grade is Grade.HISTORY_REMAINS)
    n = len(outcomes)
    parts = [f"\nProcessed {n} repositor{'y' if n == 1 else 'ies'}"]
    if review:
        parts.append(f"{review} need review")
    if history:
        parts.append(f"{history} still carry it in their history")
    return "; ".join(parts) + "."


def fix_status(outcomes) -> int:
    """The status a fix run ends with, from each repository's grade."""
    grades = {o.grade for o in outcomes}
    if Grade.NEEDS_REVIEW in grades:
        return exitcodes.INCOMPLETE
    if Grade.HISTORY_REMAINS in grades:
        return exitcodes.FINDINGS
    return exitcodes.CLEAN


# ── saw discard ──────────────────────────────────────────────────────────────────

def _discard_local(cfg, opts, branch: bool, pr: bool, paths, prog: Streamer) -> list[str]:
    missing = named_but_absent(paths)
    if missing:
        prog.line(f"error: no such path: {', '.join(missing)}")
        return []
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

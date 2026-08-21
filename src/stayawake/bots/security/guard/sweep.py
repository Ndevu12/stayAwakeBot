#!/usr/bin/env python3
"""`saw guard` sweep — resolve TARGETS (local repos / remote slugs, like saw scan/fix), check or set
up each, streaming per repo; one repo's failure never aborts the run."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from stayawake.lib import auth
from stayawake.lib import git as gitutil
from stayawake.utils import parallel
from stayawake.utils.config import load_yaml
from stayawake.utils.streaming import Streamer, stream_enabled, status as spin_status
from stayawake.utils.sweep import run_sweep
from stayawake.utils.terminal import supports_color
from stayawake.bots.security import resolution
from stayawake.bots.security.config import resolve_config
from stayawake.bots.security.targets import ScanOptions
from stayawake.bots.security.guard.detect import check, render, GuardStatus, latest_strix
from stayawake.bots.security.guard.provision import setup, render_setup, resolve_pin, SetupResult
from stayawake.bots.security.guard.pindrift import drift_one, render_drift, DriftOutcome

# ── sweep: resolve targets (local repos / remote slugs) and check each — like saw scan/fix ────────
# `saw guard check` takes positional TARGETS (local paths, or owner/repo slugs under --remote),
# Streams per repo; one repo's failure never aborts the run.

def _guard_config(config_path: str | None):
    return resolve_config(config_path)


def _local_patterns(cfg: dict, paths) -> list[str]:
    cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
    return list(paths) if paths else (list(cfg_local) or [str(resolution.enclosing_repo_root())])


def _disp(repo: Path) -> str:
    return str(repo).replace(os.path.expanduser("~"), "~")


def _act(base_token, source, *, repo: Path | None = None, slug: str | None = None):
    """(token, err) to act on ONE repo in a sweep. A GitHub App upgrades to the token of the
    installation that OWNS the repo (multi-account) so each account/org is acted on with its own
    credentials; env / gh stay repo-agnostic. `err` (install/expand guidance) is set when an App is
    configured but can't reach the repo — the caller records it as that repo's outcome and continues."""
    s = slug if slug else (gitutil.origin_slug(repo) if repo is not None else None)
    return auth.act_token(base_token, source, s)


def _indent(text: str) -> str:
    return "\n".join("    " + ln for ln in text.splitlines())


def _guard_sweep(items, labels, make_result, render_one, tag_of, dead, prog: Streamer, *,
                 jobs, verb: str, no_stream: bool):
    """Run one guard operation over each item and return the results list for the caller's tally.
    Each repo's OWN rendered result is shown AT the point it completes — never in a separate,
    untrackable pass. NO downgrade to either mode:

      * ONE worker (a single repo, or `-j 1`) → run inline, single-writer: the `[i/N]` header, the
        live phase spinners (`make_result(item, spin=prog.enabled)`), and the streamed render —
        exactly as before.
      * MANY workers → run on the shared concurrency seam (`utils.sweep`, THREAD backend: git + API
        is I/O-bound, GIL released, no token crosses a process boundary). The board shows the live
        `done · running · elapsed` header + in-flight repos, and as each repo finishes it scrolls up
        carrying its FULL rendered block right under its `[i/N] tag label` header — so the result is
        rendered in place, labelled, at completion. The board draws on STDOUT (guard's report
        stream, so it stays redirectable). Per-repo spinners are off (`spin=False`) — N concurrent
        workers can't each drive the terminal; the board is the reporter. One repo isolated; a dead
        worker becomes `dead(label, err)` so the tally still fails closed.

    `make_result(item, spin=…)` does one repo's work and never raises (wraps in `_safe_*`);
    `render_one(result)` is its human block; `tag_of(outcome)` gives the board verdict tag."""
    workers = parallel.resolve_jobs(jobs, len(items))
    results = []
    if workers == 1:
        for i, item in enumerate(items):
            prog.line(f"  [{i + 1}/{len(items)}] {labels[i]}")
            res = make_result(item, spin=prog.enabled)
            prog.line(_indent(render_one(res)))
            results.append(res)
        return results

    # The board renders each repo's own block as it completes (`describe` → (tag, "", block)); the
    # bare "" detail keeps the header clean since the block below carries the full result.
    def describe(o):
        tag, _ = tag_of(o)
        return tag, "", _indent(render_one(o.value))

    swept = run_sweep(lambda it: make_result(it, spin=False), items, jobs=workers,
                      backend=parallel.THREAD, labels=labels, describe=describe, out=sys.stdout,
                      verb=verb, progress_on=stream_enabled(sys.stdout, force_off=no_stream))
    for o in swept:
        results.append(o.value if not o.error else dead(labels[o.index], o.error))
    return results


def _check_board(o) -> tuple[str, str]:
    """Compact board tag/detail for a `GuardStatus` (progress only — never the exit code, which the
    final tally owns)."""
    st = o.value
    if st.error:
        return "[error   ]", "unreadable"
    if st.no_ci:
        return "[no ci   ]", "no CI"
    if not st.present:
        return "[absent  ]", "no worm gate"
    if st.healthy:
        return "[guarded ]", "pinned & fresh"
    return "[stale   ]", "needs attention"


def _drift_board(o) -> tuple[str, str]:
    d = o.value
    if d.state == "error":
        return "[error   ]", "check failed"
    tag = {"behind": "[stale   ]", "no-gate": "[no gate ]",
           "no-ci": "[no ci   ]"}.get(d.state, "[ok      ]")
    return tag, (d.action if d.action != "none" else d.state)


def _setup_board(o) -> tuple[str, str]:
    r = o.value
    if r.error:
        return "[error   ]", "failed"
    if r.dry_run:
        return "[preview ]", "dry run"
    if r.wrote is not None or (r.submit is not None and r.submit.kind in ("pr", "fork-pr")):
        return "[done    ]", "opened/written"
    if r.submit is not None:                       # pushed but the PR itself didn't open (#see tally)
        return "[review  ]", "PR not opened"
    return "[ok      ]", "up to date"


def _safe_check(**kw) -> GuardStatus:
    """One repo's error must never abort the sweep — a failed check becomes an error status."""
    try:
        return check(**kw)
    except Exception as exc:  # noqa: BLE001 — isolate one repo, keep the sweep going
        return GuardStatus(present=False, error=f"check failed — {exc}")


def check_targets(*, paths=None, slugs=None, users=None, orgs=None, remote: bool = False,
                  config_path: str | None = None, branch: str = "main",
                  fail: bool = False, no_stream: bool = False, jobs: int | None = None) -> int:
    """`saw guard check` across many repos. LOCAL by default (discover git repos under the given
    paths / configured `targets.local` / the enclosing repo); `remote=True` (or naming users/orgs)
    resolves GitHub repos via the ladder and checks each over the API. The latest Strix release
    is resolved ONCE and reused for every repo's freshness. A multi-repo sweep checks up to `jobs`
    repos at once (AUTO by default; `-j 1` forces sequential); results render in target order.
    Returns 2 on a missing --config, 1 when `fail` and any gate isn't a healthy pinned Strix gate,
    else 0."""
    cfg = _guard_config(config_path)
    if cfg is None:
        return 2
    remote = remote or bool(users) or bool(orgs)
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream))
    color = supports_color(sys.stdout)

    if remote:
        bad = resolution.invalid_slugs(slugs)
        if bad:
            prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
            return 2
        resolved, token, source = resolution.resolve_remote(cfg, ScanOptions(),
                                                            users=users, orgs=orgs, slugs=slugs)
        if not resolved:
            prog.line(resolution.REMOTE_EMPTY_HINT)
            return 0
        latest = latest_strix(token)
        prog.line(f"Checking {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'}…")
        items, labels = resolved, list(resolved)

        def make_result(slug, *, spin):        # check has no per-phase spinner; `spin` unused
            tok, aerr = _act(token, source, slug=slug)
            return GuardStatus(present=False, error=aerr) if aerr \
                else _safe_check(slug=slug, branch=branch, token=tok, latest=latest)
    else:
        repos = resolution.discover_local_repos(_local_patterns(cfg, paths), ScanOptions())
        if not repos:
            prog.line("No local git repositories found.")
            return 0
        token, _ = auth.resolve_token()
        latest = latest_strix(token)
        prog.line(f"Checking {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
        items, labels = repos, [_disp(r) for r in repos]

        def make_result(repo, *, spin):
            # A local check reads the working tree; only freshness touches the network (public Strix
            # release), so the base token is enough — no per-owner installation token needed here.
            return _safe_check(repo=repo, token=token, latest=latest)

    statuses = _guard_sweep(
        items, labels, make_result, lambda st: render(st, color=color), _check_board,
        lambda label, err: GuardStatus(present=False, error=f"check failed — {err}"),
        prog, jobs=jobs, verb="Checking", no_stream=no_stream)

    guarded = sum(1 for s in statuses if s.present)
    verified = sum(1 for s in statuses if s.healthy)
    no_ci = sum(1 for s in statuses if s.no_ci)
    unreadable = sum(1 for s in statuses if s.error)
    unhealthy = [s for s in statuses if not s.healthy]
    n = len(statuses)
    tail = "".join([
        f", {verified} a verified SHA-pinned Strix gate" if guarded else "",
        f", {no_ci} with no CI" if no_ci else "",
        f", {unreadable} unreadable" if unreadable else "",
    ])
    prog.line(f"\nChecked {n} repositor{'y' if n == 1 else 'ies'}: {guarded} with a worm gate{tail}.")
    return 1 if (fail and unhealthy) else 0


def _safe_drift(**kw) -> DriftOutcome:
    """One repo's error must never abort the drift sweep — a failure becomes an error outcome."""
    try:
        return drift_one(**kw)
    except Exception as exc:  # noqa: BLE001 — isolate one repo, keep the sweep going
        tgt = kw.get("slug") or str(kw.get("repo") or ".")
        return DriftOutcome(tgt, "error", detail=f"drift check failed — {exc}")


def drift_targets(*, paths=None, slugs=None, users=None, orgs=None, remote: bool = False,
                  config_path: str | None = None, no_stream: bool = False,
                  jobs: int | None = None) -> int:
    """`saw guard drift` across many repos — same target model as `saw guard check`. LOCAL by default
    (discover git repos under the given paths / configured `targets.local` / the enclosing repo);
    `remote=True` (or naming users/orgs) resolves GitHub repos via the ladder. For each repo it
    grades the pinned Strix gate and files/refreshes/closes ONE de-duplicated drift issue. The latest
    Strix release is resolved ONCE and reused. A multi-repo sweep runs up to `jobs` repos at once
    (AUTO by default; `-j 1` forces sequential); each repo files only its OWN issue. Returns 2 on a
    missing --config / a remote sweep with no credential, else 0 (drift is reported as an issue, never
    a build failure)."""
    cfg = _guard_config(config_path)
    if cfg is None:
        return 2
    remote = remote or bool(users) or bool(orgs)
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream))
    color = supports_color(sys.stdout)

    if remote:
        bad = resolution.invalid_slugs(slugs)
        if bad:
            prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
            return 2
        resolved, token, source = resolution.resolve_remote(cfg, ScanOptions(),
                                                            users=users, orgs=orgs, slugs=slugs)
        if not resolved:
            prog.line(resolution.REMOTE_EMPTY_HINT)
            return 0
        if not token:
            prog.line(auth.no_credential_hint("filing pin-drift issues") + "\n")
            return 2
        latest = latest_strix(token)
        prog.line(f"Checking pin drift on {len(resolved)} GitHub "
                  f"repositor{'y' if len(resolved) == 1 else 'ies'}…")
        items, labels = resolved, list(resolved)

        def make_result(slug, *, spin):        # drift has no per-phase spinner; `spin` unused
            tok, aerr = _act(token, source, slug=slug)
            return DriftOutcome(slug, "error", detail=aerr) if aerr \
                else _safe_drift(slug=slug, token=tok, latest=latest)
    else:
        repos = resolution.discover_local_repos(_local_patterns(cfg, paths), ScanOptions())
        if not repos:
            prog.line("No local git repositories found.")
            return 0
        token, source = auth.resolve_token()
        latest = latest_strix(token)
        prog.line(f"Checking pin drift on {len(repos)} local "
                  f"repositor{'y' if len(repos) == 1 else 'ies'}…")
        items, labels = repos, [_disp(r) for r in repos]

        def make_result(repo, *, spin):
            tok, aerr = _act(token, source, repo=repo)
            return DriftOutcome(_disp(repo), "error", detail=aerr) if aerr \
                else _safe_drift(repo=repo, token=tok, latest=latest)

    outcomes = _guard_sweep(
        items, labels, make_result, lambda o: render_drift(o, color=color), _drift_board,
        lambda label, err: DriftOutcome(label, "error", detail=f"drift check failed — {err}"),
        prog, jobs=jobs, verb="Drift on", no_stream=no_stream)

    unprotected = sum(1 for o in outcomes if o.state in ("no-gate", "no-ci"))
    behind = sum(1 for o in outcomes if o.state == "behind")
    opened = sum(1 for o in outcomes if o.action == "opened")
    closed = sum(1 for o in outcomes if o.action == "closed")
    errored = sum(1 for o in outcomes if o.state == "error")
    n = len(outcomes)
    tail = "".join([
        f", {behind} with a stale pin" if behind else "",
        f", {opened} issue(s) opened" if opened else "",
        f", {closed} closed" if closed else "",
        f", {errored} errored" if errored else "",
    ])
    prog.line(f"\nChecked {n} repositor{'y' if n == 1 else 'ies'}: "
              f"{unprotected} UNPROTECTED{tail}.")
    return 0


def _safe_setup(repo, **kw) -> SetupResult:
    """One repo's error must never abort the setup sweep — a failure becomes an error result."""
    try:
        return setup(repo, **kw)
    except Exception as exc:  # noqa: BLE001 — isolate one repo, keep the sweep going
        return SetupResult(error=f"setup failed — {exc}")


def setup_targets(*, paths=None, slugs=None, users=None, orgs=None, remote: bool = False,
                  config_path: str | None = None, ref: str | None = None, dry_run: bool = False,
                  pr: bool = False, branch: str | None = None, no_stream: bool = False,
                  jobs: int | None = None) -> int:
    """`saw guard setup` across many repos, like `saw fix`. LOCAL by default (discover git repos;
    write/prepare the gate into each working tree, or `--pr` to open a PR each); `remote=True`
    resolves GitHub repos via the ladder, clones each, and opens a PR (a remote repo has no
    working tree, so `--pr` is implied). Never pushes to a default branch. A multi-repo sweep runs up
    to `jobs` repos at once (AUTO by default; `-j 1` forces sequential) — each repo works in its own
    clone/worktree so concurrency never crosses repos. Returns 2 on a missing --config, 1 if any repo
    errored or a PR couldn't be opened, else 0."""
    cfg = _guard_config(config_path)
    if cfg is None:
        return 2
    remote = remote or bool(users) or bool(orgs)
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream))
    color = supports_color(sys.stdout)

    if remote:
        bad = resolution.invalid_slugs(slugs)
        if bad:
            prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
            return 2
        resolved, token, source = resolution.resolve_remote(cfg, ScanOptions(),
                                                            users=users, orgs=orgs, slugs=slugs)
        if not token:
            prog.line(auth.no_credential_hint("cloning and opening guard PRs") + "\n")
            return 2
        from stayawake.core.identity import Intent, require
        decision = require(Intent.OPEN_GUARD_PR)
        if not decision.allowed:
            prog.line(decision.message)
            return 2
        if not resolved:
            prog.line(resolution.REMOTE_EMPTY_HINT)
            return 0
        pin = resolve_pin(token, ref)
        if pin is None:
            prog.line("couldn't resolve the latest Strix release (offline? pass --ref <sha|tag>)")
            return 2
        prog.line(f"Setting up {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'}…")
        items, labels = resolved, list(resolved)

        def make_result(slug, *, spin):
            tok, aerr = _act(token, source, slug=slug)
            if aerr:
                return SetupResult(error=f"{slug}: {aerr}")
            # `status` shows a live "cloning…" spinner in the sequential path; off under concurrency
            # (the board reports in-flight state instead — see fix). a remote repo has no working
            # tree → always PR; _safe_setup then drives its own phase spinners.
            with spin_status(f"cloning {slug}…", enabled=spin), \
                    resolution.cloned_repo(slug, tok) as clone:
                if clone is None:
                    return SetupResult(error=f"{slug}: clone failed (check token access)")
                return _safe_setup(clone, token=tok, pin=pin, dry_run=dry_run, pr=True,
                                   branch=branch, spin=spin)
    else:
        token, source = auth.resolve_token() if (pr or not ref) else (None, None)
        pin = resolve_pin(token, ref)
        if pin is None:
            prog.line("couldn't resolve the latest Strix release (offline? pass --ref <sha|tag>)")
            return 2
        repos = resolution.discover_local_repos(_local_patterns(cfg, paths), ScanOptions())
        if not repos:
            prog.line("No local git repositories found.")
            return 0
        prog.line(f"Setting up {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
        items, labels = repos, [_disp(r) for r in repos]

        def make_result(repo, *, spin):
            tok, aerr = _act(token, source, repo=repo) if pr else (token, None)
            if aerr:
                return SetupResult(error=f"{_disp(repo)}: {aerr}")
            return _safe_setup(repo, token=tok, pin=pin, dry_run=dry_run, pr=pr,
                               branch=branch, spin=spin)

    results = _guard_sweep(
        items, labels, make_result, lambda r: render_setup(r, color=color), _setup_board,
        lambda label, err: SetupResult(error=f"{label}: setup failed — {err}"),
        prog, jobs=jobs, verb="Setting up", no_stream=no_stream)

    n = len(results)
    opened = [r for r in results if not r.error and not r.dry_run
              and (r.wrote is not None
                   or (r.submit is not None and r.submit.kind in ("pr", "fork-pr")))]
    incomplete = [r for r in results if not r.error and not r.dry_run
                  and r.submit is not None and r.submit.kind not in ("pr", "fork-pr")]
    previewed = sum(1 for r in results if r.dry_run)
    noop = sum(1 for r in results if r.plan and r.plan.action == "noop" and not r.error and not r.dry_run)
    present = sum(1 for r in results if r.plan and r.plan.action == "present")
    errored = sum(1 for r in results if r.error)
    parts = []
    if opened:
        parts.append(f"{len(opened)} {'PR opened/updated' if (pr or remote) else 'written to the working tree'}")
    if previewed:
        parts.append(f"{previewed} previewed")
    if noop:
        parts.append(f"{noop} already up to date")
    if present:
        parts.append(f"{present} already guarded by another mechanism")
    if incomplete:
        parts.append(f"{len(incomplete)} PR could NOT be opened (see above)")
    if errored:
        parts.append(f"{errored} errored")
    prog.line(f"\n{n} repositor{'y' if n == 1 else 'ies'}: " + (", ".join(parts) or "nothing to do") + ".")
    return 1 if (errored or incomplete) else 0        # a pushed-but-unopened PR is a failure, not success

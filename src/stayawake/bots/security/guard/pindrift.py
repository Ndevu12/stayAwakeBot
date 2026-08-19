#!/usr/bin/env python3
"""Worm-guard PROTECTION backstop: file ONE self-closing issue per repo when its worm-guard gate is
missing or its pinned Strix release has fallen behind — so a repo stays gated and current over time.

A SHA-pinned gate keeps a later compromise from silently changing what runs, but two things drift
quietly: the gate can be REMOVED (or never installed) — the repo is then unprotected while you think
it's covered — and the pin goes STALE, running an old detection engine. This scheduled/one-shot check
turns either into an actionable, de-duplicated GitHub issue, and closes it once the repo is protected
and current — so nobody has to remember to look. `saw guard setup`'s scheduled job runs it on the
repo; an operator sweeps a fleet with `saw guard drift --remote --org …`.

Built ON `detect.check` — the same reader/grader `saw guard check` uses — so a gate is recognized by
ANY mechanism (Strix action / local action / `saw` step). A gate present by a non-Strix mechanism is
still PROTECTED (no issue; its release pin just isn't freshness-trackable). Reports as an ISSUE, never
a build failure. The multi-repo sweep (`drift_targets`) lives in `sweep`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.utils import env
from stayawake.utils.render import SEVERITY, paint
from stayawake.utils.textsafe import code as _code
from stayawake.bots.security.guard import detect

DRIFT_LABEL = "worm-guard-drift"
DRIFT_TITLE = "Worm-guard protection needs attention"

_DEFICIENT = {"no-gate", "no-ci", "behind"}
_PROTECTED = {"fresh", "floating", "not-strix"}
# else ("unknown" freshness / "error" reading a remote) → no issue action (never churn on a blip)


@dataclass
class DriftOutcome:
    """What `drift_one` found + did for one repo — the sweep renders and tallies these."""
    target: str
    state: str
    action: str = "none"
    detail: str = ""
    issue: int | None = None


def _resolve_slug(repo: Path) -> tuple[str, str] | None:
    """`(owner, name)` from `GITHUB_REPOSITORY` (set in CI) or, locally, the git origin."""
    s = env.github_slug()
    if s:
        return s
    slug = gitutil.origin_slug(repo)
    if slug and "/" in slug:
        owner, _, name = slug.partition("/")
        return owner, name
    return None


def _classify(st: "detect.GuardStatus") -> tuple[str, str]:
    """Map a `GuardStatus` to `(state, reason)`. `reason` is the issue's lead sentence for a
    deficiency (`state in _DEFICIENT`), else empty. A non-Strix gate is PROTECTED (no reason)."""
    if st.error:
        return "error", st.error
    if not st.present:
        if st.no_ci:
            return "no-ci", ("This repository has no CI workflows, so nothing scans merges for "
                             "supply-chain worm indicators — it is **unprotected**.")
        return "no-gate", ("This repository has no worm-guard gate, so infected merges are not "
                           "blocked — it is **unprotected**.")
    if st.ref is None:                                   # protected by a local action / `saw` step
        return "not-strix", ""
    if st.fresh is None or st.fresh.state == "unknown":
        return "unknown", ""
    if st.fresh.state == "behind":
        return "behind", (f"The worm-guard gate ({_code(st.ref.workflow)}) pins "
                          f"`Ndevu12/strix@{st.ref.ref[:12]}…`, but the latest Strix release is "
                          f"**{_code(st.fresh.latest_tag or 'unknown')}** — it is running an "
                          f"out-of-date detection engine.")
    return st.fresh.state, ""                            # fresh | floating → protected + current


def _issue_body(reason: str) -> str:
    return "\n".join([
        reason,
        "",
        "**Fix:** run `saw guard setup` — it installs the gate (or bumps a stale pin) and opens a PR "
        "to review and merge.",
        "",
        "_Auto-opened by the worm-guard drift check; it closes itself once the repo is protected and "
        "current._",
    ])


def _find_issue(owner: str, name: str, token: str | None) -> int | None:
    """The number of the existing (open) drift issue for this repo, or None."""
    for it in github_api.list_open_issues(owner, name, token, labels=DRIFT_LABEL, quiet=True) or []:
        if it.get("title") == DRIFT_TITLE:
            return it.get("number")
    return None


def drift_one(*, repo: str | Path | None = None, slug: str | None = None,
              token: str | None = None, latest: "detect.LatestStrix | None" = None) -> DriftOutcome:
    """Ensure ONE repo is gated and current (reusing `detect.check`), maintaining ONE dedup tracking
    issue. Deficient (no gate / no CI / Strix pin behind) → open the issue (or silently refresh the
    open one). Protected (Strix pin fresh/floating, or a non-Strix gate) → close any open issue. A
    transient `unknown` (releases API down) or a remote read `error` touches no issue (no churn).
    LOCAL (`repo` path) or REMOTE (`slug`)."""
    token = token or env.github_token()
    st = detect.check(repo=repo, slug=slug, token=token, latest=latest)

    if slug:
        owner, _, name = slug.partition("/")
        target = slug
    else:
        s = _resolve_slug(Path(repo or "."))
        owner, name = s if s else (None, None)
        target = f"{owner}/{name}" if s else Path(repo or ".").resolve().name

    state, reason = _classify(st)

    if state in _DEFICIENT:
        if not (owner and name):
            return DriftOutcome(target, state, detail="couldn't resolve owner/repo to file the issue")
        existing = _find_issue(owner, name, token)
        body = _issue_body(reason)
        if existing:
            github_api.update_issue(owner, name, existing, token, body=body)   # silent refresh
            return DriftOutcome(target, state, "refreshed", reason, existing)
        created = github_api.create_issue(owner, name, DRIFT_TITLE, body, token,
                                          labels=[DRIFT_LABEL], quiet=True)
        num = created.get("number") if isinstance(created, dict) else None
        return DriftOutcome(target, state, "opened", reason, num)

    if state in _PROTECTED:
        if owner and name:
            existing = _find_issue(owner, name, token)
            if existing:
                github_api.update_issue(owner, name, existing, token, state="closed")
                github_api.add_issue_comment(owner, name, existing,
                                             "Repo is protected and current again — closing automatically.",
                                             token)
                return DriftOutcome(target, state, "closed", issue=existing)
        return DriftOutcome(target, state)

    return DriftOutcome(target, state, detail=reason)      # unknown / error → report only


def render_drift(o: DriftOutcome, *, color: bool = False) -> str:
    """One-line, human-facing outcome for a repo's drift check (colour gated by the caller)."""
    warn, ok, dim = SEVERITY["warning"], SEVERITY["ok"], SEVERITY["info"]
    num = f" #{o.issue}" if o.issue else ""
    verb = {"opened": "opened", "refreshed": "updated"}.get(o.action, "")
    if o.state in ("no-gate", "no-ci"):
        head = "UNPROTECTED — no worm gate" if o.state == "no-gate" else "UNPROTECTED — no CI"
        tail = f" — {verb} protection issue{num}" if verb else \
            (f" ({o.detail})" if o.detail else "")
        return paint(f"⚠️  {head}", warn, on=color) + tail
    if o.state == "behind":
        tail = f" — {verb} drift issue{num}" if verb else ""
        return paint("⚠️  pin behind", warn, on=color) + tail
    if o.state in ("fresh", "floating"):
        closed = paint("  (closed the issue)", dim, on=color) if o.action == "closed" else ""
        return paint(f"✓ gated · pin {o.state}", ok, on=color) + closed
    if o.state == "not-strix":
        closed = paint("  (closed the issue)", dim, on=color) if o.action == "closed" else ""
        return (paint("✓ gated", ok, on=color)
                + paint(" — not the pinned Strix action; release freshness not tracked", dim, on=color)
                + closed)
    if o.state == "unknown":
        return paint("• freshness unknown", dim, on=color) + (f" — {o.detail}" if o.detail else "")
    return paint(f"⚠️  {o.detail or 'drift check failed'}", warn, on=color)

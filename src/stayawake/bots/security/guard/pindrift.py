#!/usr/bin/env python3
"""Out-of-band worm-guard pin-drift reporter: file ONE self-closing issue per repo when its pinned
Strix gate falls behind the latest release.

The gate SHA-pins `Ndevu12/strix@<sha>` so a later compromise can't silently change what runs — the
cost is that the pin goes stale and quietly runs an OLD detection engine while you think you're
covered. This turns "behind" into an actionable, de-duplicated GitHub issue (and closes it once the
pin catches up), so nobody has to remember to look. `saw guard setup`'s scheduled `pin-drift` job runs
it on one repo; an operator can sweep a whole fleet with `saw guard drift --remote --org …`.

Built ON `detect.check` — the same reader/grader `saw guard check` uses — so it recognizes a gate by
ANY mechanism (Strix action / local action / `saw` step) and only files issues for the gradeable
Strix-action pin; a non-Strix gate is reported present-but-not-trackable, never "no gate". Reports
drift as an ISSUE, never a build failure. The multi-repo sweep (`drift_targets`) lives in `sweep`.
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

DRIFT_LABEL = "worm-guard-pin-drift"
DRIFT_TITLE = "Worm-guard scanner pin is behind the latest Strix release"


@dataclass
class DriftOutcome:
    """What `drift_one` found + did for one repo — the sweep renders and tallies these."""
    target: str                    # owner/repo (or a local display name)
    state: str                     # behind | fresh | floating | unknown | not-strix | no-gate | no-ci | error
    action: str = "none"           # opened | refreshed | closed | none
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


def _issue_body(ref: "detect.StrixRef", fresh: "detect.Freshness") -> str:
    lines = [
        f"The worm-guard gate in {_code(ref.workflow)} pins `Ndevu12/strix@{ref.ref[:12]}…`, but the "
        f"latest Strix release is **{_code(fresh.latest_tag or 'unknown')}** — the gate is running an "
        f"out-of-date detection engine.",
        "",
    ]
    if fresh.detail:
        lines += [f"- {_code(fresh.detail)}", ""]
    lines += [
        "**Fix:** re-run `saw guard setup` (it repins the gate to the latest reviewed release), then "
        "review and merge the PR it opens.",
        "",
        "_Auto-opened by the worm-guard pin-drift job; it closes itself once the pin catches up._",
    ]
    return "\n".join(lines)


def _find_issue(owner: str, name: str, token: str | None) -> int | None:
    """The number of the existing (open) drift issue for this repo, or None."""
    for it in github_api.list_open_issues(owner, name, token, labels=DRIFT_LABEL, quiet=True) or []:
        if it.get("title") == DRIFT_TITLE:
            return it.get("number")
    return None


def drift_one(*, repo: str | Path | None = None, slug: str | None = None,
              token: str | None = None, latest: "detect.LatestStrix | None" = None) -> DriftOutcome:
    """Grade ONE repo's worm-guard pin (reusing `detect.check`) and open / refresh / close its dedup
    tracking issue. LOCAL (`repo` path) or REMOTE (`slug`). Only a gradeable **Strix-action** pin that
    is `behind` opens/refreshes an issue; `fresh`/`floating` closes an open one; a transient `unknown`
    (releases API down) does nothing (no churn). A non-Strix gate, no gate, or no CI is reported as-is
    and touches no issue."""
    token = token or env.github_token()
    st = detect.check(repo=repo, slug=slug, token=token, latest=latest)

    if slug:
        owner, _, name = slug.partition("/")
        target = slug
    else:
        s = _resolve_slug(Path(repo or "."))
        owner, name = s if s else (None, None)
        target = f"{owner}/{name}" if s else Path(repo or ".").resolve().name

    if st.error:
        return DriftOutcome(target, "error", detail=st.error)
    if not st.present:
        return DriftOutcome(target, "no-ci" if st.no_ci else "no-gate",
                            detail="no CI workflows" if st.no_ci else "no worm gate found")
    if st.ref is None:                                   # guarded, but not by the gradeable Strix action
        return DriftOutcome(target, "not-strix",
                            detail=f"guarded by {st.mechanism or 'another mechanism'} "
                                   f"({st.gate_file}) — no Strix release pin to track")
    fresh = st.fresh
    if fresh is None or fresh.state == "unknown":
        return DriftOutcome(target, "unknown",
                            detail=(fresh.detail if fresh else "freshness not checked"))
    if not (owner and name):
        return DriftOutcome(target, fresh.state,
                            detail="couldn't resolve owner/repo to file the drift issue")

    existing = _find_issue(owner, name, token)
    if fresh.state == "behind":
        body = _issue_body(st.ref, fresh)
        if existing:
            github_api.update_issue(owner, name, existing, token, body=body)   # silent refresh
            return DriftOutcome(target, "behind", "refreshed", f"latest {fresh.latest_tag}", existing)
        created = github_api.create_issue(owner, name, DRIFT_TITLE, body, token,
                                          labels=[DRIFT_LABEL], quiet=True)
        num = created.get("number") if isinstance(created, dict) else None
        return DriftOutcome(target, "behind", "opened", f"latest {fresh.latest_tag}", num)
    # fresh / floating → the pin is current: close any open drift issue.
    if existing:
        github_api.update_issue(owner, name, existing, token, state="closed")
        github_api.add_issue_comment(owner, name, existing,
                                     "Worm-guard pin is current again — closing automatically.", token)
        return DriftOutcome(target, fresh.state, "closed", issue=existing)
    return DriftOutcome(target, fresh.state)


def render_drift(o: DriftOutcome, *, color: bool = False) -> str:
    """One-line, human-facing outcome for a repo's drift check (colour gated by the caller)."""
    warn, ok, dim = SEVERITY["warning"], SEVERITY["ok"], SEVERITY["info"]
    if o.state == "behind":
        verb = {"opened": "opened", "refreshed": "updated"}.get(o.action, "flagged")
        num = f" #{o.issue}" if o.issue else ""
        return (paint(f"⚠️  pin behind — {verb} drift issue{num}", warn, on=color)
                + (f" ({o.detail})" if o.detail else ""))
    if o.state in ("fresh", "floating"):
        closed = paint("  (closed the drift issue)", dim, on=color) if o.action == "closed" else ""
        return paint(f"✓ pin {o.state}", ok, on=color) + closed
    if o.state == "not-strix":
        return paint("• not the pinned Strix action", dim, on=color) + f" — {o.detail}"
    if o.state == "no-ci":
        return paint("• no CI", dim, on=color) + " — nothing to track."
    if o.state == "no-gate":
        return paint("• no worm gate", dim, on=color) + " — run `saw guard setup`."
    if o.state == "unknown":
        return paint("• freshness unknown", dim, on=color) + (f" — {o.detail}" if o.detail else "")
    return paint(f"⚠️  {o.detail or 'drift check failed'}", warn, on=color)

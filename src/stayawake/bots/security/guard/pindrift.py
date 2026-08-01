#!/usr/bin/env python3
"""Out-of-band worm-guard pin-drift reporter: file ONE self-closing issue when a repo's pinned Strix
gate falls behind the latest release.

The gate SHA-pins `Ndevu12/strix@<sha>` so a later compromise can't silently change what runs — the
cost is that the pin goes stale and quietly runs an OLD detection engine while you think you're
covered. `saw guard check` already grades that (fresh|behind); this is the SCHEDULED backstop the
`saw guard setup` workflow runs, turning "behind" into an actionable, de-duplicated GitHub issue —
and closing it automatically once the pin catches up — so nobody has to remember to look. Reuses the
freshness grader in `detect` and mirrors the saw repo's own `scanner-pin-drift`, keyed on the pinned
ACTION ref. Reports drift as an ISSUE, never a build failure (exit 0); exit 1 only on a hard error.
"""
from __future__ import annotations

import sys
from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.utils import env
from stayawake.utils.textsafe import code as _code
from stayawake.bots.security.guard import detect

DRIFT_LABEL = "worm-guard-pin-drift"
DRIFT_TITLE = "Worm-guard scanner pin is behind the latest Strix release"


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


def drift(repo: str | Path | None = None, *, token: str | None = None) -> int:
    """Grade the local worm-guard pin's freshness and open / refresh / close ONE dedup tracking issue.

    Behind → open a new issue (or silently refresh the open one). Fresh/floating → close the open issue
    (with a notifying comment). A transient `unknown` (releases API unreachable) does NOTHING, so a flaky
    network never churns the issue. Exit 0 always for a graded run (drift is reported, not a failure);
    exit 1 only when the repo/gate can't be resolved at all."""
    repo = Path(repo or ".")
    token = token or env.github_token()
    slug = _resolve_slug(repo)
    if not slug:
        print("guard drift: could not resolve owner/repo (set GITHUB_REPOSITORY or add a git origin)",
              file=sys.stderr)
        return 1
    owner, name = slug
    ref = detect.find_strix(detect._local_workflows(repo))
    if ref is None:
        print("guard drift: no Strix gate found in .github/workflows — nothing to track.")
        return 0

    fresh = detect.freshness(ref, token)
    existing = _find_issue(owner, name, token)
    if fresh.state == "behind":
        body = _issue_body(ref, fresh)
        if existing:
            github_api.update_issue(owner, name, existing, token, body=body)   # silent refresh
            print(f"guard drift: pin behind ({fresh.latest_tag}) — refreshed issue #{existing}.")
        else:
            created = github_api.create_issue(owner, name, DRIFT_TITLE, body, token,
                                              labels=[DRIFT_LABEL], quiet=True)
            num = created.get("number") if isinstance(created, dict) else "?"
            print(f"guard drift: pin behind ({fresh.latest_tag}) — opened issue #{num}.")
    elif fresh.state in ("fresh", "floating") and existing:
        github_api.update_issue(owner, name, existing, token, state="closed")
        github_api.add_issue_comment(owner, name, existing,
                                     "Worm-guard pin is current again — closing automatically.", token)
        print(f"guard drift: pin is {fresh.state} — closed issue #{existing}.")
    else:
        print(f"guard drift: pin is {fresh.state}"
              + (f" ({fresh.detail})" if fresh.detail else "") + " — no issue action needed.")
    return 0

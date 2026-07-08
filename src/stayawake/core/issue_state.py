#!/usr/bin/env python3
"""A GitHub issue used as a durable, file-less state store — reusable infrastructure.

A bot often needs a little cross-run state (a debounce counter, a "last seen" marker) but shouldn't
write files into, or commit to, the repo it operates on. This gives it one **marker-identified
singleton issue** whose body carries a hidden JSON state block: find it by a stable marker (never by
title, which churns), read the block, and write it back silently (a body edit sends no
notification). GitHub persists it for free — no local dir, no `history.json`, no commit.

Generic on purpose (`core`): the health sentinel stores its per-service availability debounce here,
and any other consumer (e.g. the security `IssueSink`) can reuse the same mechanism instead of
re-implementing marker lookup + state parsing. Every call is best-effort — a missing token or an
HTTP error returns None/`{}`, never raises, so a caller's own verdict/exit code is unaffected.
"""
from __future__ import annotations

import json
import re
from typing import Any

from stayawake.core.adapters import github_api

# The hidden state block: `<!-- state:{...json...} -->`. Non-greedy so it can sit anywhere in a body
# that also contains a human dashboard.
_STATE_RE = re.compile(r"<!--\s*state:(\{.*?\})\s*-->", re.DOTALL)


def parse_state(body: str | None) -> dict[str, Any]:
    """The JSON state persisted in an issue body, or `{}` if absent/malformed. A corrupt block must
    degrade to 'no prior state', never crash the run — so this never raises."""
    m = _STATE_RE.search(body or "")
    if not m:
        return {}
    try:
        state = json.loads(m.group(1))
    except (json.JSONDecodeError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def state_comment(state: dict[str, Any]) -> str:
    """The hidden state block to embed in an issue body; round-trips through `parse_state`."""
    return f"<!-- state:{json.dumps(state, separators=(',', ':'), sort_keys=True)} -->"


def _matches(owner: str, repo: str, marker: str, token: str | None, label: str | None) -> list[dict]:
    return [it for it in github_api.list_open_issues(owner, repo, token, labels=label)
            if marker in (it.get("body") or "")]


def load(owner: str, repo: str, marker: str, token: str | None,
         *, label: str | None = None) -> tuple[dict | None, dict[str, Any]]:
    """Return `(issue_or_None, parsed_state)` for the one open issue bearing `marker` (the lowest
    number if overlapping runs created duplicates)."""
    matches = _matches(owner, repo, marker, token, label)
    issue = min(matches, key=lambda it: it["number"]) if matches else None
    return issue, parse_state(issue.get("body") if issue else None)


def save(owner: str, repo: str, marker: str, token: str | None, *,
         title: str, body: str, label: str | None = None) -> dict | None:
    """Create-or-silently-update the one marker-identified issue with `body` (which should embed the
    state block via `state_comment`). Self-heals: any duplicate marker-issue from an overlapping run
    is closed. Returns the primary issue dict, or None on failure."""
    matches = _matches(owner, repo, marker, token, label)
    if not matches:
        return github_api.create_issue(owner, repo, title, body, token,
                                       labels=[label] if label else None)
    primary = min(matches, key=lambda it: it["number"])
    result = github_api.update_issue(owner, repo, primary["number"], token, title=title, body=body)
    for dup in matches:
        if dup["number"] != primary["number"]:
            github_api.update_issue(owner, repo, dup["number"], token, state="closed")
    return result

#!/usr/bin/env python3
"""Classify git-push / GitHub failures so the ladder never lies with 'no write access'."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PushFailure:
    """Typed push refusal — `reason` drives UX; `detail` is the raw stderr snippet."""
    reason: str
    # reason: workflow_scope | signed_commits | forbidden | auth | network | unknown
    detail: str = ""


def classify_push_stderr(stderr: str | None) -> PushFailure:
    """Map git-push stderr to a stable reason code."""
    text = (stderr or "").strip()
    low = text.lower()
    if not text:
        return PushFailure("unknown", "")
    if ("without `workflow` scope" in low or "without workflow scope" in low
            or "without `workflows` permission" in low
            or "without workflows permission" in low
            or "create or update workflow" in low):
        return PushFailure("workflow_scope", text)
    if "signed" in low and "commit" in low:
        return PushFailure("signed_commits", text)
    if "authentication failed" in low or "invalid username" in low or "403" in low:
        if "workflow" in low:
            return PushFailure("workflow_scope", text)
        return PushFailure("forbidden", text)
    if "could not resolve host" in low or "timed out" in low or "ssl" in low:
        return PushFailure("network", text)
    if "permission" in low or "denied" in low or "read-only" in low:
        return PushFailure("forbidden", text)
    return PushFailure("unknown", text)


def push_failure_message(failure: PushFailure) -> str:
    """One-line operator guidance for a classified push failure."""
    if failure.reason == "workflow_scope":
        return ("rejected: credential lacks Workflows permission — run "
                "`gh auth refresh -h github.com -s repo,workflow` or `saw auth app register`")
    if failure.reason == "signed_commits":
        return "rejected: branch requires signed commits — re-sign the branch, then retry"
    if failure.reason == "forbidden":
        return "rejected: no Contents write access to this repository"
    if failure.reason == "network":
        return "rejected: network/TLS failure talking to GitHub"
    if failure.reason == "auth":
        return "rejected: authentication failed — check the token"
    return "rejected: push failed (see git stderr)"

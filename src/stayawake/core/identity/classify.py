#!/usr/bin/env python3
"""Classify git-push / GitHub failures so the ladder never lies with 'no write access'."""
from __future__ import annotations

import re
from dataclasses import dataclass

NOREPLY_NEXT_STEP = ("commit with your GitHub noreply address: "
                     "`git config --global user.email <id>+<login>@users.noreply.github.com`, "
                     "then run this again")

_LARGEST_STDERR_READ = 8192
_LARGEST_WORDS = 240
_ADDRESS = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,20}://\S{0,2048}")
_CREDENTIAL = re.compile(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{1,255}")
_REJECTED = re.compile(r"!\s{0,8}\[(?:remote )?rejected\][^()\n]{0,512}\(([^()\n]{1,512})\)")


@dataclass(frozen=True)
class PushFailure:
    """Typed push refusal — `reason` drives UX; `detail` is the raw stderr snippet."""
    reason: str
    detail: str = ""


def classify_push_stderr(stderr: str | None) -> PushFailure:
    """Map git-push stderr to a stable reason code."""
    text = (stderr or "").strip()
    low = text.lower()
    if not text:
        return PushFailure("unknown", "")
    if "gh007" in low or "email privacy restrictions" in low:
        return PushFailure("private_email", text)
    # A rule violation or a non-fast-forward is a POLICY result, not an ACCESS one. Both used to
    # fall through to "unknown" and walk the fork ladder, which reports a taken branch as read-only.
    if ("gh013" in low or "gh006" in low or "repository rule violations" in low
            or "non-fast-forward" in low or "fetch first" in low
            or "declined" in low or "updates were rejected" in low):
        return PushFailure("occupied", text)
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
        # Distinguish a bad/expired CREDENTIAL from a valid token that lacks write PERMISSION:
        # `authentication failed` / `invalid username` is git rejecting the credential itself
        # (retrying the same token — incl. a fork push — won't help; the fix is a new token), whereas
        # a bare `403` is an authenticated-but-forbidden push (the token is fine, it lacks Contents
        # write). They want different operator guidance, so they get different reasons. Both still
        # walk the same fork→patch→issue ladder (proposal.submit_change_pr gates that on
        # workflow_scope/signed_commits only), so this changes the MESSAGE, not the fallback path.
        if "authentication failed" in low or "invalid username" in low:
            return PushFailure("auth", text)
        return PushFailure("forbidden", text)
    if "could not resolve host" in low or "timed out" in low or "ssl" in low:
        return PushFailure("network", text)
    if "permission" in low or "denied" in low or "read-only" in low:
        return PushFailure("forbidden", text)
    return PushFailure("unknown", text)


def what_the_remote_said(stderr: str | None) -> str:
    """Read why a push was refused, in the remote's own words. Takes git's output for the push.
    Returns the remote's error lines and each refused ref's reason, joined and bounded, with every
    address and credential taken out, or the last line git printed when there are none."""
    lines = [line.strip() for line in (stderr or "")[-_LARGEST_STDERR_READ:].splitlines() if line.strip()]
    said = [line.split(":", 2)[2].strip() for line in lines if line.lower().startswith("remote: error:")]
    said += [found.group(1).strip() for line in lines for found in [_REJECTED.search(line)] if found]
    if not said:
        said = [line for line in lines if not line.lower().startswith(("to ", "error: failed to push"))][-1:]
    words = "; ".join(dict.fromkeys(said))
    words = _CREDENTIAL.sub("[hidden]", _ADDRESS.sub("[address]", words))
    return words[:_LARGEST_WORDS]


def push_failure_message(failure: PushFailure) -> str:
    """One-line operator guidance for a classified push failure."""
    if failure.reason == "workflow_scope":
        return ("rejected: credential lacks Workflows permission — run "
                "`gh auth refresh -h github.com -s repo,workflow` or `saw auth app register`")
    if failure.reason == "signed_commits":
        return "rejected: branch requires signed commits — re-sign the branch, then retry"
    if failure.reason == "private_email":
        return f"rejected: GitHub keeps your email address private — {NOREPLY_NEXT_STEP}"
    if failure.reason == "occupied":
        return ("rejected by repository policy: the branch is taken or the update is not a "
                "fast-forward — this is not an access problem")
    if failure.reason == "forbidden":
        return "rejected: no Contents write access to this repository"
    if failure.reason == "network":
        return "rejected: network/TLS failure talking to GitHub"
    if failure.reason == "auth":
        return "rejected: authentication failed — check the token"
    return "rejected: push failed (see git stderr)"

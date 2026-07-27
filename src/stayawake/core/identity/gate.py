#!/usr/bin/env python3
"""AuthZ gate — require(intent) before any privileged side effect.

Fail closed on known-missing capabilities (classic OAuth without `workflow`, App without
Workflows write). When capabilities are unknown (fine-grained PAT), allow after liveness and
let delivery classify push failures — never invent a silent "no write access".
"""
from __future__ import annotations

from stayawake.core.identity.capabilities import Capability
from stayawake.core.identity.intents import Intent, requirements
from stayawake.core.identity.outcomes import Decision, UpgradePath, upgrades_for_missing
from stayawake.core.identity.session import Session, resolve_session
from stayawake.lib import auth


def require(intent: Intent, *, session: Session | None = None,
            repo_slug: str | None = None) -> Decision:
    """Authorize `intent`. Call BEFORE clone/worktree/push for that intent.

    Returns an Allow decision only when the session is live and either (a) capabilities are
    known and cover the intent, or (b) capabilities are unknown (fine-grained) so delivery
    must classify residual failures.
    """
    sess = session or resolve_session(repo_slug=repo_slug)
    needed = requirements(intent)

    if not sess.token:
        return Decision(
            allowed=False, intent=intent, missing=needed,
            reason=auth.no_credential_hint(f"{intent.value.replace('_', ' ')}"),
            upgrades=upgrades_for_missing(needed, source=None),
            session_source=None, session_actor=None,
        )

    if not sess.live:
        return Decision(
            allowed=False, intent=intent, missing=needed,
            reason=("GitHub API unreachable or the token was rejected — nothing started. "
                    "Check connectivity/TLS and that the token can reach the repository."),
            upgrades=(UpgradePath(
                kind="login",
                detail="re-authenticate or fix the token",
                command="gh auth status   # or check GH_SECURITY_TOKEN / GH_APP_*",
            ),),
            session_source=sess.source, session_actor=sess.actor,
        )

    if sess.capabilities is None:
        # Unknown powers (fine-grained PAT, Actions token without introspectable perms).
        # Allow past the gate; proposal ladder + push classifier handle residual denies.
        return Decision(
            allowed=True, intent=intent, missing=frozenset(),
            reason="capabilities unknown — proceeding; delivery will classify push failures",
            session_source=sess.source, session_actor=sess.actor,
        )

    missing = frozenset(c for c in needed if c not in sess.capabilities)
    if not missing:
        return Decision(
            allowed=True, intent=intent, missing=frozenset(),
            session_source=sess.source, session_actor=sess.actor,
        )

    reason = _deny_reason(intent, missing, sess)
    return Decision(
        allowed=False, intent=intent, missing=missing, reason=reason,
        upgrades=upgrades_for_missing(missing, source=sess.source),
        session_source=sess.source, session_actor=sess.actor,
    )


def _deny_reason(intent: Intent, missing: frozenset[Capability], sess: Session) -> str:
    who = sess.actor or sess.source or "this credential"
    if Capability.WORKFLOWS_WRITE in missing:
        return (
            f"{who} cannot open a guard/workflow PR: GitHub requires the `workflow` scope "
            f"(classic) or Workflows: Read and write (fine-grained / GitHub App) to create or "
            f"update `.github/workflows/*`. This is NOT missing repo write access."
        )
    names = ", ".join(sorted(c.value for c in missing))
    return f"{who} is not authorized for {intent.value} (missing {names})."

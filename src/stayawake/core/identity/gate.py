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
        return _not_live_decision(intent, sess, needed, repo_slug)

    if sess.capabilities is None:
        # Unknown powers (fine-grained PAT, Actions token without introspectable perms).
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


def _not_live_decision(intent: Intent, sess: Session, needed: frozenset[Capability],
                       repo_slug: str | None) -> Decision:
    """Distinguish a dead/unreachable credential from 'token OK but this repo is out of reach'.

    When `resolve_session(repo_slug=…)` fails liveness, the old path listed every intent
    capability as `missing:` — which looked like a scope problem. If the same token is live
    *without* a repo context, the App/token works; this repo simply isn't reachable (not in
    the App installation, private without access, wrong remote, …).
    """
    who = sess.actor or sess.source or "this credential"
    if repo_slug and "/" in repo_slug and _credential_live_globally(sess.token):
        return Decision(
            allowed=False, intent=intent, missing=frozenset(),
            reason=_repo_unreachable_reason(who, repo_slug, sess),
            upgrades=_repo_unreachable_upgrades(sess, repo_slug),
            session_source=sess.source, session_actor=sess.actor,
        )
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


def _credential_live_globally(token: str | None) -> bool:
    """True when the token is accepted by GitHub with no repo context (rate_limit /user)."""
    if not token:
        return False
    try:
        from stayawake.lib.adapters import github_api
        return bool(github_api.token_is_valid(token, repo_slug=None))
    except Exception:  # noqa: BLE001 — probe must not raise into the gate
        return False


def _repo_unreachable_reason(who: str, repo_slug: str, sess: Session) -> str:
    if sess.source == "github-app" or sess.kind == "app_installation":
        owner = repo_slug.split("/", 1)[0]
        return (
            f"{who} cannot access {repo_slug} — the StayAwakeBot App is not installed on '{owner}' "
            f"(or is installed there with 'Only select repositories' that excludes this repo). A "
            f"GitHub App is per-account, so each account/org needs its own installation. This is NOT "
            f"missing write scopes."
        )
    return (
        f"{who} cannot access {repo_slug} — the credential is live but GitHub rejected "
        f"access to that repository (private without permission, SSO, or a bad remote). "
        f"This is NOT missing write scopes."
    )


def _repo_unreachable_upgrades(sess: Session, repo_slug: str) -> tuple[UpgradePath, ...]:
    if sess.source == "github-app" or sess.kind == "app_installation":
        owner = repo_slug.split("/", 1)[0]
        paths: list[UpgradePath] = [
            UpgradePath(
                kind="register_app",
                detail=f"install the StayAwakeBot App on '{owner}' (or add {repo_slug} to its "
                       f"selected repositories)",
                command=_app_install_command(owner),
            ),
            UpgradePath(
                kind="pat_scopes",
                detail="confirm `git remote -v` points at the intended owner/repo",
            ),
        ]
        return tuple(paths)
    return (
        UpgradePath(
            kind="login",
            detail=f"grant this credential access to {repo_slug} (or fix the remote)",
            command="gh auth status   # or check GH_SECURITY_TOKEN",
        ),
    )


def _app_install_command(owner: str) -> str:
    """Best-effort URL to install the App on `owner` (the concrete multi-account unblock) — a GitHub
    App is per-account, so an org repo needs the App installed on that org, not on the personal one."""
    try:
        from stayawake.lib import github_app
        slug = (github_app.load_config() or {}).get("slug")
        if slug:
            return f"open https://github.com/apps/{slug}/installations/new"
    except Exception:  # noqa: BLE001
        pass
    return "open https://github.com/settings/installations"


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

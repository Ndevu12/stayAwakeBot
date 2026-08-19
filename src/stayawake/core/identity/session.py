#!/usr/bin/env python3
"""Credential session — AuthN result the AuthZ gate reasons about."""
from __future__ import annotations

from dataclasses import dataclass, field

from stayawake.core.identity.capabilities import (
    Capability, capabilities_from_app_permissions, capabilities_from_oauth_scopes,
)
from stayawake.lib import auth
from stayawake.lib.adapters import github_api


@dataclass
class Session:
    """Resolved credential + what we know about its powers.

    `capabilities` is None when we cannot derive them (fine-grained PAT / unknown) — the gate
    then allows only after liveness, and delivery classifies residual push failures.
    When capabilities ARE known (classic OAuth scopes or App installation permissions), the
    gate can Deny early (e.g. missing `workflow`) before any clone/worktree work.
    """
    token: str | None
    source: str | None
    kind: str
    actor: str | None = None
    capabilities: frozenset[Capability] | None = None
    scopes: frozenset[str] | None = None
    live: bool = False
    detail: str = ""


def resolve_session(*, repo_slug: str | None = None, hostname: str = "github.com") -> Session:
    """Resolve the active credential into a Session (AuthN + best-effort capability probe).

    `repo_slug` targets a specific repo: for a GitHub App it selects the installation that owns that
    repo (multi-account), and it sharpens the liveness probe to that repo."""
    token, source = auth.resolve_token(hostname, repo_slug=repo_slug)
    if not token:
        return Session(token=None, source=None, kind="none", live=False,
                       detail="no GitHub credential")

    live = github_api.token_is_valid(token, repo_slug)
    kind = "user"
    actor = None
    caps: frozenset[Capability] | None = None
    scopes: frozenset[str] | None = None

    if source == "github-app" or (source == "GITHUB_TOKEN"):
        kind = "actions" if source == "GITHUB_TOKEN" else "app_installation"
        perms = github_api.installation_permissions(token)
        if perms is not None:
            caps = capabilities_from_app_permissions(perms)
        # Installation tokens have no /user; actor from cached app config when available.
        from stayawake.lib import github_app
        actor = github_app.installation_actor_label()
    else:
        user = github_api.get_authenticated_user(token, quiet=True)
        if user and user.get("login"):
            actor = user["login"]
        scopes = github_api.oauth_scopes(token)
        if scopes is not None:
            caps = capabilities_from_oauth_scopes(scopes)
            # Classic tokens with `repo` still need an explicit `workflow` for workflow files —
            # capabilities_from_oauth_scopes already handles that (workflow scope separate).

    return Session(token=token, source=source, kind=kind, actor=actor,
                   capabilities=caps, scopes=scopes, live=live,
                   detail="" if live else "token rejected or API unreachable")

#!/usr/bin/env python3
"""Two preconditions for rewriting published history, answered without ever raising.

A force-update replaces commits that other clones already carry: every fetcher of the old SHA
diverges, and signed history is broken. A token that can PUSH does not establish the right to do
that — pushing adds to a branch, rewriting takes something away from everyone who has it. So this
module answers the two questions a force-update path must ask first:

    may_rewrite(slug, token)             — does this identity OWN the repo, or hold ADMIN on it?
    ref_protection(slug, branch, token)  — is the target ref protected, and what does the rule say?

Both fail CLOSED and degrade HONESTLY. A 403 / 404 / rate-limit / network failure is reported as
UNDETERMINED (`Authority.conclusive is False`, `Protection.protected is None`) — never as "not
permitted, definitely" and never as "not protected", because a caller that reads an unreadable
rule as "no rule" force-pushes over exactly the branch it should have refused.

Nothing here puts the credential in argv, a log line, or an exception: it travels only as an
Authorization header inside the adapter, and no remote-supplied text is copied into a result.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

from stayawake.lib.adapters import github_api
from stayawake.lib.adapters.github_api import ApiRead

# Reason/detail for every way an API read can fail. Mapping the cause to OUR sentence — rather than
# passing `ApiRead.detail` through — is deliberate: that field is the raw response body (and, on the
# network path, an exception string), i.e. remote-controlled text on its way to operator output.
_FAILURE_REASON: dict[str, str] = {
    "not_found": "not_found",
    "unauthorized": "unauthorized",
    "forbidden": "forbidden",
    "rate_limited": "rate_limited",
    "network": "network_error",
    "http_error": "api_error",
}
_FAILURE_DETAIL: dict[str, str] = {
    "not_found": "GitHub returned 404 — the repository or ref is not visible to this credential",
    "unauthorized": "GitHub rejected the credential (401)",
    "forbidden": "GitHub returned 403 — this credential may not read that",
    "rate_limited": "the GitHub API rate limit is exhausted",
    "network_error": "the GitHub API could not be reached",
    "api_error": "the GitHub API returned an unexpected status",
}


@dataclass(frozen=True)
class Authority:
    """Whether an identity may rewrite this repository's history, and why we say so.

    `permitted` is the answer; `conclusive` says whether we could actually determine it. A refusal
    with `conclusive=False` means "we could not tell" (403 / 404 / rate limit / network / no
    permissions block) — a retry or a better credential may change it — and must never be reported
    as "you definitely lack authority".

    reason ∈ permitted: `owner` · `admin`
            refused, conclusive: `no_credential` · `malformed_slug` · `push_without_admin` ·
                                 `no_admin_permission`
            refused, undetermined: `permissions_unknown` · `unreadable_repo` · `not_found` ·
                                 `unauthorized` · `forbidden` · `rate_limited` · `network_error` ·
                                 `api_error`
    """
    permitted: bool
    reason: str
    detail: str = ""
    login: str | None = None
    owner: str | None = None
    conclusive: bool = True


@dataclass(frozen=True)
class Protection:
    """What the protection rule on one ref establishes. `None` means UNKNOWN, never "no".

    `protected` comes from the branch object, which needs no admin. The rule's contents usually do,
    so `requires_signed_commits` / `allows_force_push` stay None when the protection object cannot
    be read — the branch is still known to be protected.

    An unprotected branch leaves both rule fields None rather than False: `protected` reflects
    classic branch protection, while a repository ruleset or an organisation rule can require
    signatures or block a force-push without it, so "no classic protection" is not evidence the
    push is allowed.

    reason ∈ `rule_read` · `rule_unreadable` · `not_protected` · `no_credential` ·
             `malformed_slug` · `malformed_branch` · `unreadable_branch` · `protection_absent` ·
             `not_found` · `unauthorized` · `forbidden` · `rate_limited` · `network_error` ·
             `api_error`
    """
    protected: bool | None
    requires_signed_commits: bool | None
    allows_force_push: bool | None
    reason: str
    detail: str = ""

    @property
    def undetermined(self) -> bool:
        """We could not establish whether the ref is protected — refuse rather than proceed."""
        return self.protected is None


def may_rewrite(slug: str, token: str | None) -> Authority:
    """May the identity behind `token` rewrite `owner/name`'s history?

    Permitted only when the authenticated login IS the repository owner, or the repository reports
    `permissions.admin` for this credential. `push` is explicitly not enough. Never raises.
    """
    if not token:
        return Authority(False, "no_credential", "no GitHub credential is available")
    parts = _split_slug(slug)
    if parts is None:
        return Authority(False, "malformed_slug", "the repository slug is not 'owner/name'")
    owner, name = parts

    repo = _read(f"/repos/{_seg(owner)}/{_seg(name)}", token)
    if repo.cause is not None:
        return Authority(False, *_failure(repo.cause), conclusive=False)
    if not isinstance(repo.value, dict):
        return Authority(False, "unreadable_repo", "GitHub did not return a repository object",
                         conclusive=False)

    owner_login = _owner_login(repo.value)
    login = _authenticated_login(token)
    if login and owner_login and login.casefold() == owner_login.casefold():
        return Authority(True, "owner", "the credential owns the repository",
                         login=login, owner=owner_login)

    permissions = repo.value.get("permissions")
    if not isinstance(permissions, dict):
        return Authority(False, "permissions_unknown",
                         "GitHub returned no permissions for this credential, so admin could not "
                         "be established", login=login, owner=owner_login, conclusive=False)
    if permissions.get("admin") is True:
        return Authority(True, "admin", "the credential holds admin on the repository",
                         login=login, owner=owner_login)
    if permissions.get("push") is True:
        return Authority(False, "push_without_admin",
                         "the credential can push but does not own the repository and has no "
                         "admin — that is not authority to rewrite history",
                         login=login, owner=owner_login)
    return Authority(False, "no_admin_permission",
                     "the credential neither owns the repository nor holds admin on it",
                     login=login, owner=owner_login)


def fork_count(slug: str, token: str | None) -> int | None:
    """How many forks `owner/name` has, or None when that could not be established.

    A force-update removes nothing from a fork, so this decides whether the operator still has
    work after every branch has moved. None and a positive count both mean they do; only a read
    that came back zero settles it. Reported as a count rather than a guess so a run on a repo
    nobody forked stops carrying a warning that fires every time and therefore says nothing.
    """
    if not token:
        return None
    parts = _split_slug(slug)
    if parts is None:
        return None
    owner, name = parts
    repo = _read(f"/repos/{_seg(owner)}/{_seg(name)}", token)
    if repo.cause is not None or not isinstance(repo.value, dict):
        return None
    forks = repo.value.get("forks_count")
    return forks if isinstance(forks, int) and not isinstance(forks, bool) and forks >= 0 else None


def ref_protection(slug: str, branch: str, token: str | None) -> Protection:
    """What protects `branch` on `owner/name` — protected at all, signatures required, force-push
    allowed. Unreadable rules come back as None (unknown), never as "not protected". Never raises.
    """
    parts = _split_slug(slug)
    if parts is None:
        return Protection(None, None, None, "malformed_slug",
                          "the repository slug is not 'owner/name'")
    if not branch or branch.strip() != branch:
        return Protection(None, None, None, "malformed_branch", "the branch name is not usable")
    owner, name = parts
    ref_path = f"/repos/{_seg(owner)}/{_seg(name)}/branches/{_ref_seg(branch)}"

    ref = _read(ref_path, token)
    if ref.cause is not None:
        return Protection(None, None, None, *_failure(ref.cause))
    if not isinstance(ref.value, dict):
        return Protection(None, None, None, "unreadable_branch",
                          "GitHub did not return a branch object")
    protected = ref.value.get("protected")
    if protected is False:
        return Protection(False, None, None, "not_protected",
                          "the branch carries no classic branch protection")
    if protected is not True:
        return Protection(None, None, None, "protection_absent",
                          "the branch object did not state whether it is protected")

    rule = _read(f"{ref_path}/protection", token)
    if rule.cause is not None or not isinstance(rule.value, dict):
        cause_detail = _failure(rule.cause)[1] if rule.cause else "GitHub returned no rule object"
        return Protection(True, None, None, "rule_unreadable",
                          f"the branch is protected but the rule could not be read: {cause_detail}")
    locked = _enabled(rule.value, "lock_branch")
    allows_force_push = False if locked is True else _enabled(rule.value, "allow_force_pushes")
    return Protection(True, _enabled(rule.value, "required_signatures"), allows_force_push,
                      "rule_read", "the branch is protected and its rule was read")


def _read(path: str, token: str | None) -> ApiRead:
    """The one seam onto the GitHub adapter. `_do_request` rather than the public `request()`
    because the latter collapses every failure to `None`, and `get_branch_protection()` maps a 403
    to "unprotected" — the exact fail-open this module exists to avoid."""
    return github_api._do_request(path, token=token)


def _authenticated_login(token: str | None) -> str | None:
    """The login `token` authenticates as, or None. None is expected, not an error: `GET /user` is
    forbidden to a GitHub App installation token, which then has to qualify via admin instead."""
    me = _read("/user", token)
    if me.cause is None and isinstance(me.value, dict):
        login = me.value.get("login")
        if isinstance(login, str) and login:
            return login
    return None


def _owner_login(repo: dict) -> str | None:
    owner = repo.get("owner")
    login = owner.get("login") if isinstance(owner, dict) else None
    return login if isinstance(login, str) and login else None


def _failure(cause: str | None) -> tuple[str, str]:
    reason = _FAILURE_REASON.get(cause or "", "api_error")
    return reason, _FAILURE_DETAIL[reason]


def _enabled(rule: dict, key: str) -> bool | None:
    """`{"<key>": {"enabled": bool}}` → the bool; an absent or oddly-shaped node → unknown."""
    node = rule.get(key)
    if isinstance(node, dict) and isinstance(node.get("enabled"), bool):
        return node["enabled"]
    return None


def _split_slug(slug: str) -> tuple[str, str] | None:
    if not isinstance(slug, str) or slug.count("/") != 1:
        return None
    owner, _, name = slug.partition("/")
    if not owner or not name or owner.strip() != owner or name.strip() != name:
        return None
    return owner, name


def _seg(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _ref_seg(branch: str) -> str:
    """A branch name is one greedy path segment on `/branches/{branch}`, so '/' stays literal
    while '?', '#' and friends are escaped out of the query/fragment positions."""
    return urllib.parse.quote(branch, safe="/")

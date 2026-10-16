#!/usr/bin/env python3
"""The identity saw commits under when the commit will be published to GitHub: the operator's
configured name, with the GitHub account's noreply address in place of an address of their own."""
from __future__ import annotations

import re
from collections.abc import Callable

from stayawake.lib.adapters.github_api import get_authenticated_user

NOREPLY_DOMAIN = "users.noreply.github.com"
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")


def keeps_the_address_private(email: str) -> bool:
    """Tell whether an email address is one of GitHub's noreply addresses. Takes the address. Returns
    the answer."""
    return email.strip().lower().endswith("@" + NOREPLY_DOMAIN)


def noreply_address(account) -> str | None:
    """Write a GitHub account's ID-based noreply address. Takes the account as GitHub's API returns it.
    Returns the address, or None when the account carries no usable id and login."""
    if not isinstance(account, dict):
        return None
    account_id, login = account.get("id"), account.get("login")
    if isinstance(account_id, bool) or not isinstance(account_id, int) or account_id <= 0:
        return None
    if not isinstance(login, str) or not _LOGIN.fullmatch(login):
        return None
    return f"{account_id}+{login}@{NOREPLY_DOMAIN}"


def publishing_identity(configured: tuple[str, str], token: str | None, *,
                        account_of: Callable | None = None) -> tuple[str, str]:
    """Choose the name and email saw commits under for a commit it will publish to GitHub. Takes the
    configured name and email, the token saw holds and the reader of the token's account (GitHub's,
    when not given). Returns the configured name with the account's noreply address, or the configured
    identity unchanged when its address already is a noreply address or the account cannot be read."""
    name, email = configured
    if keeps_the_address_private(email) or not token:
        return configured
    address = noreply_address((account_of or get_authenticated_user)(token, quiet=True))
    return (name, address) if address else configured

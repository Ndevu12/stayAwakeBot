#!/usr/bin/env python3
"""Name who a rewrite is committed under, and the key that signs for that identity."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from stayawake.lib.signing.commits.config import config_value
from stayawake.lib.signing.commits.decision import SigningStatus



def committer_identity(repo: str | Path) -> tuple[str, str] | None:
    """The name and email the rewrite will be committed under, or None when the repository
    resolves neither.

    A rewrite attributed to a guessed identity is not a record of who made it. With nothing
    configured git invents one from the host on a workstation and refuses outright on a bare CI
    runner, so which of the two an operator gets depends on the machine — the caller refuses
    instead, on every machine.
    """
    name = config_value(repo, "user.name")
    email = config_value(repo, "user.email")
    return (name, email) if name and email else None


def signer_pinned(status: SigningStatus, configured: tuple[str, str]) -> SigningStatus:
    """Name the signing key by the configured identity, for commits made under another committer
    address. Takes the signing decision and the configured name and email. Returns the decision with
    `user.signingkey` set to the identity git would have named the key by, or unchanged when no
    signature is made, a key is already named, or the format names its key another way."""
    held = dict(status.config)
    if not status.available or held.get("user.signingkey") or status.signature_format == "ssh":
        return status
    name, email = configured
    return replace(status, config=tuple(sorted({**held, "user.signingkey": f"{name} <{email}>"}.items())))

#!/usr/bin/env python3
"""A signing key the operator already has, read from an OpenSSH public key."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SigningKey:
    """A key on this machine that can sign a commit."""

    public_key: str
    signing_key: str
    found_in: str


def public_key_of(line: str) -> str | None:
    """Read the key type and body of an OpenSSH public key line. Returns them joined by one space, or
    None when the line holds no public key."""
    fields = (line or "").split()
    if len(fields) < 2 or not fields[0].startswith(("ssh-", "ecdsa-", "sk-")):
        return None
    return f"{fields[0]} {fields[1]}"


def agent_signing_key(public_key: str) -> str:
    """Name a key that ssh-agent holds the way git's `user.signingkey` takes it. Takes the public key.
    Returns the value to set."""
    return public_key if public_key.startswith("ssh-") else f"key::{public_key}"

#!/usr/bin/env python3
"""A remote's address read as data from a repository and checked against
`contexts.OPERATOR_TRANSPORTS`, and an `ls-remote` run from no repository."""
from __future__ import annotations

import re
from pathlib import Path

from stayawake.lib.git import contexts
from stayawake.lib.git.run import NETWORK_TIMEOUT, OPERATOR_PUSH, UNTRUSTED, run, stdout

_HELPER_TRANSPORT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.-]*::")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
_PROTOCOL_OF_SCHEME = {"https": "https", "http": "http", "ssh": "ssh", "git+ssh": "ssh",
                       "ssh+git": "ssh", "git": "git", "file": "file"}


def transport_of(url: str) -> str | None:
    """The protocol git would use for `url` (`https`, `ssh`, `file`, …), or None for a form git
    hands to a helper program or that is not an address at all."""
    if not url or url != url.strip() or any(ord(c) < 32 for c in url):
        return None
    if _HELPER_TRANSPORT.match(url):
        return None
    scheme = _SCHEME.match(url)
    if scheme:
        return _PROTOCOL_OF_SCHEME.get(scheme.group(1).lower())
    head, colon, _rest = url.partition(":")
    if colon and "/" not in head:
        host = head.rsplit("@", 1)[-1]
        return None if not host or host.startswith("-") or head.startswith("-") else "ssh"
    return "file"


def checked_url(url: str | None) -> str | None:
    """`url` when git may be pointed at it for a push, fetch or listing, else None."""
    if url is None or url.startswith("-"):
        return None
    return url if transport_of(url) in contexts.OPERATOR_TRANSPORTS else None


def remote_url(repo: str | Path, name: str = "origin", *, for_push: bool = False) -> str | None:
    """The checked address of remote `name` in `repo`, or None when it has none git may use.
    `for_push` prefers `remote.<name>.pushurl`, as `git push` does."""
    keys = ([f"remote.{name}.pushurl"] if for_push else []) + [f"remote.{name}.url"]
    for key in keys:
        value = stdout(repo, ["config", "--get", key], context=UNTRUSTED).strip()
        if value:
            return checked_url(value)
    return None


def resolve(remote: str, repo: str | Path | None, *, for_push: bool = False) -> str | None:
    """`remote` as a checked URL: a name is looked up in `repo`, anything else is taken as a URL."""
    if repo is not None and re.fullmatch(r"[A-Za-z0-9._-]+", remote or ""):
        return remote_url(repo, remote, for_push=for_push)
    return checked_url(remote)


def ls_remote(url: str, args: list[str], *, env: dict | None = None):
    """`git ls-remote <args> <url>` run from no repository.
    Returns the CompletedProcess, or None when `url` is refused or git could not run."""
    if checked_url(url) is None:
        return None
    head, tail = [a for a in args if a.startswith("-")], [a for a in args if not a.startswith("-")]
    return run(None, ["ls-remote", *head, "--", url, *tail], env=env,
               timeout=NETWORK_TIMEOUT, context=OPERATOR_PUSH)

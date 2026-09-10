#!/usr/bin/env python3
"""Credential-safe GitHub remote access — HTTPS with the token kept out of argv/URLs/logs, and
SSH as an added reach when HTTPS cannot get to a repository."""
from __future__ import annotations

import contextlib
import os
import stat
import tempfile

_HOST = "github.com"
_SSH_COMMAND = "ssh -o BatchMode=yes -o ConnectTimeout=15"
_transport: dict[str, str] = {}


@contextlib.contextmanager
def github_https_auth(token: str | None):
    """Yield (url_prefix, env) for authenticated GitHub HTTPS that keeps the token OUT of
    the URL and process args — so it can't leak via argv, `ps`, git's own error output,
    or anything we might log.

    With a token (POSIX), GIT_ASKPASS points at a throwaway 0700 script that reads the
    token from the child env, and the URL prefix carries only the username
    (`https://x-access-token@github.com/`). The secret therefore lives only in the child
    environment, never in argv/URLs/files. On Windows (no POSIX askpass) and when there
    is no token, it falls back to the prior behaviour.

        with github_https_auth(token) as (prefix, env):
            subprocess.run(["git", "clone", f"{prefix}{slug}.git", dst], env=env, ...)
    """
    base_env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
    if not token:
        yield f"https://{_HOST}/", base_env
        return
    if os.name == "nt":  # no /bin/sh askpass on native Windows — keep credential-in-URL
        yield f"https://x-access-token:{token}@{_HOST}/", base_env
        return
    fd, path = tempfile.mkstemp(prefix="sab-askpass-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("#!/bin/sh\n"
                    'case "$1" in\n'
                    "  Username*) printf %s 'x-access-token' ;;\n"
                    '  *) printf %s "$SAB_GH_TOKEN" ;;\n'
                    "esac\n")
        os.chmod(path, stat.S_IRWXU)  # 0700: only this user can read/exec the helper
        env = dict(base_env, GIT_ASKPASS=path, SAB_GH_TOKEN=token)
        yield f"https://x-access-token@{_HOST}/", env
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _ssh_env() -> dict:
    """A child env for SSH git that never prompts (batch mode, bounded connect)."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_EDITOR="true")
    env.setdefault("GIT_SSH_COMMAND", _SSH_COMMAND)
    return env


def _order(slug: str) -> list[str]:
    """The transports to try for `slug`, the last one that worked first, else HTTPS then SSH."""
    order = ["https", "ssh"]
    cached = _transport.get(slug)
    return [cached] + [k for k in order if k != cached] if cached else order


def run_remote_git(slug: str, token: str | None, attempt):
    """Reach `github.com/<slug>` over HTTPS (token), then SSH on failure, caching the transport
    that works so the next call tries it first. `attempt(url, env)` runs the op — the caller keeps
    its own runner, so this decides only the transport. Returns the first result whose `returncode`
    is 0, else the last (or None)."""
    last = None
    for kind in _order(slug):
        if kind == "ssh":
            last = attempt(f"git@{_HOST}:{slug}.git", _ssh_env())
        else:
            with github_https_auth(token) as (prefix, env):
                last = attempt(f"{prefix}{slug}.git", env)
        if last is not None and getattr(last, "returncode", 1) == 0:
            _transport[slug] = kind
            return last
    return last


@contextlib.contextmanager
def github_remote(slug: str, token: str | None):
    """Yield `(url, env)` for reaching `github.com/<slug>` over the transport that last worked
    (HTTPS with the token, else SSH), for a caller that builds its own command instead of running
    one through `run_remote_git`."""
    if _transport.get(slug) == "ssh":
        yield f"git@{_HOST}:{slug}.git", _ssh_env()
        return
    with github_https_auth(token) as (prefix, env):
        yield f"{prefix}{slug}.git", env

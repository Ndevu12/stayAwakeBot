#!/usr/bin/env python3
"""Credential-safe GitHub HTTPS — keep the token out of argv, URLs, `ps`, and logs."""
from __future__ import annotations

import contextlib
import os
import stat
import tempfile

_HOST = "github.com"


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

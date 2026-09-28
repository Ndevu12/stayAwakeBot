#!/usr/bin/env python3
"""The one place a `git` subprocess is executed.

Every command runs under a context (`contexts`) that fixes which configuration and environment it
sees, and is judged against that context's allowlist (`allowlist`) before it runs. The default is
`UNTRUSTED`: a repository saw did not create never gets to run code through saw's git. A refused
command is a defect in saw, so it is reported on stderr and answered as a failure (`None`), or raised
as `GitRefused` when `allowlist.RAISE_ON_REFUSAL` is set, as the test suite sets it.
"""
from __future__ import annotations

import contextlib
import contextvars
import subprocess
import sys
from pathlib import Path

from stayawake.lib.git import allowlist, owned
from stayawake.lib.git.allowlist import GitRefused
from stayawake.lib.git.contexts import (Context, UNTRUSTED, SAW_OWNED, OPERATOR_PUSH,
                                        OPERATOR_CONFIG, child_env, config_prefix, neutral_dir)

__all__ = ["run", "run_ok", "stdout", "stdout_bytes", "stdout_bytes_fed", "open_stdout",
           "GitRefused", "UNTRUSTED", "SAW_OWNED", "OPERATOR_PUSH", "OPERATOR_CONFIG",
           "LOCAL_TIMEOUT", "NETWORK_TIMEOUT"]

LOCAL_TIMEOUT = 60
NETWORK_TIMEOUT = 180
_NO_DIFF_DRIVERS = ["--no-textconv", "--no-ext-diff"]



def _refuse(context: Context, args: list[str], why: str) -> None:
    message = f"saw refused to run git {' '.join(args[:3])} as {context!r}: {why}"
    if allowlist.RAISE_ON_REFUSAL:
        raise GitRefused(message)
    print(f"saw: {message} — this is a defect in saw; please report it", file=sys.stderr)


def _prepare(repo: str | Path | None, args: list[str], env: dict | None,
             context: Context) -> tuple[list[str], dict, str | None] | None:
    """Build the argv, environment and working directory for one command, or None when it is
    refused. Takes the repo, the arguments, the caller's environment and the context."""
    if context.repository == "none" and repo is not None:
        _refuse(context, args, "runs outside any repository, so a repository's configuration is "
                               "never read")
        return None
    if (context.repository == "owned-or-none" and repo is not None
            and not owned.is_owned(repo)):
        _refuse(context, args, f"{repo} is not a repository this run created")
        return None
    verdict = allowlist.judge(context, list(args), env)
    if verdict.refusal:
        _refuse(context, args, verdict.refusal)
        return None
    callers_globals, sub, rest = allowlist.split(list(args))
    if context in (UNTRUSTED, SAW_OWNED) and sub in allowlist.DIFF_SUBCOMMANDS:
        rest = _NO_DIFF_DRIVERS + rest
    argv = ["git"]
    if repo is not None:
        argv += ["-C", str(repo)]
    if not verdict.reads_configuration:
        argv += config_prefix(context)
    argv += callers_globals + [sub] + rest
    child = child_env(context, env,
                      operator_scopes=True if verdict.reads_configuration else None,
                      repository_less=repo is None)
    return argv, child, (str(neutral_dir()) if repo is None else None)


_STALLED = contextvars.ContextVar("saw_git_stalled", default=None)


@contextlib.contextmanager
def stalls_recorded():
    """Within the block, every git command that does not answer in time is recorded, while it
    still answers None to its caller. Yields the list the records go into."""
    stalled: list[str] = []
    token = _STALLED.set(stalled)
    try:
        yield stalled
    finally:
        _STALLED.reset(token)


def _stalled(args: list[str], timeout) -> None:
    """Record a git command that did not answer in time. Takes its arguments and the timeout."""
    record = _STALLED.get()
    if record is not None:
        record.append(f"git {args[0] if args else ''} did not answer within {timeout}s")


def run(repo: str | Path | None, args: list[str], *, env: dict | None = None,
        timeout: int | None = LOCAL_TIMEOUT, context: Context = UNTRUSTED,
        input_text: str | None = None) -> subprocess.CompletedProcess | None:
    """Run a git command in `repo` under `context`, with `input_text` on its stdin; return the
    CompletedProcess, or None when git could not run or the command was refused. `repo=None` runs
    from a saw-owned empty directory, for commands that name their target explicitly (a URL, a
    destination, the global configuration).

    The return code and stdout are exposed even on a non-zero exit (`merge-tree` exits 1 on a
    conflict yet prints the tree); output decodes with `errors="replace"`.
    """
    prepared = _prepare(repo, args, env, context)
    if prepared is None:
        return None
    argv, child, cwd = prepared
    try:
        return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              timeout=timeout, check=False, env=child, cwd=cwd, input=input_text)
    except subprocess.TimeoutExpired:
        _stalled(args, timeout)
        return None
    except (subprocess.SubprocessError, OSError):
        return None


def run_ok(repo: str | Path | None, args: list[str], *, env: dict | None = None,
           timeout: int = LOCAL_TIMEOUT, context: Context = UNTRUSTED) -> bool:
    """True iff the git command ran and exited 0 — the checked form."""
    res = run(repo, args, env=env, timeout=timeout, context=context)
    return res is not None and res.returncode == 0


def stdout_bytes_fed(repo: str | Path | None, args: list[str], stdin: bytes, *,
                     env: dict | None = None, context: Context = UNTRUSTED) -> bytes | None:
    """Run a git command with `stdin` written to it. Returns its raw stdout, or None on any failure."""
    prepared = _prepare(repo, args, env, context)
    if prepared is None:
        return None
    argv, child, cwd = prepared
    try:
        res = subprocess.run(argv, input=stdin, capture_output=True, timeout=LOCAL_TIMEOUT,
                             env=child, cwd=cwd)
    except subprocess.TimeoutExpired:
        _stalled(args, LOCAL_TIMEOUT)
        return None
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout if res.returncode == 0 else None


def stdout_bytes(repo: str | Path | None, args: list[str], *,
                 context: Context = UNTRUSTED) -> bytes | None:
    """Raw stdout, undecoded — None on any failure. For content whose BYTES are the thing, such as a
    commit message in a legacy encoding."""
    prepared = _prepare(repo, args, None, context)
    if prepared is None:
        return None
    argv, child, cwd = prepared
    try:
        res = subprocess.run(argv, capture_output=True, timeout=LOCAL_TIMEOUT, env=child, cwd=cwd)
    except subprocess.TimeoutExpired:
        _stalled(args, LOCAL_TIMEOUT)
        return None
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout if res.returncode == 0 else None


def open_stdout(repo: str | Path | None, args: list[str], *,
                context: Context = UNTRUSTED) -> subprocess.Popen | None:
    """Start a git command whose stdout the caller streams. Returns the process, or None when it was
    refused or could not start. The caller owns the process and must wait for or kill it."""
    prepared = _prepare(repo, args, None, context)
    if prepared is None:
        return None
    argv, child, cwd = prepared
    try:
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=child, cwd=cwd)
    except (OSError, subprocess.SubprocessError):
        return None


def stdout(repo: str | Path | None, args: list[str], *, context: Context = UNTRUSTED) -> str:
    """Run a git command; return its stdout ('' on any failure)."""
    res = run(repo, args, context=context)
    return res.stdout if (res is not None and res.returncode == 0) else ""

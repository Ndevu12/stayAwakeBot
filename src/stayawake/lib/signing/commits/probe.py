#!/usr/bin/env python3
"""Prove that a repository's signing settings can make a signature."""
from __future__ import annotations

import os
import shutil
from collections.abc import Mapping
from pathlib import Path

from stayawake.lib.git import owned
from stayawake.lib.git.run import SAW_OWNED, run, run_ok
from stayawake.utils import scratch


PROBE_TIMEOUT = 10


_PROBE_IDENTITY = {"user.name": "saw signing probe", "user.email": "probe@stayawake.local"}


def first_probe_failure(config: Mapping[str, str]) -> str | None:
    """Make a throwaway signature with the signing settings `config`. Returns why it could not be
    made, or None when it was."""
    probe = scratch.new_dir("a signing probe")
    try:
        if not run_ok(None, ["init", "-q", "-b", "main", "--template=", str(probe)],
                      timeout=PROBE_TIMEOUT, context=SAW_OWNED):
            return "a probe repository could not be created"
        owned.own(probe)
        overrides = [arg
                     for key, value in {**_PROBE_IDENTITY, **config}.items()
                     for arg in ("-c", f"{key}={value}")]
        res = run(probe, [*overrides, "commit", "--allow-empty", "-q",
                          "-m", "saw signing probe", "-S"],
                  env=refuse_to_prompt(dict(os.environ)), timeout=PROBE_TIMEOUT,
                  context=SAW_OWNED)
        if res is None:
            return f"the signing attempt did not finish within {PROBE_TIMEOUT}s"
        if res.returncode != 0:
            return _first_line(res.stderr) or "the signing attempt failed"
        if not _has_signature_header(probe):
            return "the probe commit was created but carried no signature"
        return None
    finally:
        owned.disown(probe)
        shutil.rmtree(probe, ignore_errors=True)


def _has_signature_header(probe: Path) -> bool:
    """A signature on the object, not merely a zero exit. Only the header block is inspected, so
    a commit *message* mentioning gpgsig cannot stand in for a signature."""
    res = run(probe, ["cat-file", "commit", "HEAD"], timeout=PROBE_TIMEOUT, context=SAW_OWNED)
    if res is None or res.returncode != 0:
        return False
    headers = res.stdout.split("\n\n", 1)[0]
    return any(line.startswith("gpgsig") for line in headers.splitlines())


def refuse_to_prompt(env: dict) -> dict:
    """Make a signing attempt fail instead of asking for a passphrase. Takes the environment it runs
    in. Returns that environment, changed."""
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["SSH_ASKPASS"] = "/nonexistent/saw-refuses-to-prompt"
    env.pop("GPG_TTY", None)
    return env


def _first_line(text: str) -> str:
    """git puts the cause first (`error: Couldn't load public key ...`) and the consequence last
    (`fatal: failed to write commit object`), so the first line is the one an operator needs."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""

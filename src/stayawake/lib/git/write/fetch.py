#!/usr/bin/env python3
"""Refresh a remote ref before building the fix, so the base is `origin/<default>` at its
newest rather than a stale local copy."""
from __future__ import annotations

from pathlib import Path

from stayawake.lib.git.run import run_ok, NETWORK_TIMEOUT


def fetch(repo: str | Path, remote: str, ref: str) -> bool:
    """`git fetch --quiet <remote> <ref>`. Best-effort: the caller falls back to the local
    base when this fails (offline), but routing it here gives it the network timeout so a hung
    fetch can't stall the sweep."""
    return run_ok(repo, ["fetch", "--quiet", remote, ref], timeout=NETWORK_TIMEOUT)

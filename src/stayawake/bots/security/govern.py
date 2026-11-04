#!/usr/bin/env python3
"""`saw govern` core — check an incoming git or GitHub update in a holding directory, before the
operator's open folder changes.

`prepare` carries out the operator's incoming command so its result exists only in a saw-owned
holding directory, scans what arrived, and returns a verdict. `apply` makes the open folder match
that already-scanned tree, without fetching again. The open folder is untouched until apply, and
nothing from the incoming repository runs — its hooks, filters and configuration are not honoured.
"""
from __future__ import annotations

SCHEMA = 1

TOOLS = ("gh", "git")

# Subcommands that bring files in. An alias is never sent here, and a command that brings nothing
# in (status, commit, push, pr view) is not sent here either.
_GIT_INBOUND = frozenset({"pull", "fetch", "merge", "rebase", "checkout", "switch"})
_GIT_SUBMODULE_UPDATE = ("submodule", "update")
_GH_INBOUND = frozenset({("pr", "checkout"), ("repo", "sync"), ("release", "download"),
                         ("run", "download")})


def is_recognised(tool: str, args: list[str]) -> bool:
    """Whether `(tool, args)` is one of the incoming commands saw governs. Takes the tool and the
    operator's arguments without the program name. Returns the answer."""
    if tool == "git":
        return (bool(args) and args[0] in _GIT_INBOUND) or tuple(args[:2]) == _GIT_SUBMODULE_UPDATE
    if tool == "gh":
        return tuple(args[:2]) in _GH_INBOUND
    return False


def prepare(repo: str, into: str, tool: str, args: list[str]) -> dict:
    """Carry out the incoming command into the holding directory and scan what arrived. Returns the
    payload without the schema stamp: `{"scan": <saw scan --json document>}` when a scan was made,
    else `{"reason": <one sentence>}` with no `scan` key, so the caller holds the update."""
    if not is_recognised(tool, args):
        return {"reason": f"saw does not govern this {tool} command"}
    # TODO(prepare): materialise the result in `into` — OPERATOR_PUSH to fetch the bytes, UNTRUSTED
    # to realise the tree with no repository or scan-on-clone hooks — then scan the inbound scope
    # with the operator's allowlist. Until that lands, fail closed: no scan, so the caller holds.
    return {"reason": "saw govern prepare is not yet implemented"}


def apply(repo: str, into: str) -> dict:
    """Make the open folder match the tree prepare scanned in the holding directory, without
    fetching again. Returns `{"applied": True}`, or `{"applied": False, "reason": <one sentence>}`
    with the open folder unchanged."""
    # TODO(apply): copy the scanned tree into the open folder under the untrusted context,
    # preserving the operator's uncommitted work or, if that is not possible, changing nothing.
    return {"applied": False, "reason": "saw govern apply is not yet implemented"}

#!/usr/bin/env python3
"""The answers `saw fix amend` must get from GitHub before it may move anything, given offline."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from unittest import mock


class NoRemoteTags:
    """What `git ls-remote --tags` looks like for a remote carrying no tags."""
    returncode = 0
    stdout = ""
    stderr = ""


@contextmanager
def github_answers(remote_head, *, permitted=True, protected=False, slug="acme/app"):
    """Answer every question the amend path asks the remote: who may rewrite, whether the refs
    refreshed, what each remote branch is at, and which tags it holds.

    Takes `remote_head(branch) -> sha`, whether a rewrite is permitted, whether the branch is
    protected, and the repository's slug. An answer a test has already put in place is kept.
    """
    import stayawake.bots.security.pr.amend as amendmod
    from stayawake.bots.security import remediator as remediatormod
    at = "stayawake.bots.security.pr.amend."
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(remediatormod, "_preflight", return_value=None))
        for target, patch in (
            ("gitutil.origin_slug", dict(return_value=slug)),
            ("authority.may_rewrite", dict(return_value=mock.Mock(
                permitted=permitted, conclusive=True,
                reason="owner" if permitted else "unauthorized"))),
            ("authority.ref_protection", dict(return_value=mock.Mock(
                protected=protected, reason="rule_read"))),
            ("authority.fork_count", dict(return_value=0)),
            ("gitutil.fetch_refs", dict(return_value=mock.Mock(ok=True, reason=""))),
            ("_read_remote_head", dict(side_effect=lambda r, s, b, tk: (True, remote_head(b)))),
            ("gitremote.ls_remote", dict(return_value=NoRemoteTags())),
        ):
            held = amendmod
            for part in target.split("."):
                held = getattr(held, part)
            if isinstance(held, mock.Mock):
                continue
            stack.enter_context(mock.patch(at + target, **patch))
        yield

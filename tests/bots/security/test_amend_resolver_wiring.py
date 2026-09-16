#!/usr/bin/env python3
"""Tests for the resolver wiring in `remediator.amend` / `_amend_local`.

The run-shape half of the interactive gate lives here: the resolver reaches the core only for a
single local repository, never a remote run and never a multi-repo (parallel) sweep.
"""
from __future__ import annotations

import io
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from stayawake.bots.security import remediator
from stayawake.bots.security.resolution import ScanOptions
from stayawake.utils.streaming import Streamer


class TestResolverWiring(unittest.TestCase):
    def _captured_resolver(self, repo_paths, resolver):
        """Run `_amend_local` over `repo_paths` and return the `resolver` kwarg amend_outcome saw."""
        captured = {}

        def fake_amend_outcome(*a, **kw):
            captured["resolver"] = kw.get("resolver", "MISSING")
            return mock.Mock(needs_review=False)

        with ExitStack() as s:
            s.enter_context(mock.patch.object(remediator, "_preflight", return_value=None))
            s.enter_context(mock.patch.object(remediator.auth, "resolve_token",
                                              return_value=("tok", "github-user")))
            s.enter_context(mock.patch.object(remediator.auth, "act_token",
                                              return_value=("tok", None)))
            s.enter_context(mock.patch.object(remediator, "_local_repos",
                                              return_value=[Path(p) for p in repo_paths]))
            s.enter_context(mock.patch.object(remediator.gitutil, "origin_slug",
                                              return_value="acme/app"))
            s.enter_context(mock.patch("stayawake.bots.security.pr.amend.amend_outcome",
                                       side_effect=fake_amend_outcome))
            s.enter_context(mock.patch("stayawake.bots.security.pr.outcome.render_amend_line",
                                       return_value="ok"))
            remediator._amend_local({}, ScanOptions(), {}, [], None,
                                    Streamer(enabled=False, out=io.StringIO()),
                                    jobs=1, resolver=resolver)
        return captured.get("resolver", "MISSING")

    def test_a_single_local_repo_gets_the_resolver(self):
        sentinel = lambda item: None
        self.assertIs(self._captured_resolver(["/r1"], sentinel), sentinel)

    def test_multiple_repos_never_get_the_resolver(self):
        sentinel = lambda item: None
        self.assertIsNone(self._captured_resolver(["/r1", "/r2"], sentinel))

    def test_amend_threads_the_resolver_to_local_but_not_remote(self):
        sentinel = lambda item: None
        with ExitStack() as s:
            s.enter_context(mock.patch.object(remediator, "_resolve_config",
                                              return_value={"settings": {}, "allowlist": []}))
            s.enter_context(mock.patch.object(remediator, "load_signatures", return_value={}))
            local = s.enter_context(mock.patch.object(remediator, "_amend_local", return_value=[]))
            remote = s.enter_context(mock.patch.object(remediator, "_amend_remote", return_value=[]))
            remediator.amend(remote=False, resolver=sentinel)
            remediator.amend(remote=True, resolver=sentinel)
        self.assertIs(local.call_args.kwargs.get("resolver"), sentinel)
        self.assertNotIn("resolver", remote.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()

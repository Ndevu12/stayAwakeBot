#!/usr/bin/env python3
"""core.env — the single place the app reads the process environment.

Locks the contract every caller now relies on: values are stripped, an empty/whitespace value
reads as unset, and GITHUB_REPOSITORY is parsed to (owner, name) in ONE place (the split the
alerters + remediator used to each duplicate)."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.core import env


def _environ(**kv):
    """Patch os.environ to EXACTLY kv (cleared), so a real GITHUB_TOKEN in CI can't leak in."""
    return mock.patch.dict("os.environ", kv, clear=True)


class TestGet(unittest.TestCase):
    def test_unset_returns_default(self):
        with _environ():
            self.assertIsNone(env.get("X"))
            self.assertEqual(env.get("X", "d"), "d")

    def test_value_is_stripped(self):
        with _environ(X="  hi  "):
            self.assertEqual(env.get("X"), "hi")

    def test_empty_or_whitespace_reads_as_unset(self):
        for raw in ("", "   ", "\t", "\n"):
            with _environ(X=raw):
                self.assertIsNone(env.get("X"))
                self.assertEqual(env.get("X", "d"), "d")   # falls back to default

    def test_internal_whitespace_preserved(self):
        with _environ(X="less -R"):
            self.assertEqual(env.get("X"), "less -R")


class TestGitHubContext(unittest.TestCase):
    def test_token_and_repository(self):
        with _environ(GITHUB_TOKEN=" ghs_x ", GITHUB_REPOSITORY=" o/r "):
            self.assertEqual(env.github_token(), "ghs_x")
            self.assertEqual(env.github_repository(), "o/r")

    def test_github_slug_parses_owner_name(self):
        with _environ(GITHUB_REPOSITORY="Ndevu12/stayAwakeBot"):
            self.assertEqual(env.github_slug(), ("Ndevu12", "stayAwakeBot"))

    def test_github_slug_rejects_unset_and_malformed(self):
        for repo, why in [(None, "unset"), ("noslash", "no slash"),
                          ("owner/", "empty name"), ("/name", "empty owner")]:
            kv = {} if repo is None else {"GITHUB_REPOSITORY": repo}
            with _environ(**kv):
                self.assertIsNone(env.github_slug(), why)

    def test_github_slug_is_the_single_split(self):
        # A token+repo that the alerters guard on: both present → (owner, name) usable directly.
        with _environ(GITHUB_TOKEN="t", GITHUB_REPOSITORY="o/r"):
            self.assertTrue(env.github_token() and env.github_slug())
            owner, name = env.github_slug()
            self.assertEqual((owner, name), ("o", "r"))


class TestToggles(unittest.TestCase):
    def test_slack_webhook(self):
        with _environ(SLACK_WEBHOOK_URL=" https://hook "):
            self.assertEqual(env.slack_webhook(), "https://hook")
        with _environ():
            self.assertIsNone(env.slack_webhook())

    def test_no_color(self):
        with _environ(NO_COLOR="1"):
            self.assertTrue(env.no_color())
        with _environ(NO_COLOR=""):       # empty = not set → colour stays on
            self.assertFalse(env.no_color())
        with _environ():
            self.assertFalse(env.no_color())

    def test_stream_disabled_on_either_var(self):
        with _environ(STAYAWAKE_NO_STREAM="1"):
            self.assertTrue(env.stream_disabled())
        with _environ(NO_STREAM="yes"):
            self.assertTrue(env.stream_disabled())
        with _environ():
            self.assertFalse(env.stream_disabled())

    def test_any_set(self):
        with _environ(B="x"):
            self.assertTrue(env.any_set(("A", "B")))
            self.assertFalse(env.any_set(("A", "C")))


if __name__ == "__main__":
    unittest.main()

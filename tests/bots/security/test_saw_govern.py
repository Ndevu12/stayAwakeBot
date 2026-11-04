#!/usr/bin/env python3
"""`saw govern` — the capability it advertises, and the fail-closed shape of its two commands.

The folder-changing behaviour (prepare materialises an incoming update in a holding directory and
scans it; apply copies a clean tree into the open folder, preserving uncommitted work) is covered
by the end-to-end tests once implemented. These pin the contract that holds from the start: the
capability is advertised at schema 1, an unrecognised command is not governed, and every path that
did not produce a clean result prints schema 1 and does not release the update.
"""
from __future__ import annotations

import json
import unittest

from stayawake.bots.security import govern
from stayawake.cli.commands.capabilities import capabilities
from stayawake.cli.dispatch import build_parser


def _capabilities() -> dict:
    parser = build_parser()
    commands = next(a.choices for a in parser._actions if hasattr(a, "choices") and a.choices
                    and "scan" in (a.choices or {}))
    return capabilities(commands)


class TestGovernCapability(unittest.TestCase):
    def test_capabilities_advertises_govern_at_schema_one(self):
        caps = _capabilities()
        self.assertIn("govern.json", caps["features"])
        self.assertEqual(caps["schema_versions"].get("govern"), 1)


class TestGovernRecognisedCommands(unittest.TestCase):
    def test_the_inbound_commands_are_recognised(self):
        for tool, args in [("git", ["pull"]), ("git", ["fetch", "origin"]),
                           ("git", ["merge", "main"]), ("git", ["rebase", "origin/main"]),
                           ("git", ["checkout", "main"]), ("git", ["switch", "main"]),
                           ("git", ["submodule", "update", "--init"]),
                           ("gh", ["pr", "checkout", "12"]), ("gh", ["repo", "sync"]),
                           ("gh", ["release", "download"]), ("gh", ["run", "download", "4"])]:
            with self.subTest(tool=tool, args=args):
                self.assertTrue(govern.is_recognised(tool, args))

    def test_a_command_that_brings_nothing_in_is_not_governed(self):
        for tool, args in [("git", ["status"]), ("git", ["commit"]), ("git", ["push"]),
                           ("gh", ["pr", "view"]), ("git", [])]:
            with self.subTest(tool=tool, args=args):
                self.assertFalse(govern.is_recognised(tool, args))


class TestGovernFailsClosed(unittest.TestCase):
    def test_an_unrecognised_command_is_held_with_a_reason_and_no_scan(self):
        out = govern.prepare("/repo", "/holding", "git", ["status"])
        self.assertNotIn("scan", out)
        self.assertIn("reason", out)

    def test_apply_defaults_to_not_applied_with_a_reason(self):
        out = govern.apply("/repo", "/holding")
        self.assertFalse(out.get("applied"))
        self.assertIn("reason", out)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A held update judges only what it brings, says what to do, and can be let in after review."""
from __future__ import annotations

import json
import subprocess

from stayawake.bots.security import govern
from stayawake.utils import exitcodes
from tests.support import samples
from tests.support.gitrepo import GitSandbox
from tests.support.local_remotes import allow_local_remotes


def _hook(command: str = "node scripts/setup.js", name: str = "app") -> str:
    return json.dumps({"name": name, "hooks": {"SessionStart": [{"hooks": [{"type": "command",
                                                                             "command": command}]}]}},
                      indent=2) + "\n"


class _Update(GitSandbox):
    """An open folder cloned from an upstream; each test commits an update upstream and pulls it."""

    def setUp(self):
        super().setUp()
        allow_local_remotes(self)
        self.upstream = self.new_repo("upstream")

    def start(self, files: dict[str, str]) -> None:
        for rel, text in files.items():
            self.write(self.upstream, rel, text)
        self.commit(self.upstream, "start")
        self.open = self.owned(self.root / "open")
        subprocess.run(["git", "clone", "-q", str(self.upstream), str(self.open)], check=True, capture_output=True)
        self.git(self.open, "config", "commit.gpgsign", "false")
        self.into = self.root / "holding"

    def update(self, files: dict[str, str]) -> tuple[dict, int]:
        for rel, text in files.items():
            self.write(self.upstream, rel, text)
        self.commit(self.upstream, "update")
        return govern.prepare(str(self.open), str(self.into), "git", ["pull"])

    def head(self) -> str:
        return self.git(self.open, "rev-parse", "HEAD").strip()


class WhatTheUpdateBrings(_Update):

    def test_a_finding_the_folder_already_had_does_not_hold_the_update(self):
        self.start({".claude/settings.json": _hook()})
        answer, code = self.update({".claude/settings.json": _hook(name="renamed")})
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "clean")
        self.assertEqual([f["path"] for f in answer["pre_existing"]], [".claude/settings.json"])
        self.assertTrue(all(f["pre_existing"] for f in answer["pre_existing"]))
        self.assertNotIn("decision", answer)
        self.assertTrue(any("already there" in step for step in answer["next_steps"]))
        self.assertEqual(govern.apply(str(self.open), str(self.into))[0], {"applied": True, "outcome": "brought_in"})

    def test_a_finding_the_update_changes_still_holds_it(self):
        self.start({".claude/settings.json": _hook()})
        answer, _code = self.update({".claude/settings.json": _hook(command="node scripts/other.js")})
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "suspicious")
        self.assertNotIn("pre_existing", answer)

    def test_a_confirmed_finding_holds_the_update_even_when_it_was_already_there(self):
        self.start({".gitignore": samples._gitignore()})
        answer, code = self.update({".gitignore": "dist/\n" + samples._gitignore()})
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertEqual(answer["scan"]["results"][0]["verdict"], "infected")


class AWayThrough(_Update):

    def test_a_suspicious_update_is_let_in_with_a_yes_after_review(self):
        self.start({"README.md": "one\n"})
        before = self.head()
        answer, _code = self.update({".claude/settings.json": _hook()})
        decision = answer["decision"]
        self.assertEqual(decision["choices"], ["let-in", "leave-unchanged"])
        self.assertEqual(decision["confirm"], "yes")
        commit = decision["let_in"][-1]
        self.assertEqual(decision["let_in"][:3], ["saw", "govern", "apply"])
        self.assertTrue(any(".claude/settings.json" in step for step in answer["next_steps"]))
        self.assertFalse(govern.apply(str(self.open), str(self.into))[0]["applied"])
        self.assertFalse(govern.apply(str(self.open), str(self.into), accept="0" * 40)[0]["applied"])
        self.assertEqual(self.head(), before)
        self.assertEqual(govern.apply(str(self.open), str(self.into), accept=commit)[0], {"applied": True, "outcome": "brought_in"})
        self.assertEqual(self.head(), commit)
        said, code = govern.verdict(str(self.open))
        self.assertEqual((said["governed"], said["code"]), ("not-let-in", "let-in-by-you"))
        self.assertEqual(code, exitcodes.FINDINGS)

    def test_an_infected_update_needs_the_folder_name_typed(self):
        self.start({"README.md": "one\n"})
        before = self.head()
        answer, _code = self.update({".gitignore": samples._gitignore()})
        decision = answer["decision"]
        self.assertEqual((decision["confirm"], decision["type_to_confirm"]), ("typed", "open"))
        self.assertTrue(any("saw audit" in step for step in answer["next_steps"]))
        commit = decision["let_in"][-1]
        for confirm in (None, "yes", "Open"):
            self.assertFalse(govern.apply(str(self.open), str(self.into), accept=commit, confirm=confirm)[0]["applied"])
        self.assertEqual(self.head(), before)
        self.assertEqual(govern.apply(str(self.open), str(self.into), accept=commit, confirm="open")[0],
                         {"applied": True, "outcome": "brought_in"})
        self.assertEqual(govern.verdict(str(self.open))[0]["code"], "let-in-by-you")

    def test_a_clean_update_carries_no_decision(self):
        self.start({"README.md": "one\n"})
        answer, code = self.update({"README.md": "two\n"})
        self.assertEqual(code, exitcodes.CLEAN)
        self.assertNotIn("decision", answer)
        self.assertNotIn("pre_existing", answer)


if __name__ == "__main__":
    import unittest
    unittest.main()

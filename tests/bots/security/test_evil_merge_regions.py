#!/usr/bin/env python3
"""What evidence an evil-merge claim may rest on depends on what git could have done at that path.

Git's merge is deterministic, so where it merged a path cleanly it CANNOT have produced a different
result — a recorded tree that differs there was edited by hand while merging. Where it conflicted, a
human resolution is expected to differ, so structure proves nothing and only content can. And where
there is no merge base at all there is no "what git would have produced", so no structural claim
exists — substituting a parent tree for it reports the whole of one side as introduced by the merge.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.lib.git.merge import evil_merge_paths
from stayawake.bots.security.matchers.git_history import _obfuscation_reason


def _sig(text):
    return "worm-loader" if "EVIL_PAYLOAD" in text else None


class _MergeFixture(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="evil-regions-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "t@example.com")
        self._git("config", "user.name", "t")
        self._git("config", "commit.gpgsign", "false")

    def _git(self, *args):
        return subprocess.run(["git", "-C", str(self.d), *args], capture_output=True, text=True)

    def _write(self, rel, body):
        p = self.d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)

    def _commit(self, msg):
        self._git("add", "-A")
        self._git("commit", "-q", "-m", msg)

    def _diverged(self):
        """A base, a feature branch and a mainline commit — no conflict between them."""
        self._write("app.js", "const a = 1;\n")
        self._commit("base")
        self._git("checkout", "-qb", "feat")
        self._write("feat.js", "export const f = 2;\n")
        self._commit("feat")
        self._git("checkout", "-q", "main")
        self._write("main.js", "export const m = 3;\n")
        self._commit("main")

    def _conflict(self):
        self._write("app.js", "line\n")
        self._commit("base")
        self._git("checkout", "-qb", "feat")
        self._write("app.js", "feat side\n")
        self._commit("feat")
        self._git("checkout", "-q", "main")
        self._write("app.js", "main side\n")
        self._commit("main")

    def _flagged(self):
        sha = self._git("rev-parse", "HEAD").stdout.strip()
        return evil_merge_paths(self.d, sha, _sig, _obfuscation_reason)


class TestACleanlyMergedPathNeedsNoCorroboration(_MergeFixture):
    def test_a_hand_edit_while_merging_is_decisive_on_its_own(self):
        # The shape of the real attack: an edit made during the merge, carrying no signature and no
        # obfuscation. No parent's diff shows it, and a PR review never renders a merge commit.
        self._diverged()
        self._git("merge", "--no-commit", "--no-ff", "-q", "feat")
        self._write("app.js", "const a = 1;\nconst stolen = readSecrets();\n")
        self._commit("Merge feat")
        flagged = self._flagged()
        self.assertIn("app.js", flagged)
        self.assertIn("did NOT conflict", flagged["app.js"])

    def test_a_deviation_that_adds_nothing_is_not_an_injection(self):
        # Removing or reordering during a merge is real, but this detector reports what a merge
        # INTRODUCED; a hunk with no added text smuggles nothing.
        self._diverged()
        self._git("merge", "--no-commit", "--no-ff", "-q", "feat")
        self._write("app.js", "")
        self._commit("Merge feat")
        self.assertEqual(self._flagged(), {})

    def test_an_ordinary_sync_merge_stays_clean(self):
        self._diverged()
        self._git("merge", "--no-ff", "-q", "-m", "Merge feat", "feat")
        self.assertEqual(self._flagged(), {})


class TestAConflictedPathNeedsContentEvidence(_MergeFixture):
    def test_a_benign_resolution_is_not_a_finding(self):
        self._conflict()
        self._git("merge", "--no-commit", "--no-ff", "feat")
        self._write("app.js", "feat side\nmain side\n")
        self._commit("Merge")
        self.assertEqual(self._flagged(), {})

    def test_a_payload_in_the_resolution_still_fires(self):
        self._conflict()
        self._git("merge", "--no-commit", "--no-ff", "feat")
        self._write("app.js", "resolved\nEVIL_PAYLOAD\n")
        self._commit("Merge")
        self.assertIn("app.js", self._flagged())

    def test_a_resolution_taken_verbatim_from_the_other_side_still_fires(self):
        # `-X theirs` to a payload parent: the conflicted auto-merge blob ALREADY carries that text,
        # so nothing is introduced against it. The first parent — what a reviewer compares against —
        # is where it shows, which is why that baseline exists.
        self._write("util.js", "export const id = (x) => x;\n")
        self._commit("base")
        self._git("checkout", "-qb", "evil")
        self._write("util.js", "export const id = (x) => x;\nEVIL_PAYLOAD\n")
        self._commit("evil")
        self._git("checkout", "-q", "main")
        self._write("util.js", "export const id = (y) => y;\n")
        self._commit("divergent")
        self._git("merge", "--no-ff", "-q", "-X", "theirs", "-m", "Merge", "evil")
        self.assertIn("util.js", self._flagged())


class TestNoMergeBaseMakesNoStructuralClaim(_MergeFixture):
    """Two roots merged with `--allow-unrelated-histories`: there is no common ancestor, so there is
    no clean 3-way merge to deviate from. Comparing against a parent instead reported every file the
    other root contributed — 18 of them, in the repository that raised this."""

    def _unrelated(self):
        self._write("a.js", "export const a = 1;\n")
        self._commit("root one")
        self._git("checkout", "-q", "--orphan", "other")
        self._git("rm", "-q", "-rf", ".")
        for name in ("b.js", "c.js", "d.js"):
            self._write(name, "export const x = 'y';\n" + "z" * 500 + "\n")
        self._commit("root two")
        self._git("checkout", "-q", "main")

    def test_an_unrelated_history_merge_is_not_an_attack(self):
        self._unrelated()
        self._git("merge", "--no-ff", "-q", "--allow-unrelated-histories", "-m", "Merge", "other")
        self.assertEqual(self._flagged(), {})

    def test_infected_content_still_fires_without_a_baseline(self):
        # No structural claim is available, but infected bytes are infected either way.
        self._unrelated()
        self._git("merge", "--no-commit", "--no-ff", "--allow-unrelated-histories", "other")
        self._write("dropped.js", "EVIL_PAYLOAD\n")
        self._commit("Merge")
        self.assertIn("dropped.js", self._flagged())


if __name__ == "__main__":
    unittest.main()

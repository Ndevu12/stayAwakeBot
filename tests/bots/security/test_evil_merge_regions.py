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


class TestLivenessSaysWhetherItIsStillThere(_MergeFixture):
    """"This merge was evil" and "this payload is in the file you are about to run" are different
    facts, and only the second is actionable. Blob identity settles it, in one direction only: an
    identical blob PROVES the bytes survive, while a different blob proves only that the file
    changed — the introduced lines may sit untouched inside it."""

    def _evil_merge(self):
        self._diverged()
        self._git("merge", "--no-commit", "--no-ff", "-q", "feat")
        self._write("app.js", "const a = 1;\nconst stolen = readSecrets();\n")
        self._commit("Merge feat")
        return self._git("rev-parse", "HEAD").stdout.strip()

    def test_untouched_since_the_merge_is_reported_present(self):
        from stayawake.lib.git.merge.liveness import introduced_liveness, PRESENT
        sha = self._evil_merge()
        self.assertEqual(introduced_liveness(self.d, sha, "app.js"), PRESENT)

    def test_a_later_edit_is_never_reported_as_removed(self):
        # The trap: treating "the hash moved" as "the payload is gone". A reformat, a cherry-pick or
        # an unrelated edit all move the hash while the introduced lines stay.
        from stayawake.lib.git.merge.liveness import introduced_liveness, CHANGED, describe
        sha = self._evil_merge()
        self._write("app.js", "const a = 1;\nconst stolen = readSecrets();\nconst extra = 2;\n")
        self._commit("later edit")
        state = introduced_liveness(self.d, sha, "app.js")
        self.assertEqual(state, CHANGED)
        self.assertIn("UNVERIFIED", describe(state))
        self.assertNotIn("removed", describe(state).replace("do not read this as removed", ""))

    def test_a_deleted_path_still_says_it_survives_in_history(self):
        from stayawake.lib.git.merge.liveness import introduced_liveness, GONE, describe
        sha = self._evil_merge()
        (self.d / "app.js").unlink()
        self._commit("remove")
        self.assertEqual(introduced_liveness(self.d, sha, "app.js"), GONE)
        self.assertIn("history", describe(GONE))


class TestObfuscationNeedsTheReachabilityItsNameImplies(unittest.TestCase):
    """A decode is not an execution, and a numeric array is not a shuffler.

    `atob` decodes and returns; grouping it with `eval` makes every JWT reader and data-URI handler a
    finding. A numeric literal becomes a string shuffler only when something CONSUMES it as character
    codes — otherwise it is every size table, colour table and lookup table in existence.
    """

    def _fires(self, source, ext=".ts"):
        from stayawake.bots.security.obfuscation import analyze_file
        return bool(analyze_file(source, ext))

    def test_a_jwt_decoder_is_not_a_dynamic_exec_sink(self):
        self.assertFalse(self._fires(
            "export function decode(t){const p=t.split('.')[1];"
            "const j=atob(p);return JSON.parse(j);}"))

    def test_a_data_uri_decode_is_not_a_dynamic_exec_sink(self):
        self.assertFalse(self._fires(
            "const bytes=atob(dataUri.split(',')[1]);const blob=new Blob([bytes]);"))

    def test_a_size_table_is_not_a_string_shuffler(self):
        self.assertFalse(self._fires(
            "const iosSizes=[72,96,128,144,152,180,192,384,512];\nfor (const s of iosSizes){}", ".js"))

    def test_a_decode_that_feeds_an_exec_still_fires(self):
        # The decode half was never the signal; the exec half is, and it is untouched.
        self.assertTrue(self._fires("const p=atob('ZXZpbA==');eval(p);", ".js"))
        self.assertTrue(self._fires("const s=atob(x); new Function(s)();", ".js"))

    def test_a_numeric_array_consumed_as_charcodes_still_fires(self):
        self.assertTrue(self._fires(
            "const _0x=[72,101,108,108,111,44,32,87,111];"
            "const t=a=>String.fromCharCode(...a);", ".js"))

    def test_the_remediation_gate_still_defers_on_a_bare_decode(self):
        # Deliberately NOT relaxed: in the gate, trusting a benign shape can pass an RCE, so a decode
        # primitive left in auto-cleaned code remains a reason to stop.
        from stayawake.bots.security.obfuscation.execsink import _has_exec_sink
        self.assertTrue(_has_exec_sink("const j=atob(p);return JSON.parse(j);", strict=True))

    def test_the_reason_no_longer_advertises_a_decode_as_a_sink(self):
        from stayawake.bots.security.obfuscation import analyze_file
        verdict = analyze_file("eval(userInput);", ".js")
        self.assertNotIn("atob", verdict.reason)

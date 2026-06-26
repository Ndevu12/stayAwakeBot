#!/usr/bin/env python3
"""Evil-merge detector test: a merge commit that introduces a file present in
neither parent must be flagged."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


from stayawake.bots.security.matchers.git_history import GitHistoryMatcher          # noqa: E402
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions  # noqa: E402

EVIL_SIG = [{
    "id": "evil-merge", "category": "evil-merge", "severity": "high",
    "matcher": "git-history", "kind": "evil-merge",
    "description": "evil merge", "remediation": "manual",
}]


def _git(d, *args):
    subprocess.run(["git", "-C", str(d), *args], check=True,
                   capture_output=True, text=True)


class TestEvilMerge(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="evilmerge-"))
        _git(self.d, "init", "-q")
        _git(self.d, "config", "user.email", "t@t.test")
        _git(self.d, "config", "user.name", "Tester")
        (self.d / "a.txt").write_text("base\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "init")
        self.base = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        _git(self.d, "checkout", "-qb", "feature")
        (self.d / "b.txt").write_text("feature\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "feature work")
        _git(self.d, "checkout", "-q", self.base)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _findings(self):
        t = LocalRepoTarget(self.d, "tmp", ScanOptions())
        return GitHistoryMatcher().scan(t, EVIL_SIG)

    def test_clean_merge_not_flagged(self):
        _git(self.d, "merge", "--no-ff", "-q", "-m", "honest merge", "feature")
        self.assertEqual(self._findings(), [], "honest merge must not be flagged")

    def test_evil_merge_flagged(self):
        # Merge but inject a file that exists in neither parent.
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected in the merge only\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "merge with injection")
        findings = self._findings()
        self.assertTrue(findings, "evil merge should be detected")
        self.assertIn("evil.txt", findings[0].evidence)

    def test_evil_merge_inside_merged_side_branch_flagged(self):
        # Regression: an evil merge that lives INSIDE a merged side-branch is reachable only
        # through a SECOND parent, never the first-parent mainline chain. Enumeration must
        # traverse ALL merges (`--diff-merges=first-parent` sets only the diff format) — the
        # earlier `-m --first-parent` restricted *traversal* and silently skipped it.
        _git(self.d, "checkout", "-qb", "topic")
        (self.d / "t.txt").write_text("topic\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "topic work")
        _git(self.d, "checkout", "-qb", "sub")
        (self.d / "s.txt").write_text("sub\n")
        _git(self.d, "add", "."); _git(self.d, "commit", "-qm", "sub work")
        _git(self.d, "checkout", "-q", "topic")
        _git(self.d, "merge", "--no-ff", "--no-commit", "sub")
        (self.d / "evil2.txt").write_text("injected only in the side-branch merge\n")
        _git(self.d, "add", "evil2.txt")
        _git(self.d, "commit", "-qm", "side-branch merge with injection")
        # Bring the side branch (with its buried evil merge) onto mainline via a clean merge.
        _git(self.d, "checkout", "-q", self.base)
        _git(self.d, "merge", "--no-ff", "-q", "-m", "merge topic into main", "topic")
        findings = self._findings()
        self.assertTrue(findings, "evil merge buried inside a merged side-branch must be detected")
        self.assertIn("evil2.txt", " ".join(f.evidence for f in findings))

    def test_overlapping_clean_merge_not_flagged(self):
        # Regression for #1004: both sides edit the SAME file in different hunks; the clean
        # 3-way auto-merge combines them, so the merged file differs from BOTH parents. That
        # is normal git, not an evil merge — it must NOT be flagged. (The old "changed vs
        # every parent" intersection flagged exactly this.)
        (self.d / "shared.txt").write_text("l1\nl2\nl3\nl4\nl5\n")
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "add shared")
        _git(self.d, "checkout", "-qb", "side")
        (self.d / "shared.txt").write_text("l1-side\nl2\nl3\nl4\nl5\n")    # edit top hunk
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "side edits l1")
        _git(self.d, "checkout", "-q", self.base)
        (self.d / "shared.txt").write_text("l1\nl2\nl3\nl4\nl5-base\n")    # edit bottom hunk
        _git(self.d, "add", "shared.txt"); _git(self.d, "commit", "-qm", "base edits l5")
        _git(self.d, "merge", "--no-ff", "-q", "-m", "clean combine", "side")
        # The merged shared.txt == "l1-side … l5-base": differs from both parents, equals the
        # clean auto-merge → no deviation → no finding.
        self.assertEqual(self._findings(), [],
                         "a clean 3-way merge of independent edits must not be flagged")

    def test_obfuscated_injection_into_modified_source_flagged(self):
        # G3: a NOVEL obfuscated payload (matches no existing signature) MODIFIED into a
        # tracked, non-sensitive, previously-formatted source file during the merge itself.
        # The introduced hunk is a charcode-array string shuffler — caught by the
        # context-aware obfuscation corroborator on the merge-introduced delta.
        (self.d / "util.js").write_text("export const id = (x) => x;\n")
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "add util")
        _git(self.d, "checkout", "-qb", "feat2")
        (self.d / "other.js").write_text("export const k = 1;\n")
        _git(self.d, "add", "other.js"); _git(self.d, "commit", "-qm", "unrelated feat")
        _git(self.d, "checkout", "-q", self.base)
        _git(self.d, "merge", "--no-ff", "--no-commit", "feat2")
        # Inject obfuscation into util.js within the merge commit (review-evading):
        with (self.d / "util.js").open("a") as fh:
            fh.write("var _q=[104,116,116,112,115,58,47,47,120];"
                     "eval(String.fromCharCode.apply(null,_q));\n")
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "merge feat2")
        findings = self._findings()
        self.assertTrue(findings, "obfuscated merge-introduced hunk must be flagged (G3)")
        self.assertIn("util.js", findings[0].evidence)

    def test_novel_human_conflict_resolution_not_flagged(self):
        # The FP this whole layer exists to kill: a REAL conflict where the human resolves to
        # a third, valid, NON-obfuscated variant of the conflicting line. The result deviates
        # from the clean auto-merge tree (so the raw heuristic flagged it) but the introduced
        # hunk is ordinary code → no corroboration → must be CLEAN.
        (self.d / "greet.js").write_text('export const g = () => "hello";\n')
        _git(self.d, "add", "greet.js"); _git(self.d, "commit", "-qm", "add greet")
        _git(self.d, "checkout", "-qb", "side2")
        (self.d / "greet.js").write_text('export const g = () => "hello world";\n')
        _git(self.d, "add", "greet.js"); _git(self.d, "commit", "-qm", "side greet")
        _git(self.d, "checkout", "-q", self.base)
        (self.d / "greet.js").write_text('export const g = () => "hola";\n')
        _git(self.d, "add", "greet.js"); _git(self.d, "commit", "-qm", "base greet")
        # conflicting merge (exits 1 on conflict) resolved to a NOVEL third variant:
        subprocess.run(["git", "-C", str(self.d), "merge", "--no-ff", "--no-commit", "side2"],
                       capture_output=True, text=True)

        (self.d / "greet.js").write_text('export const g = () => "hello world (es: hola)";\n')
        _git(self.d, "add", "greet.js"); _git(self.d, "commit", "-qm", "resolve conflict")
        self.assertEqual(self._findings(), [],
                         "a benign novel conflict resolution must NOT be flagged")

    def test_merge_deleting_one_sided_add_not_flagged(self):
        # Regression for the worm-guard false positive: `feature` ADDS b.txt (absent on base
        # and at the merge-base). A clean 3-way merge KEEPS that addition, so the auto-merge
        # tree contains b.txt — but the recorded merge DELETES it (a routine "accept the other
        # branch's removal" resolution). That deviates from the auto-merge only by a deletion,
        # which injects nothing, so it must NOT be flagged as an evil merge.
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        _git(self.d, "rm", "-qf", "b.txt")   # -f: b.txt is staged by the merge but not in HEAD
        _git(self.d, "commit", "-qm", "merge but drop b.txt")
        self.assertEqual(self._findings(), [],
                         "a merge that only deletes a path must not be flagged")

    # ── G2: payload byte-identical to ONE parent escapes the intersection ──────────
    _CHARCODE = ("var _q=[104,116,116,112,115,58,47,47,120];"
                 "eval(String.fromCharCode.apply(null,_q));\n")  # obfuscated, no loader sig

    def test_g2_octopus_payload_identical_to_one_parent_flagged(self):
        # G2: an OCTOPUS merge pulls in three heads. The payload MODIFIES an existing tracked
        # file (util.js) and the merge resolves it byte-identical to the payload-carrying
        # parent. The old ">2-parent intersection" (added/modified vs EVERY parent) dropped
        # util.js — it does NOT differ from the parent that carries it — so NO finding was
        # ever emitted, even at the merge_commits prefilter (empty combined diff). The
        # first-parent enumeration + corroboration must now flag it.
        (self.d / "util.js").write_text("export const id = (x) => x;\n")
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "add util")
        _git(self.d, "checkout", "-qb", "side")
        (self.d / "s.txt").write_text("s\n")
        _git(self.d, "add", "s.txt"); _git(self.d, "commit", "-qm", "side")
        _git(self.d, "checkout", "-q", self.base)
        _git(self.d, "checkout", "-qb", "payload")
        (self.d / "util.js").write_text("export const id = (x) => x;\n" + self._CHARCODE)
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "wip payload")
        _git(self.d, "checkout", "-q", self.base)
        # octopus: feature + side + payload; -X theirs resolves util.js to the payload blob,
        # leaving it byte-identical to the `payload` parent.
        _git(self.d, "merge", "--no-ff", "-q", "-X", "theirs",
             "-m", "octopus", "feature", "side", "payload")
        findings = self._findings()
        self.assertTrue(findings, "G2 octopus payload identical to one parent must be flagged")
        self.assertIn("util.js", findings[0].evidence)

    def test_g2_two_parent_resolution_to_one_parent_payload_flagged(self):
        # G2 in the 2-parent shape: a `-X theirs` merge resolves an existing file to the
        # feature parent's payload blob verbatim. The combined diff is EMPTY (the merge tree
        # equals one parent for that path), so the old combined-diff prefilter dropped the
        # whole merge. The first-parent prefilter keeps it; the auto-merge deviation +
        # obfuscation corroborator confirm it.
        (self.d / "util.js").write_text("export const id = (x) => x;\n")
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "add util")
        _git(self.d, "checkout", "-qb", "evil")
        (self.d / "util.js").write_text("export const id = (x) => x;\n" + self._CHARCODE)
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "evil edit")
        _git(self.d, "checkout", "-q", self.base)
        (self.d / "util.js").write_text("export const id = (y) => y;\n")  # divergent base edit
        _git(self.d, "add", "util.js"); _git(self.d, "commit", "-qm", "base edit")
        _git(self.d, "merge", "--no-ff", "-q", "-X", "theirs", "-m", "merge", "evil")
        findings = self._findings()
        self.assertTrue(findings, "G2 2-parent -X theirs to payload parent must be flagged")
        self.assertIn("util.js", findings[0].evidence)

    def test_g2_benign_octopus_not_flagged(self):
        # The FP guard for the G2 fix: an octopus combining three CLEAN branches (no payload
        # anywhere). First-parent enumeration surfaces every introduced path, but the
        # corroboration gate finds no signature/obfuscation and no new-vs-all-parents inject,
        # so the merge stays clean.
        for name in ("o1", "o2", "o3"):
            _git(self.d, "checkout", "-q", self.base)
            _git(self.d, "checkout", "-qb", name)
            (self.d / f"{name}.js").write_text(f"export const {name} = 1;\n")
            _git(self.d, "add", "."); _git(self.d, "commit", "-qm", name)
        _git(self.d, "checkout", "-q", self.base)
        _git(self.d, "merge", "--no-ff", "-q", "-m", "octopus", "o1", "o2", "o3")
        self.assertEqual(self._findings(), [],
                         "a benign octopus of clean branches must not be flagged")

    # ── G6: ref scope — remote-tracking reachability vs the stash FP ───────────────
    def test_g6_evil_merge_only_on_remote_tracking_ref_flagged(self):
        # G6 recall: an evil merge that exists ONLY on a remote-tracking ref the user fetched
        # (refs/remotes/origin/*) but never merged into a local branch. `--branches --tags`
        # alone CANNOT reach it (no local branch contains it); `--remotes` must, so the
        # detector's scope includes it. Build it directly: a merge commit referenced only by
        # refs/remotes/origin/main, unreachable from HEAD/any local branch.
        _git(self.d, "merge", "--no-ff", "--no-commit", "feature")
        (self.d / "evil.txt").write_text("injected in the merge only\n")
        _git(self.d, "add", "evil.txt")
        _git(self.d, "commit", "-qm", "remote evil merge")
        remote_sha = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
        # Park that merge on a remote-tracking ref, then rewind the local branch so NO local
        # branch reaches it. Only refs/remotes/origin/main now points at the evil merge.
        _git(self.d, "update-ref", "refs/remotes/origin/main", remote_sha)
        _git(self.d, "reset", "-q", "--hard", "HEAD~1")
        # Sanity: unreachable from --branches, reachable from --remotes.
        from stayawake.core import git as gitutil
        self.assertNotIn(remote_sha, gitutil.merge_commits(self.d, refs=("--branches",)),
                         "precondition: evil merge is NOT on any local branch")
        findings = self._findings()
        self.assertTrue(findings, "evil merge reachable only via a fetched remote-tracking "
                                  "ref must be flagged (G6)")
        self.assertIn("evil.txt", findings[0].evidence)

    def test_g6_stash_merge_never_enumerated(self):
        # G6 FP guard: a `git stash` creates a 2/3-parent merge commit under refs/stash. The
        # scope (`--branches --tags --remotes`, deliberately NOT `--all`) must never enumerate
        # it, so a stash can never become an evil-merge candidate regardless of its content.
        (self.d / "a.txt").write_text("dirty change\n")   # working-tree dirt to stash
        _git(self.d, "stash", "-q")
        from stayawake.core import git as gitutil
        stash_sha = subprocess.run(
            ["git", "-C", str(self.d), "rev-parse", "refs/stash"],
            capture_output=True, text=True, check=True).stdout.strip()
        self.assertNotIn(stash_sha, gitutil.merge_commits(self.d),
                         "refs/stash must be outside the merge-enumeration scope")
        self.assertEqual(self._findings(), [], "a stash must never be an evil-merge finding")

    def test_g6_overlapping_local_and_remote_ref_not_double_counted(self):
        # G6 cost/dedup: a merge reachable from BOTH a local branch and a remote-tracking ref
        # must be enumerated exactly once (git log dedups by SHA), so `--remotes` adds no
        # duplicate-candidate cost in the common case where local and origin agree.
        _git(self.d, "merge", "--no-ff", "-q", "-m", "honest merge", "feature")
        head = subprocess.run(["git", "-C", str(self.d), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        _git(self.d, "update-ref", "refs/remotes/origin/main", head)  # same SHA on both refs
        from stayawake.core import git as gitutil
        cands = gitutil.merge_commits(self.d)
        self.assertEqual(cands.count(head), 1,
                         "a merge on both a local and a remote ref must appear once, not twice")


if __name__ == "__main__":
    unittest.main()

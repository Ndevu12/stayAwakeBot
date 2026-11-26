#!/usr/bin/env python3
"""An allowlist rule that names a commit accepts that signature's finding in that one commit, read by
its full id, and every command refuses a rule that names a commit any other way."""
from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from stayawake.bots.security.config import allowlist_ok, resolve_config, usable
from stayawake.bots.security.hook_policy import operator_policy
from stayawake.bots.security.models import HEURISTIC, Finding, Severity
from stayawake.bots.security.scanner import finalize, scan_target
from stayawake.bots.security.signatures import every_signature, load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from tests.support.gitrepo import GitSandbox

REPO = Path(__file__).resolve().parents[3]
ALL_SIGNATURES = every_signature(load_signatures())
MERGE_SIGNATURES = {"git-history": [s for s in load_signatures()["git-history"]
                                    if s["id"].startswith("evil-merge")]}

REVIEWED = "f75d2b92d102e73ecc38f9d0da3d2dbf6b857df8"
SAME_SHORT_ID = REVIEWED[:10] + "0" * 30
SHA256_ID = "0d63c24db636be8fa8289d4d9b0b1777cc8e0020" + "ab" * 12


def _merge_finding(commit, signature="evil-merge") -> Finding:
    return Finding(signature, "evil-merge", Severity.MEDIUM, (commit or "")[:10] or "merge",
                   "merge", vector="evil-merge", commit_sha=commit, confidence=HEURISTIC,
                   composed_evidence=True)


def _reported(findings, allowlist) -> list[tuple[str, str | None]]:
    result = finalize("repo", "local", {"git-history": findings}, ["git-history"], [], [], None,
                      None, allowlist, ALL_SIGNATURES)
    return [(f.signature_id, f.commit_sha) for f in result.findings]


class ACommitRuleHidesThatMergeOnly(GitSandbox):
    def _merge_adding(self, repo: Path, branch: str, name: str) -> str:
        self.git(repo, "checkout", "-q", "-b", branch)
        self.write(repo, f"{branch}.txt", f"{branch}\n")
        self.commit(repo, f"{branch} work")
        self.git(repo, "checkout", "-q", "main")
        self.git(repo, "merge", "--no-ff", "--no-commit", "-q", branch)
        self.write(repo, name, "injected in the merge only\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", f"Merge {branch}")
        return self.rev(repo)

    def test_the_named_merge_is_accepted_and_another_is_still_reported(self):
        repo = self.new_repo()
        self.write(repo, "a.txt", "base\n")
        self.commit(repo, "init")
        reviewed = self._merge_adding(repo, "first", "one.txt")
        other = self._merge_adding(repo, "second", "two.txt")
        rule = [{"signature": "evil-merge", "commit": reviewed}]

        unruled = scan_target(LocalRepoTarget(repo, "repo", ScanOptions()), MERGE_SIGNATURES, [])
        ruled = scan_target(LocalRepoTarget(repo, "repo", ScanOptions()), MERGE_SIGNATURES, rule)

        self.assertEqual({f.commit_sha for f in unruled.findings}, {reviewed, other})
        self.assertEqual([(f.signature_id, f.commit_sha) for f in ruled.findings],
                         [("evil-merge", other)])


class ACommitRuleMatchesTheFullIdOnly(unittest.TestCase):
    def test_a_merge_whose_short_id_is_the_same_is_still_reported(self):
        rule = [{"signature": "evil-merge", "commit": REVIEWED}]
        found = [_merge_finding(REVIEWED), _merge_finding(SAME_SHORT_ID)]
        self.assertEqual(found[0].path, found[1].path)
        self.assertEqual(_reported(found, rule), [("evil-merge", SAME_SHORT_ID)])

    def test_the_id_is_read_in_either_case(self):
        rule = [{"signature": "evil-merge", "commit": REVIEWED.upper()}]
        self.assertEqual(_reported([_merge_finding(REVIEWED)], rule), [])

    def test_a_sha256_id_is_matched_in_full(self):
        rule = [{"signature": "evil-merge", "commit": SHA256_ID}]
        self.assertEqual(_reported([_merge_finding(SHA256_ID)], rule), [])
        self.assertEqual(_reported([_merge_finding(SHA256_ID[:40])], rule),
                         [("evil-merge", SHA256_ID[:40])])

    def test_a_finding_without_a_commit_is_still_reported(self):
        rule = [{"signature": "evil-merge", "commit": REVIEWED}]
        self.assertEqual(_reported([_merge_finding(None)], rule), [("evil-merge", None)])

    def test_another_signature_in_that_commit_is_still_reported(self):
        rule = [{"signature": "evil-merge", "commit": REVIEWED}]
        found = [_merge_finding(REVIEWED, "evil-merge-loader")]
        self.assertEqual(_reported(found, rule), [("evil-merge-loader", REVIEWED)])

    def test_a_rule_whose_commit_is_not_a_full_id_hides_nothing(self):
        for commit in (REVIEWED[:10], REVIEWED[:39], "", None, 0, [REVIEWED]):
            with self.subTest(commit=commit):
                rule = [{"signature": "evil-merge", "commit": commit}]
                self.assertEqual(_reported([_merge_finding(REVIEWED)], rule),
                                 [("evil-merge", REVIEWED)])


class ARuleWithAnUnknownKeyAcceptsNothing(unittest.TestCase):
    def test_a_misspelled_commit_key_hides_nothing_and_is_named(self):
        for key in ("comit", "Commit", "sha", "commits"):
            with self.subTest(key=key):
                rule = [{"signature": "evil-merge", key: REVIEWED}]
                found = [_merge_finding(REVIEWED), _merge_finding(SAME_SHORT_ID), _merge_finding(None)]
                result = finalize("repo", "local", {"git-history": found}, ["git-history"], [], [], None,
                                  None, rule, ALL_SIGNATURES)
                self.assertEqual(len(result.findings), 3)
                self.assertTrue(any(key in note and "accepts nothing" in note for note in result.notes),
                                result.notes)

    def test_a_known_rule_names_no_note(self):
        rule = [{"signature": "evil-merge", "commit": REVIEWED}]
        result = finalize("repo", "local", {"git-history": [_merge_finding(REVIEWED)]}, ["git-history"],
                          [], [], None, None, rule, ALL_SIGNATURES)
        self.assertFalse([note for note in result.notes if "accepts nothing" in note])


class APathGlobRuleIsUnchanged(unittest.TestCase):
    def _file_finding(self, path: str) -> Finding:
        return Finding("loader-seed-var", "code-loader", Severity.HIGH, path, "loader")

    def test_a_path_glob_rule_still_accepts_its_path_only(self):
        rule = [{"signature": "loader-seed-var", "path_glob": "tests/**"}]
        result = finalize("repo", "local",
                          {"content": [self._file_finding("tests/a.js"), self._file_finding("src/a.js")]},
                          ["content"], [], [], None, None, rule, ALL_SIGNATURES)
        self.assertEqual([f.path for f in result.findings], ["src/a.js"])


class ARuleShapeIsChecked(unittest.TestCase):
    def test_every_shape_saw_applies_is_accepted(self):
        for rule in ({"signature": "loader-seed-var", "path_glob": "tests/**"},
                     {"signature": "loader-seed-var"},
                     {"signature": "evil-merge", "commit": REVIEWED},
                     {"signature": "evil-merge", "commit": REVIEWED.upper()},
                     {"signature": "evil-merge", "commit": SHA256_ID},
                     {"signature": "evil-merge", "commit": REVIEWED, "evidence": "e"}):
            with self.subTest(rule=rule):
                self.assertTrue(allowlist_ok({"allowlist": [rule]}))

    def test_a_rule_naming_a_commit_any_other_way_is_refused(self):
        for commit in (REVIEWED[:10], REVIEWED[:39], REVIEWED + "0", SHA256_ID[:63],
                       SHA256_ID + "0", "g" * 40, REVIEWED + "\n", " " + REVIEWED,
                       "０" * 40, "", None, 1234, [REVIEWED]):
            with self.subTest(commit=commit):
                rule = {"signature": "evil-merge", "commit": commit}
                self.assertFalse(allowlist_ok({"allowlist": [rule]}))

    def test_a_rule_naming_both_a_path_glob_and_a_commit_is_refused(self):
        rule = {"signature": "evil-merge", "path_glob": "**", "commit": REVIEWED}
        self.assertFalse(allowlist_ok({"allowlist": [rule]}))

    def test_every_command_refuses_a_config_naming_a_shortened_commit(self):
        folder = Path(tempfile.mkdtemp(prefix="allowlist-commit-"))
        self.addCleanup(shutil.rmtree, folder, True)
        bad = folder / "security.yml"
        bad.write_text(f"allowlist:\n  - {{signature: evil-merge, commit: '{REVIEWED[:10]}'}}\n")
        said = io.StringIO()
        with redirect_stderr(said):
            self.assertIsNone(resolve_config(str(bad)))
        self.assertIn("full id", said.getvalue())
        self.assertFalse(usable(str(bad)))
        with self.assertRaises(ValueError):
            operator_policy(str(bad))

    def test_this_repositorys_config_applies(self):
        self.assertTrue(usable(str(REPO / "config" / "security.yml")))


if __name__ == "__main__":
    unittest.main()

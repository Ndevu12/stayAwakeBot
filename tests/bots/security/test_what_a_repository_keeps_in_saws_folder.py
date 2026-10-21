#!/usr/bin/env python3
"""Everything in saw's own folder is read. A copy an older `saw fix` kept is told apart only by what
the repository's history proves, and goes once its fix is committed."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import kept_copies
from stayawake.bots.security.models import CONFIRMED, INFECTED, RESIDUE, RESIDUE_VERDICT
from stayawake.bots.security.pr.fix_verdict import checkout_of
from stayawake.bots.security.remediation import live
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.targets.base import ScanOptions, Target
from tests.bots.security.test_a_merge_that_carries_a_known_payload import MARKERS, _Merges
from tests.support.gitrepo import GitSandbox

LOADER = "var _0x=String.fromCharCode(118,97,114);eval(_0x+\" x=1\");\n"
SIGS = load_signatures()


def _scan(target):
    return scan_target(target, SIGS, [])


def _found(result) -> set[tuple[str, str]]:
    return {(f.signature_id, f.path) for f in result.findings}


def _paths(result) -> set[str]:
    return {f.path for f in result.findings}


class _Repository(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.write(self.repo, "README.md", "# project\n")

    def committed(self, rel: str, text: str = LOADER) -> None:
        self.write(self.repo, rel, text)
        self.commit(self.repo, "add")

    def scan(self, opts: ScanOptions | None = None):
        return _scan(LocalRepoTarget(self.repo, "p", opts or ScanOptions()))

    def kept_by_an_older_fix(self, rel: str = "app.woff", *, fix_committed: bool = True) -> str:
        """Lay out what an older `saw fix` left: the infected version committed, its copy kept
        uncommitted, and the file rewritten. Returns the copy's path."""
        self.committed(".gitignore", ".saw/\n")
        self.committed(rel)
        copy = f".saw/rollback/{rel}"
        self.write(self.repo, copy, LOADER)
        self.write(self.repo, rel, "module.exports = 1;\n")
        if fix_committed:
            self.commit(self.repo, "the fix")
        return copy


class TestWhatARepositoryKeepsInSawsFolder(_Repository):
    def test_a_payload_committed_there_reads_infected(self):
        self.committed(".saw/text.woff")
        result = self.scan()
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".saw/text.woff", _paths(result))

    def test_one_committed_among_the_copies_reads_infected(self):
        self.committed(".saw/rollback/text.woff")
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_one_in_a_folder_of_that_name_further_down_reads_infected(self):
        self.committed("packages/app/.saw/text.woff")
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_one_there_that_is_not_committed_reads_infected(self):
        self.committed(".gitignore", ".saw/\n")
        self.write(self.repo, ".saw/text.woff", LOADER)
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_a_setting_that_leaves_saws_folder_out_still_reads_it(self):
        self.committed(".saw/text.woff")
        opts = ScanOptions(exclude_dirs=ScanOptions().exclude_dirs | {".saw"})
        self.assertEqual(INFECTED, self.scan(opts).verdict)

    def test_a_repository_committed_among_the_copies_is_read(self):
        library = self.new_repo("library")
        self.write(library, "text.woff", LOADER)
        self.commit(library, "add")
        self.git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library),
                 ".saw/rollback/sub")
        self.commit(self.repo, "a library")
        self.assertIn(".saw/rollback/sub/text.woff", _paths(self.scan()))

    def test_a_folder_named_rollback_you_leave_out_elsewhere_stays_out(self):
        self.committed("lib/rollback/text.woff")
        opts = ScanOptions(exclude_dirs=ScanOptions().exclude_dirs | {"rollback"})
        target = LocalRepoTarget(self.repo, "p", opts)
        self.assertNotIn("lib/rollback/text.woff", _paths(_scan(target)))
        self.assertIn("rollback", target.pruned_dirs)


class TestACopyTheHistoryProves(_Repository):
    def test_it_reads_residue_and_the_note_says_saw_fix_removes_it(self):
        copy = self.kept_by_an_older_fix()
        result = self.scan()
        self.assertEqual(RESIDUE_VERDICT, result.verdict)
        self.assertTrue(all(f.confidence == RESIDUE for f in result.findings if f.path == copy))
        self.assertIn(copy, _paths(result))
        self.assertTrue(any("Run `saw fix` to remove the 1 whose fix is committed" in n
                            for n in result.notes), result.notes)

    def test_its_fix_not_yet_committed_keeps_it_and_says_so(self):
        copy = self.kept_by_an_older_fix(fix_committed=False)
        result = self.scan()
        self.assertNotEqual(INFECTED, result.verdict)
        self.assertTrue(any("1 stay until their fix is committed" in n for n in result.notes))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / copy).exists())

    def test_one_put_back_over_its_committed_fix_is_kept(self):
        copy = self.kept_by_an_older_fix()
        self.write(self.repo, "app.woff", LOADER)
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / copy).exists())

    def test_saw_fix_removes_it_and_the_folders_it_leaves_empty(self):
        copy = self.kept_by_an_older_fix("src/app.woff")
        self.assertEqual(([copy], []), kept_copies.remove_fixed(self.repo))
        self.assertFalse((self.repo / ".saw").exists())

    def test_saw_fix_in_place_removes_it_and_says_so(self):
        copy = self.kept_by_an_older_fix()
        result = live.clean_checkout(self.repo, ScanOptions(), SIGS, [])
        self.assertEqual([copy], result.copies_removed)
        self.assertFalse((self.repo / copy).exists())
        _, detail = checkout_of(result)
        self.assertTrue(any("removed 1 file(s) an older `saw fix` kept as copies" in n
                            for n in detail.notes), detail.notes)

    def test_a_file_beside_it_the_history_does_not_prove_reads_infected_and_stays(self):
        self.kept_by_an_older_fix()
        self.write(self.repo, ".saw/rollback/other.woff", LOADER)
        result = self.scan()
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".saw/rollback/other.woff",
                      {f.path for f in result.findings if f.confidence == CONFIRMED})
        kept_copies.remove_fixed(self.repo)
        self.assertTrue((self.repo / ".saw/rollback/other.woff").exists())

    def test_one_committed_reads_infected_even_where_the_history_would_prove_it(self):
        copy = self.kept_by_an_older_fix()
        self.git(self.repo, "add", "-f", copy)
        self.commit(self.repo, "the copy")
        self.assertEqual(INFECTED, self.scan().verdict)
        self.assertEqual([], kept_copies.proven(self.repo))


class TestACopyTheHistoryDoesNotProve(_Repository):
    def test_bytes_committed_at_another_path_read_infected(self):
        self.committed(".gitignore", ".saw/\n")
        self.committed("lib/a.woff")
        self.write(self.repo, ".saw/rollback/b.woff", LOADER)
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_bytes_never_committed_read_infected(self):
        self.committed(".gitignore", ".saw/\n")
        self.write(self.repo, ".saw/rollback/app.woff", LOADER)
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_a_linked_rollback_folder_is_left_where_it_points(self):
        elsewhere = Path(tempfile.mkdtemp())
        (elsewhere / "app.woff").write_text(LOADER, encoding="utf-8")
        self.kept_by_an_older_fix()
        (self.repo / ".saw" / "rollback" / "app.woff").unlink()
        (self.repo / ".saw" / "rollback").rmdir()
        (self.repo / ".saw" / "rollback").symlink_to(elsewhere, target_is_directory=True)
        self.assertEqual([], kept_copies.proven(self.repo))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((elsewhere / "app.woff").exists())

    def test_a_linked_saw_folder_is_left_where_it_points(self):
        self.kept_by_an_older_fix()
        elsewhere = Path(tempfile.mkdtemp())
        (self.repo / ".saw").rename(elsewhere / ".saw")
        (self.repo / ".saw").symlink_to(elsewhere / ".saw", target_is_directory=True)
        self.assertEqual([], kept_copies.proven(self.repo))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((elsewhere / ".saw/rollback/app.woff").exists())

    def test_bytes_only_another_ref_holds_read_infected(self):
        self.committed(".gitignore", ".saw/\n")
        self.git(self.repo, "checkout", "-q", "-b", "elsewhere")
        self.committed("app.woff")
        self.git(self.repo, "update-ref", "refs/x/hidden", "HEAD")
        self.git(self.repo, "checkout", "-q", "main")
        self.git(self.repo, "branch", "-D", "elsewhere")
        self.write(self.repo, ".saw/rollback/app.woff", LOADER)
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_a_repository_among_them_reads_infected_and_stays(self):
        self.committed(".gitignore", ".saw/\n")
        self.committed("sub/text.woff")
        self.committed("sub/text.woff", "module.exports = 1;\n")
        library = self.new_repo("library")
        self.write(library, "text.woff", LOADER)
        self.commit(library, "add")
        self.git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", "-f",
                 str(library), ".saw/rollback/sub")
        self.commit(self.repo, "a library")
        self.assertEqual(INFECTED, self.scan().verdict)
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / ".saw/rollback/sub/text.woff").exists())

    def test_one_inside_a_repository_nested_among_them_reads_infected(self):
        copy = self.kept_by_an_older_fix("sub/text.woff")
        self.git(self.repo / ".saw/rollback/sub", "init", "-q")
        self.assertEqual(INFECTED, self.scan().verdict)
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / copy).exists())

    def test_a_committed_folder_named_otherwise_than_saw_names_it_is_left_alone(self):
        self.committed("config.json", '{"a": 1}\n')
        self.committed("config.json", '{"a": 2}\n')
        self.committed(".saw/Rollback/config.json", '{"a": 1}\n')
        self.assertEqual([], kept_copies.proven(self.repo))
        kept_copies.remove_fixed(self.repo)
        self.assertIn(".saw/Rollback/config.json", self.git(self.repo, "ls-files"))
        self.assertEqual("", self.git(self.repo, "status", "--porcelain"))

    def test_a_repository_among_them_that_lost_its_marker_is_still_left_alone(self):
        self.test_a_repository_among_them_reads_infected_and_stays()
        (self.repo / ".saw/rollback/sub/.git").unlink()
        self.assertEqual([], kept_copies.proven(self.repo))

    def test_a_copy_git_tracks_in_another_letter_case_is_left_alone(self):
        copy = self.kept_by_an_older_fix()
        blob = self.git(self.repo, "hash-object", "-w", str(self.repo / copy)).strip()
        self.git(self.repo, "update-index", "--add", "--cacheinfo",
                 f"100644,{blob},.saw/Rollback/app.woff")
        self.assertEqual([], kept_copies.proven(self.repo))

    def test_a_folder_named_otherwise_than_saw_names_it_is_not_its_copies(self):
        self.committed(".gitignore", ".saw/\n")
        self.committed("app.woff")
        self.committed("app.woff", "module.exports = 1;\n")
        self.write(self.repo, ".saw/Rollback/app.woff", LOADER)
        self.assertEqual([], kept_copies.proven(self.repo))
        kept_copies.remove_fixed(self.repo)
        self.assertTrue((self.repo / ".saw/Rollback/app.woff").exists())

    def test_a_saw_folder_that_is_a_repository_is_left_alone(self):
        copy = self.kept_by_an_older_fix()
        self.git(self.repo / ".saw", "init", "-q")
        self.assertEqual([], kept_copies.proven(self.repo))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / copy).exists())

    def test_one_the_current_commit_stores_is_left_alone_after_it_leaves_the_index(self):
        copy = self.kept_by_an_older_fix()
        self.git(self.repo, "add", "-f", copy)
        self.commit(self.repo, "the copy")
        self.git(self.repo, "rm", "-q", "--cached", copy)
        self.assertEqual([], kept_copies.proven(self.repo))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo))
        self.assertTrue((self.repo / copy).exists())

    def test_one_git_tracks_under_another_unicode_form_is_left_alone(self):
        self.git(self.repo, "config", "core.precomposeunicode", "false")
        decomposed, composed = "cafe\u0301.woff", "caf\u00e9.woff"
        copy = self.kept_by_an_older_fix(decomposed)
        blob = self.git(self.repo, "hash-object", "-w", str(self.repo / copy)).strip()
        self.git(self.repo, "update-index", "--add", "--cacheinfo",
                 f"100644,{blob},.saw/rollback/{composed}")
        self.assertEqual([], kept_copies.proven(self.repo))

    def test_copies_in_a_folder_below_the_repositorys_top_are_left_alone(self):
        self.git(self.repo, "config", "diff.relative", "true")
        self.committed(".gitignore", ".saw/\n")
        self.committed("sub/app.woff")
        self.committed("sub/app.woff", "module.exports = 1;\n")
        self.write(self.repo, "sub/.saw/rollback/app.woff", LOADER)
        self.assertEqual([], kept_copies.proven(self.repo / "sub"))
        self.assertEqual(([], []), kept_copies.remove_fixed(self.repo / "sub"))
        self.assertTrue((self.repo / "sub/.saw/rollback/app.woff").exists())

    def test_one_too_large_to_prove_reads_on_its_evidence(self):
        self.kept_by_an_older_fix()
        with mock.patch.object(kept_copies, "_LARGEST_COPY", 8):
            self.assertEqual([], kept_copies.proven(self.repo))
            self.assertEqual(INFECTED, self.scan().verdict)

    def test_git_failing_to_say_errors_the_target(self):
        self.kept_by_an_older_fix()
        with mock.patch.object(kept_copies, "stdout_bytes", return_value=None):
            result = self.scan()
        self.assertIsNotNone(result.error)


class TestALinkInSawsFolder(_Repository):
    def test_one_leading_out_of_the_repository_is_found(self):
        outside = Path(tempfile.mkdtemp()) / "shared"
        outside.mkdir()
        (self.repo / ".saw").mkdir()
        (self.repo / ".saw" / "lib").symlink_to(outside, target_is_directory=True)
        self.assertIn(("symlink-escapes-repo", ".saw/lib"), _found(self.scan()))


class TestAFolderThatIsNotARepository(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())

    def put(self, rel: str) -> None:
        path = self.folder / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(LOADER, encoding="utf-8")

    def test_a_payload_in_saws_folder_reads_infected(self):
        self.put(".saw/text.woff")
        self.assertEqual(INFECTED, _scan(Target(self.folder, "f", ScanOptions())).verdict)

    def test_a_payload_among_the_copies_reads_infected(self):
        self.put("project/.saw/rollback/text.woff")
        self.assertEqual(INFECTED, _scan(Target(self.folder, "f", ScanOptions())).verdict)


class TestAMergeThatAddsAPayloadInSawsFolder(_Merges):
    def test_it_reads_infected(self):
        repo = self.merged(".saw/.gitignore", "node_modules/\n" + MARKERS, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(CONFIRMED, finding.confidence)
        self.assertEqual((".saw/.gitignore",), finding.payload_paths)


if __name__ == "__main__":
    unittest.main()

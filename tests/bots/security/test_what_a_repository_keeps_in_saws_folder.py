#!/usr/bin/env python3
"""A file a repository keeps in saw's own folder is read like any other; the copies `saw fix` keeps
there are not."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.models import CONFIRMED, INFECTED
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service import workers
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


class _Repository(GitSandbox):
    def setUp(self):
        super().setUp()
        self.repo = self.new_repo()
        self.write(self.repo, "README.md", "# project\n")

    def committed(self, rel: str, text: str = LOADER) -> None:
        self.write(self.repo, rel, text)
        self.commit(self.repo, "add")

    def scan(self):
        return _scan(LocalRepoTarget(self.repo, "p", ScanOptions()))


class TestWhatARepositoryCommitsInSawsFolder(_Repository):
    def test_a_payload_committed_there_reads_infected(self):
        self.committed(".saw/text.woff")
        result = self.scan()
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".saw/text.woff", {path for _, path in _found(result)})

    def test_one_committed_among_the_rollback_copies_reads_infected(self):
        self.committed(".saw/rollback/text.woff")
        result = self.scan()
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".saw/rollback/text.woff", {path for _, path in _found(result)})

    def test_one_in_a_folder_of_that_name_further_down_reads_infected(self):
        self.committed("packages/app/.saw/text.woff")
        self.assertEqual(INFECTED, self.scan().verdict)

    def test_one_there_that_is_not_committed_reads_infected(self):
        self.committed(".gitignore", ".saw/\n")
        self.write(self.repo, ".saw/text.woff", LOADER)
        self.assertEqual(INFECTED, self.scan().verdict)


class TestTheCopiesSawFixKeeps(_Repository):
    def test_they_are_not_read(self):
        self.committed(".gitignore", ".saw/\n")
        self.write(self.repo, ".saw/rollback/fonts/text.woff", LOADER)
        result = self.scan()
        self.assertEqual([], result.findings)
        self.assertIsNone(result.error)

    def test_a_committed_one_beside_them_is_read_and_they_are_not(self):
        self.committed(".saw/rollback/committed.woff")
        self.write(self.repo, ".saw/rollback/kept.woff", LOADER)
        paths = {path for _, path in _found(self.scan())}
        self.assertIn(".saw/rollback/committed.woff", paths)
        self.assertNotIn(".saw/rollback/kept.woff", paths)

    def test_a_folder_of_that_name_you_leave_out_elsewhere_stays_out(self):
        self.committed("lib/rollback/text.woff")
        opts = ScanOptions(exclude_dirs=ScanOptions().exclude_dirs | {"rollback"})
        target = LocalRepoTarget(self.repo, "p", opts)
        self.assertNotIn("lib/rollback/text.woff", {path for _, path in _found(_scan(target))})
        self.assertIn("rollback", target.pruned_dirs)

    def test_a_link_in_their_place_is_not_read_through(self):
        elsewhere = self.new_repo("elsewhere")
        self.write(elsewhere, "text.woff", LOADER)
        self.commit(elsewhere, "add")
        (self.repo / ".saw").mkdir()
        (self.repo / ".saw" / "rollback").symlink_to(elsewhere, target_is_directory=True)
        paths = {path for _, path in _found(self.scan())}
        self.assertFalse(any(path.startswith(".saw/rollback/") for path in paths), paths)


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

    def test_the_copies_saw_fix_keeps_are_not_read_and_the_note_says_so(self):
        self.put("project/.saw/rollback/text.woff")
        target = Target(self.folder, "f", ScanOptions())
        result = _scan(target)
        self.assertEqual([], result.findings)
        self.assertIsNotNone(workers.pruning_note(target.pruned_dirs))

    def test_a_scan_that_leaves_nothing_out_reads_them(self):
        self.put(".saw/rollback/text.woff")
        opts = ScanOptions(exclude_dirs={".git"})
        self.assertEqual(INFECTED, _scan(Target(self.folder, "f", opts)).verdict)


class TestAMergeThatAddsAPayloadInSawsFolder(_Merges):
    def test_it_reads_infected(self):
        repo = self.merged(".saw/.gitignore", "node_modules/\n" + MARKERS, conflict=False)
        [finding] = self.merge_findings(repo)
        self.assertEqual(CONFIRMED, finding.confidence)
        self.assertEqual((".saw/.gitignore",), finding.payload_paths)


if __name__ == "__main__":
    unittest.main()

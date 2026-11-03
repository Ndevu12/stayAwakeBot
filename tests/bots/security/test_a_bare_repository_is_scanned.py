#!/usr/bin/env python3
"""A repository with no working tree is scanned. Its files are read, and a scan that cannot read
them is not clean."""
from __future__ import annotations

import shutil
from pathlib import Path

from stayawake.bots.security.models import CLEAN, INFECTED
from stayawake.bots.security.resolution import resolve_local_targets
from stayawake.bots.security.service import workers
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions
from tests.support.gitrepo import GitSandbox
from tests.support.samples import INFECTED_PROJECT

SIGS = load_signatures()
_TASK = INFECTED_PROJECT[".vscode/tasks.json"]()


class TestABareRepositoryIsScanned(GitSandbox):
    def _one(self, path: Path):
        found = resolve_local_targets([str(path)], ScanOptions())
        self.assertEqual(len(found), 1, found)
        return found[0]

    def _scanned(self, path: Path, *, history: bool = False):
        """Scan one named path the way the worker scans it. Returns the result."""
        scope = self._one(path)
        opts = ScanOptions(history=history)
        return workers.scan_local(workers.LocalScanJob(scope, str(path), opts, SIGS, [])).result

    def _mirror(self) -> Path:
        repo = self.new_repo("src")
        self.write(repo, ".vscode/tasks.json", _TASK)
        self.commit(repo, "add the task")
        mirror = self.owned(self.root / "mirror.git")
        self.git(repo, "clone", "--mirror", str(repo), str(mirror))
        return mirror

    def test_a_checkout_still_reads_its_work_tree(self):
        repo = self.new_repo("checkout")
        self.write(repo, ".vscode/tasks.json", _TASK)
        result = self._scanned(repo)
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".vscode/tasks.json", {f.path for f in result.findings})

    def test_the_files_it_holds_are_read(self):
        mirror = self._mirror()
        self.assertTrue(self._one(mirror).is_repo)
        result = self._scanned(mirror, history=True)
        self.assertEqual(INFECTED, result.verdict)
        self.assertIn(".vscode/tasks.json", {f.path for f in result.findings})
        self.assertNotIn("not a repository", " ".join(result.notes))

    def test_one_that_cannot_be_read_is_not_clean(self):
        mirror = self._mirror()
        shutil.rmtree(mirror / "objects")
        (mirror / "objects").mkdir()
        result = self._scanned(mirror, history=True)
        self.assertTrue(result.error)
        self.assertNotEqual(INFECTED, result.verdict)
        self.assertNotIn("not a repository", " ".join(result.notes))

    def test_a_git_directory_git_cannot_answer_is_not_clean(self):
        folder = self.owned(self.root / "broken.git")
        (folder / "refs" / "heads").mkdir(parents=True)
        (folder / "objects").mkdir()
        (folder / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (folder / "refs" / "heads" / "main").write_text("a" * 40 + "\n", encoding="utf-8")
        result = self._scanned(folder)
        self.assertTrue(result.error)
        self.assertNotIn("not a repository", " ".join(result.notes))

    def test_an_empty_bare_repository_is_clean(self):
        empty = self.owned(self.root / "empty.git")
        self.git(self.new_repo("holder"), "init", "--bare", str(empty))
        result = self._scanned(empty)
        self.assertEqual(CLEAN, result.verdict)
        self.assertFalse(result.error)
        self.assertNotIn("not a repository", " ".join(result.notes))

    def test_a_directory_with_only_a_head_file_is_not_a_repository(self):
        folder = self.owned(self.root / "partial")
        folder.mkdir()
        (folder / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (folder / "README.md").write_text("hello\n", encoding="utf-8")
        self.assertFalse(self._one(folder).is_repo)

    def test_a_sweep_finds_a_bare_repository(self):
        mirror = self._mirror()
        found = [t for t in resolve_local_targets([str(self.root)], ScanOptions())
                 if t.root == mirror.resolve()]
        self.assertTrue(found and found[0].is_repo)

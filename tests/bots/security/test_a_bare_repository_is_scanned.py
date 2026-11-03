#!/usr/bin/env python3
"""A repository with no working tree is scanned. Its files are read, and a scan that cannot read
them is not clean."""
from __future__ import annotations

import io
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security.resolution import resolve_local_targets
from stayawake.bots.security.targets import ScanOptions
from tests.support.gitrepo import GitSandbox
from tests.support.samples import INFECTED_PROJECT


def _report(target: Path, *, history: bool = False) -> str:
    """The terminal report a scan of `target` prints."""
    from stayawake.bots.security import service
    cfg = target.parent / "saw-config"
    cfg.mkdir(exist_ok=True)
    (cfg / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        service.scan(str(cfg / "c.yml"), paths=[str(target)], no_stream=True,
                     no_advisories=True, history=history)
    return out.getvalue()


class TestABareRepositoryIsScanned(GitSandbox):
    def _mirror(self) -> Path:
        repo = self.new_repo("src")
        self.write(repo, ".vscode/tasks.json", INFECTED_PROJECT[".vscode/tasks.json"]())
        self.commit(repo, "add the task")
        mirror = self.owned(self.root / "mirror.git")
        self.git(repo, "clone", "--mirror", str(repo), str(mirror))
        return mirror

    def test_a_checkout_still_reads_its_work_tree(self):
        repo = self.new_repo("checkout")
        self.write(repo, ".vscode/tasks.json", INFECTED_PROJECT[".vscode/tasks.json"]())
        report = _report(repo)
        self.assertIn("INFECTED", report)
        self.assertIn(".vscode/tasks.json", report)

    def test_the_files_it_holds_are_read(self):
        mirror = self._mirror()
        resolved = resolve_local_targets([str(mirror)], ScanOptions())
        self.assertTrue(resolved[0].is_repo)
        report = _report(mirror, history=True)
        self.assertIn("INFECTED", report)
        self.assertIn(".vscode/tasks.json", report)
        self.assertNotIn("not a repository", report)

    def test_one_that_cannot_be_read_is_not_clean(self):
        mirror = self._mirror()
        shutil.rmtree(mirror / "objects")
        (mirror / "objects").mkdir()
        report = _report(mirror, history=True)
        self.assertIn("ERROR", report)
        self.assertNotIn("INFECTED", report)
        self.assertNotIn("not a repository", report)

    def test_a_git_directory_git_cannot_answer_is_not_clean(self):
        folder = self.owned(self.root / "broken.git")
        folder.mkdir()
        (folder / "HEAD").write_text("not a ref\n", encoding="utf-8")
        (folder / "objects").mkdir()
        (folder / "refs").mkdir()
        report = _report(folder)
        self.assertIn("ERROR", report)
        self.assertNotIn("not a repository", report)

    def test_an_empty_bare_repository_is_clean(self):
        empty = self.owned(self.root / "empty.git")
        self.git(self.new_repo("holder"), "init", "--bare", str(empty))
        report = _report(empty)
        self.assertIn("clean", report)
        self.assertNotIn("ERROR", report)
        self.assertNotIn("not a repository", report)

    def test_a_directory_with_only_a_head_file_is_not_a_repository(self):
        folder = self.owned(self.root / "partial")
        folder.mkdir()
        (folder / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (folder / "README.md").write_text("hello\n", encoding="utf-8")
        self.assertIn("not a repository", _report(folder))

    def test_a_sweep_finds_a_bare_repository(self):
        mirror = self._mirror()
        found = [t for t in resolve_local_targets([str(self.root)], ScanOptions())
                 if t.root == mirror.resolve()]
        self.assertTrue(found and found[0].is_repo)

    def test_a_directory_is_still_not_a_repository(self):
        folder = self.owned(self.root / "plain")
        folder.mkdir()
        (folder / "README.md").write_text("hello\n", encoding="utf-8")
        resolved = resolve_local_targets([str(folder)], ScanOptions())
        self.assertFalse(resolved[0].is_repo)
        self.assertIn("not a repository", _report(folder))

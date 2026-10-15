#!/usr/bin/env python3
"""saw's hooks check the merges that landed since the history was last found clean: every merge of
the branch the first time and after new rules, a merge a reset brought in, and a known merge each time."""
from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hook
from tests.bots.security.test_hook import _INFECTED, _Isolated, _repo, _run


class _Watched(_Isolated):
    def setUp(self):
        super().setUp()
        self.given: list = []
        self.reported: list = []
        scan, tell = hook._scan_within_budget, hook._tell

        def scan_noting(root, include, config_path, display, merges=None):
            self.given.append(merges)
            return scan(root, include, config_path, display, merges)

        def tell_noting(result, *args, **kwargs):
            self.reported.append({f.category for f in result.findings})
            return tell(result, *args, **kwargs)

        for name, stand_in in (("_scan_within_budget", scan_noting), ("_tell", tell_noting)):
            patcher = mock.patch.object(hook, name, side_effect=stand_in)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _repository(self) -> Path:
        repo = _repo({"README.md": "readme\n", "app.js": "base\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        self._in_repo(repo)
        return repo

    def _merge(self, repo: Path, branch: str, *, payload: bool = False) -> str:
        _run(repo, "checkout", "-q", "-b", branch)
        (repo / f"{branch}.js").write_text(f"{branch}\n")
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", f"{branch} work")
        _run(repo, "checkout", "-q", "-")
        (repo / f"main-{branch}.js").write_text("main\n")
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", f"main work beside {branch}")
        _run(repo, "merge", "--no-ff", "--no-commit", "-q", branch)
        if payload:
            (repo / "payload.js").write_text("PAYLOAD\n")
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", f"Merge branch '{branch}'")
        return hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()

    def _pull_event(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            hook.run_event("post-merge", ["0"])

    def _merge_reported(self) -> bool:
        return "evil-merge" in self.reported[-1]


class TestTheHooksCheckWhatLanded(_Watched):
    def test_a_clean_history_is_checked_once_then_only_the_merges_after_it(self):
        repo = self._repository()
        first = self._merge(repo, "one")
        self._pull_event()
        self.assertEqual(self.given[-1], [first])
        second = self._merge(repo, "two")
        self._pull_event()
        self.assertEqual(self.given[-1], [second])

    def test_a_merge_a_reset_brought_in_is_checked_at_the_next_event(self):
        repo = self._repository()
        self._merge(repo, "one")
        self._pull_event()
        self.assertFalse(self._merge_reported())
        _run(repo, "checkout", "-q", "-b", "elsewhere")
        self._merge(repo, "bad", payload=True)
        bad = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        _run(repo, "checkout", "-q", "master" if hook.gitutil.run_ok(repo, ["rev-parse", "--verify", "master"])
             else "main")
        _run(repo, "reset", "-q", "--hard", bad)
        self._pull_event()
        self.assertTrue(self._merge_reported())

    def test_a_known_merge_is_reported_at_every_event(self):
        repo = self._repository()
        self._merge(repo, "bad", payload=True)
        self._pull_event()
        self._pull_event()
        self.assertTrue(all("evil-merge" in seen for seen in self.reported[-2:]), self.reported)

    def test_new_rules_check_every_merge_of_the_branch_again(self):
        repo = self._repository()
        first = self._merge(repo, "one")
        self._pull_event()
        second = self._merge(repo, "two")
        with mock.patch.object(hook, "_policy_digest", return_value="new rules"):
            self._pull_event()
        self.assertEqual(sorted(self.given[-1]), sorted([first, second]))

    def test_a_merge_on_another_branch_is_checked_when_that_branch_is_checked_out(self):
        repo = self._repository()
        here = hook.gitutil.stdout(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
        old = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        _run(repo, "checkout", "-q", "-b", "backup")
        self._merge(repo, "bad", payload=True)
        new = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        _run(repo, "checkout", "-q", here)
        self._merge(repo, "fine")
        self._pull_event()
        self.assertFalse(self._merge_reported())
        _run(repo, "checkout", "-q", "backup")
        with contextlib.redirect_stderr(io.StringIO()):
            hook.run_event("post-checkout", [old, new, "1"])
        self.assertTrue(self._merge_reported())

    def test_a_clone_checks_the_merges_of_every_branch(self):
        repo = self._repository()
        self._merge(repo, "one")
        head = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        with contextlib.redirect_stderr(io.StringIO()):
            hook.run_event("post-checkout", [hook._NULL_REV, head, "1"])
        self.assertIsNone(self.given[-1])


class TestOnlyACompleteCheckIsRecorded(_Watched):
    def test_more_merges_than_are_checked_are_never_recorded_as_clean(self):
        from stayawake.bots.security.models import ScanResult
        result = ScanResult(target="t", source="local")
        many = ["a" * 40] * (hook.MOST_MERGES_CHECKED + 1)
        self.assertFalse(hook._history_found_clean(result, many))
        self.assertTrue(hook._history_found_clean(result, many[:1]))
        self.assertFalse(hook._history_found_clean(result, None))

    def test_a_recorded_commit_the_repository_no_longer_has_is_not_trusted(self):
        repo = self._repository()
        self._merge(repo, "one")
        self._pull_event()
        self.assertIsNotNone(hook._history_checked(repo, None))
        held = hook.hookscript.history_checked_path()
        held.write_text(held.read_text().replace(hook._history_checked(repo, None), "f" * 40))
        self.assertIsNone(hook._history_checked(repo, None))


class TestNothingThatLandedGoesUnchecked(_Watched):
    def _rev(self, repo: Path) -> str:
        return hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()

    def _worm_commit(self, repo: Path, branch: str) -> str:
        _run(repo, "checkout", "-q", "-b", branch)
        (repo / ".gitignore").write_text(_INFECTED)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "theirs")
        commit = self._rev(repo)
        _run(repo, "checkout", "-q", "-")
        return commit

    def test_a_file_checkout_does_not_quiet_a_known_merge(self):
        repo = self._repository()
        self._merge(repo, "bad", payload=True)
        self._pull_event()
        self.assertTrue(self._merge_reported())
        head = self._rev(repo)
        (repo / "README.md").write_text("edited\n")
        _run(repo, "checkout", "--", "README.md")
        with contextlib.redirect_stderr(io.StringIO()):
            hook.run_event("post-checkout", [head, head, "0"])
        self._merge(repo, "next")
        self._pull_event()
        self.assertTrue(self._merge_reported())

    def test_a_shallow_repository_is_never_recorded_as_checked(self):
        import subprocess
        import tempfile
        origin = self._repository()
        self._merge(origin, "one")
        clone = Path(tempfile.mkdtemp(prefix="shallow-")) / "clone"
        self.addCleanup(lambda: __import__("shutil").rmtree(clone.parent, ignore_errors=True))
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{origin}", str(clone)],
                       check=True, capture_output=True)
        for cmd in (["config", "user.email", "t@t"], ["config", "user.name", "t"],
                    ["config", "commit.gpgsign", "false"]):
            _run(clone, *cmd)
        self._in_repo(clone)
        before = self._rev(clone)
        (clone / "new.js").write_text("new\n")
        _run(clone, "add", "-A")
        _run(clone, "commit", "-qm", "new")
        _run(clone, "update-ref", "ORIG_HEAD", before)
        self._pull_event()
        self.assertIsNone(hook._history_checked(clone, None))

    def test_an_amend_after_a_reset_scans_what_the_reset_brought_in(self):
        repo = self._repository()
        theirs = self._worm_commit(repo, "theirs")
        _run(repo, "reset", "-q", "--hard", theirs)
        _run(repo, "commit", "-q", "--amend", "-m", "reworded")
        amended = self._rev(repo)
        with contextlib.redirect_stderr(io.StringIO()):
            code = hook._run_event("post-rewrite", ["amend"], None, rewritten=f"{theirs} {amended}\n")
        self.assertEqual(code, 1)

    def test_a_commit_picked_from_another_branch_is_scanned_for_its_own_change(self):
        repo = self._repository()
        before = self._rev(repo)
        picked = self._worm_commit(repo, "other")
        _run(repo, "cherry-pick", picked)
        _run(repo, "update-ref", "ORIG_HEAD", before)
        include, label = hook._scan_scope("post-rewrite", ["rebase"], repo, None,
                                          f"{picked} {self._rev(repo)}\n")
        self.assertIn(".gitignore", include)


class TestARewriteIsScannedForWhatItChanged(_Watched):
    def _commit(self, repo: Path, files: dict[str, str]) -> str:
        for name, text in files.items():
            (repo / name).write_text(text)
        _run(repo, "add", "-A")
        _run(repo, "commit", "-qm", "work")
        return hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()

    def test_an_amend_is_scanned_for_the_files_it_changed(self):
        repo = self._repository()
        old = self._commit(repo, {f"f{n}.js": f"{n}\n" for n in range(5)})
        (repo / "f1.js").write_text("changed\n")
        _run(repo, "commit", "-qa", "--amend", "--no-edit")
        new = hook.gitutil.stdout(repo, ["rev-parse", "HEAD"]).strip()
        include, label = hook._scan_scope("post-rewrite", ["amend"], repo, None, f"{old} {new}\n")
        self.assertEqual((include, label), (("f1.js",), "rewrite"))

    def test_a_rewrite_with_nothing_to_compare_scans_the_whole_tree(self):
        repo = self._repository()
        _run(repo, "update-ref", "-d", "ORIG_HEAD")
        self.assertEqual(hook._scan_scope("post-rewrite", ["amend"], repo, None, ""), (None, "rewrite"))

    def test_a_line_that_names_no_commits_is_never_handed_to_git(self):
        self.assertEqual(hook._rewritten_pairs("--output=/tmp/x HEAD\nnot a pair\n"), [])


class TestTheRewriteHookHandsOnWhatGitGaveIt(unittest.TestCase):
    def test_saw_and_your_own_hook_each_read_the_rewritten_commits(self):
        import subprocess
        import tempfile
        folder = Path(tempfile.mkdtemp(prefix="rewrite-hook-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, ignore_errors=True))
        saw = folder / "saw"
        saw.write_text(f'#!/bin/sh\ncat > "{folder}/saw-read"\n')
        theirs = folder / "post-rewrite.local"
        theirs.write_text(f'#!/bin/sh\ncat > "{folder}/theirs-read"\n')
        script = folder / "post-rewrite"
        script.write_text(hook.hookscript.render("post-rewrite", str(saw), None))
        for path in (saw, theirs, script):
            os.chmod(path, 0o755)
        pairs = "a" * 40 + " " + "b" * 40 + "\n"
        done = subprocess.run([str(script), "amend"], input=pairs, text=True, capture_output=True)
        self.assertEqual(done.returncode, 0)
        self.assertEqual((folder / "saw-read").read_text(), pairs)
        self.assertEqual((folder / "theirs-read").read_text(), pairs)

    def test_the_push_hook_says_what_to_do_when_git_lfs_is_missing(self):
        script = hook.hookscript.render("pre-push", "/usr/local/bin/saw", None)
        self.assertIn("Install Git LFS, then push again.", script)


class TestAHookAnEarlierSawInstalledIsBroughtUpToDate(_Isolated):
    def _outdated(self) -> list[Path]:
        saw = hook._saw_executable()
        written = []
        for event in ("post-rewrite", "pre-push"):
            path = hook._hooks_dir() / event
            path.write_text(hook.hookscript.render_previous(event, saw, None))
            os.chmod(path, 0o755)
            written.append(path)
        return written

    def test_install_brings_them_up_to_date_without_a_warning_or_a_kept_copy(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(hook.install(), 0)
        for path in self._outdated():
            self.assertEqual(hook.hookscript.verdict(path), hook.hookscript.OUTDATED)
        self.assertEqual(hook.hookscript.altered_hooks(), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(hook.install(), 0)
        self.assertNotIn("had been changed", out.getvalue())
        self.assertNotIn("was not saw's", out.getvalue())
        for event in ("post-rewrite", "pre-push"):
            self.assertEqual(hook.hookscript.verdict(hook._hooks_dir() / event), hook.hookscript.PRISTINE)
        kept = hook.hookscript.set_aside_dir()
        self.assertFalse(kept.exists() and any(kept.iterdir()))

    def test_repair_brings_a_repositorys_outdated_hook_up_to_date(self):
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.install(repositories=[str(repo)]), 0)
        rewrite = repo / ".git" / "hooks" / "post-rewrite"
        rewrite.write_text(hook.hookscript.render_previous("post-rewrite", hook._saw_executable(), None))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hook.repair(), 0)
        self.assertEqual(hook.hookscript.verdict(rewrite), hook.hookscript.PRISTINE)
        self.assertNotIn("had been changed", out.getvalue())

    def test_a_saw_hook_under_another_events_name_is_not_saws_own(self):
        saw = hook._saw_executable()
        folder = hook._hooks_dir()
        folder.mkdir(parents=True, exist_ok=True)
        for script in (hook.hookscript.render("post-checkout", saw, None),
                       hook.hookscript.render_previous("post-rewrite", saw, None)):
            path = folder / "pre-push"
            path.write_text(script)
            os.chmod(path, 0o755)
            self.assertEqual(hook.hookscript.verdict(path, (saw, None)), hook.hookscript.ALTERED)

    def test_uninstall_removes_them(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.install(), 0)
        self._outdated()
        repo = _repo({"a.txt": "x\n"})
        self.addCleanup(lambda: __import__("shutil").rmtree(repo, ignore_errors=True))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hook.install(repositories=[str(repo)]), 0)
        in_repo = repo / ".git" / "hooks" / "pre-push"
        in_repo.write_text(hook.hookscript.render_previous("pre-push", hook._saw_executable(), None))
        self._outdated()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(hook.uninstall(), 0)
        self.assertEqual([e for e in hook._HOOKS if (hook._hooks_dir() / e).exists()], [])
        self.assertFalse(in_repo.exists())
        self.assertNotIn("was not saw's", out.getvalue())
        kept = hook.hookscript.set_aside_dir()
        self.assertFalse(kept.exists() and any(kept.iterdir()))


if __name__ == "__main__":
    unittest.main()

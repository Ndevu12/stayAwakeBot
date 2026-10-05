"""The outbound hook reports what a push would publish, and never stops the push."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hookscript, outbound, push_record, version_scan
from stayawake.bots.security.matchers import git_history
from stayawake.bots.security.matchers.installed_package_audit import InstalledPackageAuditMatcher
from stayawake.bots.security.targets import HistoryTarget, LocalRepoTarget, PushedTarget, ScanOptions
from stayawake.lib.git import objects, pushed
from stayawake.utils import env

_PAYLOAD = "node_modules\ntemp_auto_push.bat\nbranch_structure.json\n"
_ZERO = "0" * 40


class _Sandbox(unittest.TestCase):
    """Each test gets its own HOME, XDG dirs and git configuration, and a work repo with a remote."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="push-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        (self.home / "gitconfig").write_text("[user]\n\temail = t@t\n\tname = t\n[commit]\n"
                                             "\tgpgsign = false\n[init]\n\tdefaultBranch = main\n")
        patched = mock.patch.dict(os.environ, {
            "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_CACHE_HOME": str(self.home / ".cache"),
            "XDG_STATE_HOME": str(self.home / ".local" / "state"),
            "GIT_CONFIG_GLOBAL": str(self.home / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1"})
        patched.start()
        self.addCleanup(patched.stop)
        for name in ("SAW_HOOK_DISABLED", "SAW_HOOK_TIMEOUT"):
            os.environ.pop(name, None)
        self.remote = self.home / "remote.git"
        self.work = self.home / "work"
        self.git(self.home, "init", "-q", "--bare", str(self.remote))
        self.git(self.home, "init", "-q", str(self.work))
        self.commit({"app.js": "export const x = 1;\n"}, "base")
        self.git(self.work, "remote", "add", "origin", str(self.remote))
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")

    def git(self, where, *args) -> str:
        return subprocess.run(["git", "-C", str(where), *args], check=True, capture_output=True,
                              text=True).stdout.strip()

    def commit(self, files: dict[str, str | None], message="work", where=None) -> str:
        where = where or self.work
        for rel, content in files.items():
            path = Path(where) / rel
            if content is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.git(where, "add", "-A")
        self.git(where, "commit", "-qm", message)
        return self.git(where, "rev-parse", "HEAD")

    def remote_tip(self, ref: str) -> str:
        found = subprocess.run(["git", "-C", str(self.remote), "rev-parse", "--verify", "-q", ref],
                               capture_output=True, text=True).stdout.strip()
        return found or _ZERO

    def line(self, ref: str, remote_ref: str | None = None, where=None) -> str:
        local = self.git(where or self.work, "rev-parse", ref)
        remote_ref = remote_ref or ref
        return f"{ref} {local} {remote_ref} {self.remote_tip(remote_ref)}\n"

    def check(self, refs: str, argv=("origin", "url"), where=None, **kw) -> tuple[int, str]:
        cwd = os.getcwd()
        os.chdir(where or self.work)
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                code = outbound.check_push(list(argv), refs, None, **kw)
        finally:
            os.chdir(cwd)
        return code, " ".join(err.getvalue().split())


class TestWhatThePushSendsIsJudged(_Sandbox):
    """The report is about the objects the push sends, not about the working copy."""

    def test_a_payload_on_the_checked_out_branch_is_reported(self):
        self.commit({".gitignore": _PAYLOAD})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)
        self.assertIn("WORM DETECTED", text)

    def test_a_branch_that_is_not_checked_out_is_judged(self):
        self.git(self.work, "switch", "-qc", "feature")
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "switch", "-q", "main")
        code, text = self.check(self.line("refs/heads/feature"))
        self.assertEqual(code, 1, text)

    def test_a_working_copy_that_differs_from_the_commit_does_not_hide_it(self):
        self.commit({".gitignore": _PAYLOAD})
        (self.work / ".gitignore").write_text("dist/\n")
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)

    def test_a_payload_removed_later_in_the_same_push_is_still_reported(self):
        self.commit({".gitignore": _PAYLOAD})
        self.commit({".gitignore": None}, "later")
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)

    def test_a_pushed_tag_is_judged(self):
        self.git(self.work, "switch", "-qc", "side")
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "tag", "-a", "v1", "-m", "release")
        self.git(self.work, "switch", "-q", "main")
        code, text = self.check(self.line("refs/tags/v1"))
        self.assertEqual(code, 1, text)

    def test_an_uncommitted_payload_is_not_reported_as_pushed(self):
        self.commit({".gitignore": "dist/\n"})
        (self.work / ".gitignore").write_text(_PAYLOAD)
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 0, text)
        self.assertNotIn("WORM DETECTED", text)

    def test_a_payload_filed_under_two_names_is_reported(self):
        self.commit({"-notes.txt": _PAYLOAD, ".gitignore": _PAYLOAD})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)
        self.assertIn(".gitignore", text)

    def test_a_payload_moved_to_where_it_runs_is_reported(self):
        self.commit({"notes.txt": _PAYLOAD}, "inert")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.git(self.work, "mv", "notes.txt", ".gitignore")
        self.git(self.work, "commit", "-qm", "moved")
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)

    def test_a_push_from_a_bare_repository_is_judged(self):
        self.commit({".gitignore": _PAYLOAD})
        mirror = self.home / "mirror.git"
        self.git(self.home, "clone", "-q", "--mirror", str(self.work), str(mirror))
        local = self.git(mirror, "rev-parse", "refs/heads/main")
        refs = f"refs/heads/main {local} refs/heads/main {_ZERO}\n"
        code, text = self.check(refs, where=mirror)
        self.assertEqual(code, 1, text)


class TestWhatTheRemoteAlreadyHolds(_Sandbox):
    """A payload is reported wherever the push publishes it, and only there."""

    def test_a_push_to_a_second_remote_is_reported(self):
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        local = self.git(self.work, "rev-parse", "HEAD")
        refs = f"refs/heads/main {local} refs/heads/main {_ZERO}\n"
        code, text = self.check(refs, argv=("mirror", "/elsewhere.git"))
        self.assertEqual(code, 1, text)

    def test_a_payload_pushed_back_to_a_cleaned_remote_is_reported(self):
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.git(self.work, "fetch", "-q", "origin")
        clean = self.git(self.remote, "rev-parse", "main~1")
        self.git(self.remote, "update-ref", "refs/heads/main", clean)
        self.git(self.work, "switch", "-qc", "topic")
        self.commit({"more.js": "export const y = 2;\n"})
        local = self.git(self.work, "rev-parse", "HEAD")
        code, text = self.check(f"refs/heads/topic {local} refs/heads/topic {_ZERO}\n")
        self.assertEqual(code, 1, text)

    def test_a_push_over_remote_work_this_clone_never_saw_is_reported(self):
        self.commit({".gitignore": _PAYLOAD})
        local = self.git(self.work, "rev-parse", "HEAD")
        code, text = self.check(f"refs/heads/main {local} refs/heads/main {'ab' * 20}\n")
        self.assertEqual(code, 1, text)

    def test_what_the_remote_already_holds_is_not_reported_again(self):
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 0, text)


class TestWhatABranchWillServe(_Sandbox):
    """A push that makes a branch serve a payload again is reported, and a clean branch is quiet."""

    def _cleaned(self) -> tuple[str, str]:
        infected = self.commit({".gitignore": _PAYLOAD}, "infected")
        cleaned = self.commit({".gitignore": None}, "cleaned")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        return infected, cleaned

    def test_a_stale_branch_forced_over_a_cleaned_one_is_reported(self):
        infected, cleaned = self._cleaned()
        self.git(self.work, "switch", "-qc", "stale", infected)
        local = self.commit({"local.txt": "local\n"})
        code, text = self.check(f"refs/heads/stale {local} refs/heads/main {cleaned}\n")
        self.assertEqual(code, 1, text)
        self.assertIn(".gitignore", text)

    def test_a_branch_rewound_to_an_infected_commit_is_reported(self):
        infected, cleaned = self._cleaned()
        code, text = self.check(f"refs/heads/main {infected} refs/heads/main {cleaned}\n")
        self.assertEqual(code, 1, text)
        self.assertNotIn("This machine may be infected", text)

    def test_new_work_carrying_a_worm_suggests_checking_the_machine(self):
        self.commit({".gitignore": _PAYLOAD})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)
        self.assertIn("This machine may be infected", text)

    def test_a_new_branch_from_a_cleaned_one_names_the_history_it_carries(self):
        self._cleaned()
        self.git(self.work, "fetch", "-q", "origin")
        self.git(self.work, "switch", "-qc", "feature")
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/feature"))
        self.assertEqual(code, 1, text)
        self.assertNotIn("WORM DETECTED", text)
        self.assertIn("an older commit in this push", text)

    def test_a_new_branch_on_history_the_remote_purged_is_reported(self):
        infected, cleaned = self._cleaned()
        self.git(self.work, "fetch", "-q", "origin")
        base = self.git(self.work, "rev-parse", f"{infected}~1")
        other = self.home / "other"
        self.git(self.home, "clone", "-q", str(self.remote), str(other))
        self.git(other, "reset", "-q", "--hard", base)
        self.commit({"clean.js": "export const c = 0;\n"}, "rewritten", where=other)
        self.git(other, "push", "-q", "--no-verify", "-f", "origin", "main")
        self.git(self.remote, "reflog", "expire", "--expire=now", "--all")
        self.git(self.remote, "gc", "-q", "--prune=now")
        self.git(self.work, "switch", "-qc", "topic", cleaned)
        local = self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(f"refs/heads/topic {local} refs/heads/topic {_ZERO}\n")
        self.assertEqual(code, 1, text)

    def test_a_new_tag_on_a_stale_commit_is_reported(self):
        infected, _cleaned = self._cleaned()
        self.git(self.work, "fetch", "-q", "origin")
        self.git(self.work, "tag", "old", infected)
        code, text = self.check(f"refs/tags/old {infected} refs/tags/old {_ZERO}\n")
        self.assertEqual(code, 1, text)

    def test_history_the_remote_no_longer_holds_is_judged_again(self):
        base = self.git(self.work, "rev-parse", "HEAD")
        self.git(self.work, "switch", "-qc", "side")
        self.commit({".gitignore": _PAYLOAD})
        self.git(self.work, "push", "-q", "--no-verify", "origin", "side")
        other = self.home / "other"
        self.git(self.home, "clone", "-q", "--branch", "side", str(self.remote), str(other))
        self.git(other, "reset", "-q", "--hard", base)
        rewritten = self.commit({"clean.js": "export const c = 0;\n"}, "rewritten", where=other)
        self.git(other, "push", "-q", "--no-verify", "-f", "origin", "side")
        self.commit({".gitignore": None}, "removed")
        local = self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(f"refs/heads/side {local} refs/heads/side {rewritten}\n")
        self.assertEqual(code, 1, text)


class TestItNeverReadsAsCleanWhenUnsure(_Sandbox):
    """A push that could not be checked says so; nothing but a full read says it was checked."""

    def test_a_line_not_in_gits_form_is_reported_not_verified(self):
        code, text = self.check("garbage\n")
        self.assertEqual(code, 2)
        self.assertIn("NOT verified", text)

    def test_git_failing_to_list_the_push_is_reported_not_verified(self):
        self.commit({".gitignore": _PAYLOAD})
        refs = self.line("refs/heads/main")
        with mock.patch.object(pushed, "own_view_fed", return_value=None):
            code, text = self.check(refs)
        self.assertEqual(code, 2)
        self.assertIn("NOT verified", text)

    def test_a_scan_that_runs_out_of_time_is_reported_and_finished_next_time(self):
        self.commit({".gitignore": _PAYLOAD})
        refs = self.line("refs/heads/main")
        real = outbound._scan_batch

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        with mock.patch.object(outbound, "_scan_batch", slow):
            code, text = self.check(refs)
        self.assertEqual(code, 2, text)
        self.assertIn("did not finish checking", text)
        self.assertIn("NOT verified", text)
        self.assertNotIn("no worm found", text)
        del os.environ["SAW_HOOK_TIMEOUT"]
        self.commit({"more.js": "export const y = 2;\n"})
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main~1:main")
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)

    def _small_reads(self):
        from stayawake.bots.security import hook_policy
        real = hook_policy.operator_policy

        def small(config_path):
            policy = real(config_path)
            policy.opts.max_file_bytes = 1_000
            return policy

        return mock.patch.object(outbound, "operator_policy", small)

    def test_a_version_too_large_to_read_in_full_is_said_so_every_time(self):
        self.commit({"big.js": "// padding\n" * 500})
        refs = self.line("refs/heads/main")
        with self._small_reads():
            first = self.check(refs)
            second = self.check(refs)
        for code, text in (first, second):
            self.assertEqual(code, 0, text)
            self.assertIn("too large to read in full", text)

    def test_the_budget_counts_from_the_start_of_the_check(self):
        self.commit({"more.js": "export const y = 2;\n"})
        refs = self.line("refs/heads/main")
        real_policy, real_batch = outbound.operator_policy, outbound._scan_batch

        def slow_policy(config_path):
            time.sleep(1.0)
            return real_policy(config_path)

        def slow_batch(*args, **kw):
            time.sleep(3.0)
            return real_batch(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "1.5"
        started = time.monotonic()
        with mock.patch.object(outbound, "operator_policy", slow_policy), \
                mock.patch.object(outbound, "_scan_batch", slow_batch):
            code, text = self.check(refs)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(code, 2, text)

    def test_this_push_is_read_before_what_an_earlier_check_left(self):
        infected = self.commit({".gitignore": _PAYLOAD}, "infected")
        cleaned = self.commit({".gitignore": None}, "cleaned")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        record = push_record.load(self.work / ".git", "unused")
        record.where.parent.mkdir(parents=True, exist_ok=True)
        pending = [{"path": f"old/{n}.js", "oid": self.git(self.work, "rev-parse", "HEAD:app.js"),
                    "commit": cleaned, "link": False} for n in range(300)]
        record.where.write_text(json.dumps({"policy": "", "verified": [], "pending": pending}))
        order: list[str] = []
        real = outbound._scan_batch

        def spy(progress, git_dir, display, batch, *rest):
            order.extend(e.path for e in batch)
            return real(progress, git_dir, display, batch, *rest)

        with mock.patch.object(outbound, "_scan_batch", spy):
            code, text = self.check(f"refs/heads/main {infected} refs/heads/main {cleaned}\n")
        self.assertEqual(code, 1, text)
        self.assertEqual(order[0], ".gitignore")

    def test_versions_that_cannot_be_kept_for_later_are_named(self):
        self.commit({f"f{n}.js": f"export const v = {n};\n" for n in range(6)})
        real = outbound._scan_batch

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        with mock.patch.object(outbound, "_scan_batch", slow), \
                mock.patch.object(push_record, "MAX_PENDING", 2):
            code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 2, text)
        self.assertIn("could not be kept for a later push", text)

    def test_a_version_that_could_not_be_read_is_never_called_clean(self):
        from stayawake.bots.security.targets import history, pushed as pushed_target
        self.commit({"more.js": "export const y = 2;\n"})

        def unreadable(self, sha):
            raise OSError("unreadable")

        with mock.patch.object(pushed_target, "read_blobs", return_value=({}, {})), \
                mock.patch.object(history.HistoryTarget, "_cat_file", unreadable):
            code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 2, text)
        self.assertIn("NOT verified", text)
        self.assertNotIn("✓", text)

    def test_time_running_out_while_history_is_listed_is_never_called_clean(self):
        self._with_history()
        self.git(self.work, "switch", "-qc", "feature")
        self.commit({"new.js": "export const n = 3;\n"})
        real = pushed.history_entries

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        with mock.patch.object(pushed, "history_entries", slow):
            code, text = self.check(self.line("refs/heads/feature"))
        self.assertEqual(code, 2, text)
        self.assertNotIn("✓", text)
        self.assertIn("your new changes", text)
        self.assertIn("NOT verified", text)

    def _with_history(self):
        self.commit({"a.js": "export const v = 1;\n"}, "v1")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.git(self.work, "fetch", "-q", "origin")

    def test_history_left_unlisted_is_finished_on_the_next_push(self):
        infected = self.commit({".gitignore": _PAYLOAD}, "infected")
        self.commit({".gitignore": None}, "cleaned")
        self.git(self.work, "switch", "-qc", "feature")
        self.commit({"new.js": "export const n = 3;\n"})
        real = pushed.history_entries

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        with mock.patch.object(pushed, "history_entries", slow):
            code, text = self.check(self.line("refs/heads/feature"), argv=("/new.git", "/new.git"))
        self.assertEqual(code, 2, text)
        self.assertIn("saw will finish the check the next time", text)
        del os.environ["SAW_HOOK_TIMEOUT"]
        self.git(self.work, "push", "-q", "--no-verify", "origin", "feature")
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/feature"))
        self.assertEqual(code, 1, text)
        self.assertIn("an earlier push from this repository", text)
        self.assertIn(infected[:10], text)

    def test_own_changes_are_called_checked_only_once_they_were_read(self):
        self.commit({".gitignore": _PAYLOAD}, "own work")
        self.commit({".gitignore": None}, "tidied")
        real = pushed.history_entries

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        local = self.git(self.work, "rev-parse", "HEAD")
        with mock.patch.object(pushed, "history_entries", slow):
            code, text = self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                                    argv=("/new.git", "/new.git"))
        self.assertNotIn("your new changes", text)
        self.assertIn("NOT verified", text)

    def test_history_carried_from_a_url_push_is_later_worded_as_history(self):
        infected = self.commit({".gitignore": _PAYLOAD}, "infected")
        self.commit({".gitignore": None}, "cleaned")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.git(self.work, "fetch", "-q", "origin")
        real = pushed.history_entries

        def slow(*args, **kw):
            time.sleep(8)
            return real(*args, **kw)

        os.environ["SAW_HOOK_TIMEOUT"] = "4"
        local = self.git(self.work, "rev-parse", "HEAD")
        with mock.patch.object(pushed, "history_entries", slow):
            self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                       argv=("/elsewhere.git", "/elsewhere.git"))
        del os.environ["SAW_HOOK_TIMEOUT"]
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertIn("a commit in an earlier push", text)
        self.assertNotIn("This machine may be infected", text)
        self.assertIn(infected[:10], text)

    def test_commits_listed_by_this_push_are_not_kept_for_later(self):
        self.commit({"a.js": "export const v = 1;\n"}, "v1")
        listed = self.git(self.work, "rev-parse", "HEAD")
        record = push_record.load(self.work / ".git", "unused")
        record.where.parent.mkdir(parents=True, exist_ok=True)
        record.where.write_text(json.dumps({"policy": "", "verified": [], "pending": [],
                                            "unlisted": [{"commit": listed, "parents": [],
                                                          "role": "history"}]}))
        local = self.git(self.work, "rev-parse", "HEAD")
        asked: list[str] = []
        real = pushed.history_entries

        def spy(repo, commits, **kw):
            asked.extend(commit for commit, _parents in commits)
            return real(repo, commits, **kw)

        with mock.patch.object(pushed, "history_entries", spy):
            self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                       argv=("/new.git", "/new.git"))
        self.assertEqual(asked.count(listed), 1)
        self.assertEqual(json.loads(record.where.read_text())["unlisted"], [])

    def test_old_history_sent_to_an_unfamiliar_url_does_not_blame_this_machine(self):
        self._cleaned_main()
        local = self.git(self.work, "rev-parse", "HEAD")
        code, text = self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                                argv=("/new.git", "/new.git"))
        self.assertEqual(code, 1, text)
        self.assertNotIn("This machine may be infected", text)

    def _cleaned_main(self):
        self.commit({".gitignore": _PAYLOAD}, "infected")
        self.commit({".gitignore": None}, "cleaned")

    def test_a_url_spelled_another_way_is_the_same_remote(self):
        url = self.git(self.work, "remote", "get-url", "origin")
        for spelling in (url + "/", "file://" + url, url.removesuffix(".git") + ".git/"):
            self.assertEqual(pushed.remote_for_url(self.work / ".git", spelling), "origin", spelling)

    def test_the_count_is_this_push_only(self):
        oid = self.git(self.work, "rev-parse", "HEAD:app.js")
        record = push_record.load(self.work / ".git", "unused")
        record.where.parent.mkdir(parents=True, exist_ok=True)
        record.where.write_text(json.dumps({"policy": "", "verified": [], "pending": [
            {"path": f"old/{n}.js", "oid": oid, "commit": "", "link": False} for n in range(5)]}))
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertIn("(1 file checked)", text)

    def test_what_an_earlier_check_left_is_named_as_an_earlier_push(self):
        infected = self.commit({".gitignore": _PAYLOAD}, "infected")
        oid = self.git(self.work, "rev-parse", "HEAD:.gitignore")
        self.commit({".gitignore": None}, "cleaned")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        record = push_record.load(self.work / ".git", "unused")
        record.where.parent.mkdir(parents=True, exist_ok=True)
        record.where.write_text(json.dumps({"policy": "", "verified": [], "pending": [
            {"path": ".gitignore", "oid": oid, "commit": infected, "link": False}]}))
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 1, text)
        self.assertIn("an earlier push from this repository", text)
        self.assertNotIn("an older commit in this push", text)

    def test_the_check_failing_is_reported_as_a_failure_not_a_result(self):
        self.commit({".gitignore": _PAYLOAD})
        with mock.patch.object(version_scan, "scan_target", side_effect=RuntimeError("boom")):
            code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 2)
        self.assertIn("could not check this push", text)
        self.assertIn("NOT verified", text)
        self.assertNotIn("RuntimeError", text)

    def test_a_deletion_in_a_sha256_repository_is_quiet(self):
        code, text = self.check(f"(delete) {'0' * 64} refs/heads/gone {'1' * 64}\n")
        self.assertEqual((code, text), (0, ""))


class TestTheReportSaysWhatTheUserNeeds(_Sandbox):
    """The report reads as plain words through the shared writer, and only an all-clear gets a tick."""

    def test_a_suspicious_push_is_never_called_clean(self):
        self.commit({"x.js": "eval(atob('ZG9jdW1lbnQ='))\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertIn("look", text)
        self.assertIn("x.js", text)
        self.assertNotIn("✓", text)

    def test_a_clean_push_gets_the_all_clear(self):
        self.commit({"more.js": "export const y = 2;\n"})
        code, text = self.check(self.line("refs/heads/main"))
        self.assertEqual(code, 0, text)
        self.assertIn("✓", text)

    def test_the_report_is_written_by_the_shared_writer(self):
        self.commit({"more.js": "export const y = 2;\n"})
        with mock.patch.object(outbound, "say") as said:
            self.check(self.line("refs/heads/main"), no_stream=True)
        said.assert_called_once()
        self.assertTrue(said.call_args.kwargs["no_stream"])


class TestAVersionCheckedCleanIsNotCheckedAgain(_Sandbox):
    """A clean version is checked once per policy; a payload is reported on every push."""

    def _scanned(self, refs) -> list[str]:
        seen: list[str] = []
        real = outbound._scan_batch

        def spy(progress, git_dir, display, batch, *rest):
            seen.extend(e.path for e in batch)
            return real(progress, git_dir, display, batch, *rest)

        with mock.patch.object(outbound, "_scan_batch", spy):
            self.check(refs)
        return seen

    def test_a_version_checked_clean_is_not_read_again(self):
        self.commit({"more.js": "export const y = 2;\n"})
        refs = self.line("refs/heads/main")
        self.assertIn("more.js", self._scanned(refs))
        self.assertNotIn("more.js", self._scanned(refs))

    def test_a_push_to_an_unfamiliar_url_reads_what_it_serves_first(self):
        self.commit({"old.js": "export const o = 1;\n"}, "v1")
        old = self.git(self.work, "rev-parse", "HEAD:old.js")
        self.commit({"old.js": None}, "v2")
        seen: list[str] = []
        real = outbound._scan_batch

        def spy(progress, git_dir, display, batch, *rest):
            seen.extend(e.oid for e in batch)
            return real(progress, git_dir, display, batch, *rest)

        local = self.git(self.work, "rev-parse", "HEAD")
        with mock.patch.object(outbound, "_scan_batch", spy):
            self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                       argv=("/new.git", "/new.git"))
        self.assertLess(seen.index(self.git(self.work, "rev-parse", "HEAD:app.js")), seen.index(old))

    def test_a_newly_added_remote_reads_what_it_serves_first(self):
        self.commit({"old.js": "export const o = 1;\n"}, "v1")
        old = self.git(self.work, "rev-parse", "HEAD:old.js")
        self.commit({"old.js": None}, "v2")
        self.git(self.work, "remote", "add", "mirror", str(self.home / "mirror.git"))
        seen: list[str] = []
        real = outbound._scan_batch

        def spy(progress, git_dir, display, batch, *rest):
            seen.extend(e.oid for e in batch)
            return real(progress, git_dir, display, batch, *rest)

        local = self.git(self.work, "rev-parse", "HEAD")
        with mock.patch.object(outbound, "_scan_batch", spy):
            self.check(f"refs/heads/main {local} refs/heads/main {_ZERO}\n",
                       argv=("mirror", str(self.home / "mirror.git")))
        self.assertLess(seen.index(self.git(self.work, "rev-parse", "HEAD:app.js")), seen.index(old))

    def test_a_new_branch_reads_its_own_work_first(self):
        self.commit({"a.js": "export const v = 1;\n"}, "v1")
        self.git(self.work, "push", "-q", "--no-verify", "origin", "main")
        self.git(self.work, "fetch", "-q", "origin")
        self.git(self.work, "switch", "-qc", "feature")
        self.commit({"new.js": "export const n = 3;\n"})
        seen: list[str] = []
        real = outbound._scan_batch

        def spy(progress, git_dir, display, batch, *rest):
            seen.extend(e.path for e in batch)
            return real(progress, git_dir, display, batch, *rest)

        with mock.patch.object(outbound, "_scan_batch", spy):
            self.check(self.line("refs/heads/feature"))
        self.assertEqual(seen[0], "new.js")
        self.assertIn("a.js", seen)

    def test_a_payload_is_read_on_every_push_that_carries_it(self):
        self.commit({".gitignore": _PAYLOAD})
        refs = self.line("refs/heads/main")
        self.assertEqual(self.check(refs)[0], 1)
        self.assertEqual(self.check(refs)[0], 1)

    def test_a_different_policy_reads_everything_again(self):
        self.commit({"more.js": "export const y = 2;\n"})
        refs = self.line("refs/heads/main")
        self._scanned(refs)
        with mock.patch.object(push_record, "policy_digest", return_value="another"):
            self.assertIn("more.js", self._scanned(refs))


class TestAPushNamesOnlyWhatItAdds(unittest.TestCase):
    """Reading git's ref lines and the merge scope the push carries."""

    def test_sha1_and_sha256_lines_are_read(self):
        lines = (f"refs/heads/a {'1' * 40} refs/heads/a {'0' * 40}\n"
                 f"(delete) {'0' * 64} refs/heads/b {'2' * 64}\n")
        updates = pushed.read_push_updates(lines)
        self.assertEqual([u.publishes for u in updates], [True, False])

    def test_a_malformed_line_is_not_read_as_nothing(self):
        self.assertIsNone(pushed.read_push_updates("refs/heads/a 12 refs/heads/a 34\n"))

    def test_named_merges_are_the_only_merges_judged(self):
        target = PushedTarget(".", "x", ScanOptions(), {}, {}, ["m" * 40])
        with mock.patch.object(git_history.gitutil, "merge_commits",
                               side_effect=AssertionError("walked every merge")), \
                mock.patch.object(git_history.gitutil, "evil_merge_paths", return_value={}) as judged, \
                mock.patch.object(git_history.gitutil, "borrowed_or_none",
                                  return_value=contextlib.nullcontext(None)):
            git_history.GitHistoryMatcher().scan(target, [{"id": "e", "kind": "evil-merge"}])
        self.assertEqual([c.args[1] for c in judged.call_args_list], ["m" * 40])

    def test_a_push_with_no_merges_judges_none(self):
        target = PushedTarget(".", "x", ScanOptions(), {}, {}, [])
        with mock.patch.object(git_history.gitutil, "merge_commits",
                               side_effect=AssertionError("walked every merge")):
            self.assertEqual(git_history.GitHistoryMatcher().scan(
                target, [{"id": "e", "kind": "evil-merge"}]), [])


class TestReadingAheadChangesNothingButTime(_Sandbox):
    """Versions read in one pass are judged exactly as versions read one by one."""

    def test_the_findings_are_identical(self):
        from stayawake.bots.security.hook_policy import operator_policy
        from stayawake.bots.security.scanner import scan_target
        big = "// padding\n" * 40_000 + "export const x = 1;\n"
        self.commit({".gitignore": _PAYLOAD, "big.js": big, "a/.gitignore": _PAYLOAD,
                     "ok.js": "export const y = 2;\n"})
        tree = self.git(self.work, "ls-tree", "-r", "HEAD").splitlines()
        versions = {line.split("\t")[1]: line.split()[2] for line in tree}
        policy = operator_policy(None)
        policy.opts.max_file_bytes = 100_000
        seen = []
        for read_ahead in (False, True):
            target = PushedTarget(self.work / ".git", "w", policy.opts, versions, {}, [])
            if not read_ahead:
                target.read_ahead = {}
            else:
                self.assertIn(versions[".gitignore"], target.read_ahead)
                self.assertNotIn(versions["big.js"], target.read_ahead)
            result = scan_target(target, policy.signatures, policy.allowlist)
            seen.append(sorted(json.dumps(f.to_dict(), sort_keys=True, default=str)
                               for f in result.findings))
        self.assertEqual(seen[0], seen[1])
        self.assertTrue(seen[0])


class TestSmallFilesAreAlwaysReadAhead(_Sandbox):
    """Small versions are read first, so a crowd of large ones never leaves them out."""

    def test_the_smallest_are_kept_when_the_total_runs_out(self):
        big = self.commit({"big.js": "x" * 50_000})
        big_oid = self.git(self.work, "rev-parse", "HEAD:big.js")
        self.commit({"small.txt": "tiny\n"})
        small_oid = self.git(self.work, "rev-parse", "HEAD:small.txt")
        read, _sizes = objects.read_blobs(self.work / ".git", [big_oid, small_oid], max_each=100_000,
                                          max_total=50_000)
        self.assertIn(small_oid, read)
        self.assertNotIn(big_oid, read)


class TestStoredContentIsNotJudgedByTheCheckout(unittest.TestCase):
    """A scan of stored versions never reports what is installed or left in the working copy."""

    def test_installed_packages_are_not_read_for_stored_versions(self):
        for target in (HistoryTarget(".", "x", ScanOptions(), {}), PushedTarget(".", "x", ScanOptions(), {})):
            matcher = InstalledPackageAuditMatcher()
            with mock.patch.object(matcher, "_trees", [mock.Mock(read=mock.Mock(
                    side_effect=AssertionError("read the checkout")))]):
                self.assertEqual(matcher.scan(target, []), [])

    def test_the_scan_of_stored_versions_takes_nothing_from_the_working_copy(self):
        from stayawake.bots.security import scanner
        for target in (HistoryTarget(".", "x", ScanOptions(), {}), PushedTarget(".", "x", ScanOptions(), {})):
            with mock.patch.object(scanner, "run_matchers", return_value={}), \
                    mock.patch.object(scanner, "finalize") as finalize:
                scanner.scan_target(target, {}, [])
            self.assertIsNone(finalize.call_args.args[7])

    def test_a_checkout_target_still_reads_installed_packages(self):
        with tempfile.TemporaryDirectory() as d, LocalRepoTarget(d, "x", ScanOptions()) as target:
            tree = mock.Mock(read=mock.Mock(return_value=iter(())), ghost_reconcilable=False)
            matcher = InstalledPackageAuditMatcher()
            with mock.patch.object(matcher, "_trees", [tree]):
                matcher.scan(target, [])
            tree.read.assert_called_once()


class TestTheBudget(unittest.TestCase):
    """A push is bounded more tightly than an arriving clone, and the operator's value wins."""

    def test_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SAW_HOOK_TIMEOUT", None)
            self.assertEqual(env.hook_timeout("pre-push"), 20.0)
            self.assertEqual(env.hook_timeout("post-merge"), 60.0)
            self.assertEqual(env.hook_timeout(), 60.0)

    def test_the_operator_overrides_every_event(self):
        with mock.patch.dict(os.environ, {"SAW_HOOK_TIMEOUT": "5"}):
            self.assertEqual(env.hook_timeout("pre-push"), 5.0)


class TestTheInstalledHookEndToEnd(_Sandbox):
    """A real `git push` through the installed hook: the report appears and the push goes through."""

    def _install(self, where: Path):
        saw = self.home / "saw"
        saw.write_text(f"#!/bin/sh\nexec {sys.executable} -m stayawake \"$@\"\n")
        saw.chmod(0o755)
        hook = where / "pre-push"
        hook.write_text(hookscript.render("pre-push", str(saw), None))
        hook.chmod(0o755)
        return hook

    def _push(self, *refspec, extra_env=None):
        env_now = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
        env_now.update(extra_env or {})
        return subprocess.run(["git", "-C", str(self.work), "push", "origin", *refspec],
                              capture_output=True, text=True, env=env_now)

    def test_a_payload_push_is_reported_and_goes_through(self):
        self._install(self.work / ".git" / "hooks")
        self.commit({".gitignore": _PAYLOAD})
        done = self._push("main")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("WORM DETECTED", " ".join(done.stderr.split()))
        self.assertEqual(self.remote_tip("refs/heads/main"), self.git(self.work, "rev-parse", "HEAD"))

    def test_a_chained_hook_gets_the_refs_and_keeps_its_verdict_without_a_temp_file(self):
        hooks = self.work / ".git" / "hooks"
        self._install(hooks)
        got = self.home / "got"
        (hooks / "pre-push.local").write_text(f'#!/bin/sh\ncat > "{got}"\nexit 1\n')
        (hooks / "pre-push.local").chmod(0o755)
        failing = self.home / "bin"
        failing.mkdir()
        (failing / "mktemp").write_text("#!/bin/sh\nexit 1\n")
        (failing / "mktemp").chmod(0o755)
        self.commit({"more.js": "export const y = 2;\n"})
        done = self._push("main", extra_env={"PATH": f"{failing}{os.pathsep}{os.environ['PATH']}"})
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("refs/heads/main", got.read_text())
        self.assertIn("no worm found", " ".join(done.stderr.split()))


class TestLargeFileStorageStillUploads(_Sandbox):
    """In a repository git-lfs has set up, the upload git-lfs's own hook would do still happens."""

    def setUp(self):
        super().setUp()
        TestTheInstalledHookEndToEnd._install(self, self.work / ".git" / "hooks")
        self.bin = self.home / "bin"
        self.bin.mkdir()
        self.calls = self.home / "lfs-calls"

    def _fake_lfs(self, exit_code: int):
        tool = self.bin / "git-lfs"
        tool.write_text(f'#!/bin/sh\necho "$@" >> "{self.calls}"\ncat >> "{self.calls}"\n'
                        f"exit {exit_code}\n")
        tool.chmod(0o755)

    def _push(self):
        return TestTheInstalledHookEndToEnd._push(
            self, "main", extra_env={"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"})

    def test_git_lfs_gets_the_push_and_keeps_its_verdict(self):
        self.git(self.work, "config", "--local", "lfs.repositoryformatversion", "0")
        self._fake_lfs(0)
        self.commit({"more.js": "export const y = 2;\n"})
        self.assertEqual(self._push().returncode, 0)
        calls = self.calls.read_text()
        self.assertIn("pre-push origin", calls)
        self.assertIn("refs/heads/main", calls)
        self._fake_lfs(1)
        self.commit({"again.js": "export const z = 3;\n"})
        self.assertNotEqual(self._push().returncode, 0)

    def test_a_repository_git_lfs_never_set_up_is_left_alone(self):
        self._fake_lfs(1)
        self.commit({"more.js": "export const y = 2;\n"})
        self.assertEqual(self._push().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_a_chained_hook_takes_the_place_of_the_upload(self):
        self.git(self.work, "config", "--local", "lfs.repositoryformatversion", "0")
        self._fake_lfs(1)
        local = self.work / ".git" / "hooks" / "pre-push.local"
        local.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n")
        local.chmod(0o755)
        self.commit({"more.js": "export const y = 2;\n"})
        self.assertEqual(self._push().returncode, 0)
        self.assertFalse(self.calls.exists())

if __name__ == "__main__":
    unittest.main()

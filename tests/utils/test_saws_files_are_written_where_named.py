#!/usr/bin/env python3
"""saw writes its own files where they were named: never through a link someone else could have
planted, and in one step or not at all."""
from __future__ import annotations

import errno
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hook, hookscript, liveledger, schedule
from stayawake.bots.security.dependencies import db
from stayawake.bots.security.harden import live
from stayawake.bots.security.hygiene.autorun import baseline
from stayawake.lib import github_app
from stayawake.utils import atomicwrite, io, pathsafe


class _Sandbox(unittest.TestCase):

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="saw-writes-"))
        self.addCleanup(shutil.rmtree, self.base, True)
        self.elsewhere = self.base / "elsewhere"
        self.elsewhere.mkdir()

    def as_root(self):
        patched = mock.patch.object(pathsafe, "trusted_link_owners", return_value={0})
        patched.start()
        self.addCleanup(patched.stop)

    def landed_elsewhere(self) -> list[str]:
        return sorted(str(p.relative_to(self.elsewhere)) for p in self.elsewhere.rglob("*"))


class TestTheWriterStaysWhereItWasNamed(_Sandbox):

    def test_as_root_a_users_link_at_the_files_own_name_is_refused(self):
        (self.base / "state").mkdir()
        (self.base / "state" / "record.json").symlink_to(self.elsewhere / "made-through-the-link")
        self.as_root()
        self.assertFalse(atomicwrite.replace(self.base / "state" / "record.json", "{}"))
        self.assertEqual([], self.landed_elsewhere())

    def test_as_the_user_their_own_link_at_the_files_name_is_written_through(self):
        (self.base / "state").mkdir()
        (self.base / "state" / "record.json").symlink_to(self.elsewhere / "dotfiles-record.json")
        self.assertTrue(atomicwrite.replace(self.base / "state" / "record.json", "{}",
                                            at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
        self.assertTrue((self.base / "state" / "record.json").is_symlink())
        self.assertEqual(b"{}", (self.elsewhere / "dotfiles-record.json").read_bytes())

    def test_as_root_a_users_link_at_the_name_is_followed_by_no_writer(self):
        (self.base / "state").mkdir()
        (self.base / "state" / "record.json").symlink_to(self.elsewhere / "made-through-the-link")
        self.as_root()
        self.assertFalse(atomicwrite.replace(self.base / "state" / "record.json", "{}",
                                             at_a_link=atomicwrite.FOLLOW_A_TRUSTED_LINK))
        self.assertTrue(atomicwrite.replace(self.base / "state" / "record.json", "{}",
                                            at_a_link=atomicwrite.REPLACE_A_LINK))
        self.assertFalse((self.base / "state" / "record.json").is_symlink())
        self.assertEqual([], self.landed_elsewhere())

    def test_a_folder_that_can_be_passed_through_but_not_listed_is_passed_through(self):
        (self.base / "passage" / "inner").mkdir(parents=True)
        os.chmod(self.base / "passage", 0o111)
        self.addCleanup(os.chmod, self.base / "passage", 0o755)
        self.assertTrue(atomicwrite.replace(self.base / "passage" / "inner" / "record.json", "{}"))

    def test_a_plain_write_keeps_the_umask_and_an_existing_files_mode(self):
        before = os.umask(0o077)
        self.addCleanup(os.umask, before)
        fresh = self.base / "state" / "fresh.json"
        self.assertTrue(atomicwrite.replace(fresh, "{}", mode=atomicwrite.AS_A_PLAIN_WRITE))
        self.assertEqual(0o600, fresh.stat().st_mode & 0o777)
        existing = self.base / "state" / "existing.json"
        existing.write_text("old", encoding="utf-8")
        os.chmod(existing, 0o640)
        self.assertTrue(atomicwrite.replace(existing, "{}", mode=atomicwrite.AS_A_PLAIN_WRITE))
        self.assertEqual(0o640, existing.stat().st_mode & 0o777)

    def test_a_folders_mode_is_given_to_that_folder_alone(self):
        before = os.umask(0o022)
        self.addCleanup(os.umask, before)
        atomicwrite.make_folder(self.base / "a" / "b" / "saw", mode=0o700)
        self.assertEqual(0o755, (self.base / "a").stat().st_mode & 0o777)
        self.assertEqual(0o755, (self.base / "a" / "b").stat().st_mode & 0o777)
        self.assertEqual(0o700, (self.base / "a" / "b" / "saw").stat().st_mode & 0o777)

    def test_as_root_a_folder_reached_through_a_users_link_is_refused(self):
        (self.base / "state").symlink_to(self.elsewhere)
        self.as_root()
        self.assertFalse(atomicwrite.replace(self.base / "state" / "saw" / "record.json", "{}"))
        self.assertEqual([], self.landed_elsewhere())

    def test_as_root_a_folder_reached_through_the_systems_own_links_is_written(self):
        self.as_root()
        self.assertTrue(atomicwrite.replace(self.base / "state" / "saw" / "record.json", "{}"))
        self.assertEqual(b"{}", (self.base / "state" / "saw" / "record.json").read_bytes())

    def test_as_the_user_their_own_link_is_followed(self):
        (self.base / "state").symlink_to(self.elsewhere)
        self.assertTrue(atomicwrite.replace(self.base / "state" / "saw" / "record.json", "{}"))
        self.assertEqual(["saw", "saw/record.json"], self.landed_elsewhere())

    def test_a_link_inside_a_trusted_links_target_is_judged_too(self):
        (self.base / "outer").mkdir()
        (self.base / "outer" / "inner").symlink_to(self.elsewhere)
        (self.base / "state").symlink_to(self.base / "outer" / "inner")
        real_stat = os.stat

        def inner_owned_by_someone_else(path, *args, **kwargs):
            found = real_stat(path, *args, **kwargs)
            if path == "inner" and kwargs.get("follow_symlinks") is False:
                fields = list(found)[:10]
                fields[4] = found.st_uid + 1
                return os.stat_result(fields)
            return found
        with mock.patch.object(pathsafe.os, "stat", side_effect=inner_owned_by_someone_else):
            self.assertFalse(atomicwrite.replace(self.base / "state" / "record.json", "{}"))
        self.assertEqual([], self.landed_elsewhere())

    def test_a_failed_write_leaves_nothing_behind(self):
        where = self.base / "state" / "record.json"
        with self.assertRaises(RuntimeError):
            with atomicwrite.staged(where) as fh:
                fh.write("half")
                raise RuntimeError("stopped")
        self.assertEqual([], os.listdir(self.base / "state"))

    def test_the_file_has_the_mode_asked_for(self):
        where = self.base / "state" / "hook"
        self.assertTrue(atomicwrite.replace(where, "#!/bin/sh\n", mode=0o755))
        self.assertEqual(0o755, where.stat().st_mode & 0o777)

    def test_a_new_folder_is_never_one_someone_else_made(self):
        (self.base / "kept").mkdir()
        (self.base / "kept" / "x").mkdir()
        self.assertEqual(self.base / "kept" / "x-1", atomicwrite.new_folder(self.base / "kept", "x"))


class TestOnlyWhatTheWriterNamedChanges(_Sandbox):

    def test_as_root_a_root_owned_link_placed_in_a_users_folder_is_refused(self):
        (self.base / "state").symlink_to(self.elsewhere)
        real_stat = os.stat

        def link_owned_by_root(path, *args, **kwargs):
            found = real_stat(path, *args, **kwargs)
            if path == "state" and kwargs.get("follow_symlinks") is False:
                fields = list(found)[:10]
                fields[4] = 0
                return os.stat_result(fields)
            return found
        self.as_root()
        with mock.patch.object(pathsafe.os, "stat", side_effect=link_owned_by_root):
            self.assertFalse(atomicwrite.replace(self.base / "state" / "record.json", "{}"))
        self.assertEqual([], self.landed_elsewhere())

    def test_a_file_with_another_name_keeps_its_mode(self):
        other = self.elsewhere / "secret"
        other.write_text("x", encoding="utf-8")
        os.chmod(other, 0o600)
        (self.base / "hooks").mkdir()
        os.link(other, self.base / "hooks" / "post-checkout.local")
        with self.assertRaises(OSError):
            atomicwrite.set_mode(self.base / "hooks" / "post-checkout.local", 0o755)
        self.assertEqual(0o600, other.stat().st_mode & 0o777)

    def test_as_root_a_move_whose_source_is_reached_through_a_users_link_moves_nothing(self):
        (self.elsewhere / "victim").write_text("x", encoding="utf-8")
        (self.base / "hooks").symlink_to(self.elsewhere)
        (self.base / "kept").mkdir()
        self.as_root()
        with self.assertRaises(OSError):
            atomicwrite.move_into(self.base / "hooks" / "victim", self.base / "kept", "victim")
        self.assertEqual(["victim"], self.landed_elsewhere())
        self.assertEqual([], os.listdir(self.base / "kept"))


class TestThePathMeansWhatTheKernelReadsIt(_Sandbox):

    def test_dotdot_after_the_users_own_link_is_the_link_targets_parent(self):
        (self.elsewhere / "deep" / "sub").mkdir(parents=True)
        (self.base / "lnk").symlink_to(self.elsewhere / "deep" / "sub")
        self.assertTrue(atomicwrite.replace(self.base / "lnk" / ".." / "state" / "record.json", "{}"))
        self.assertEqual(b"{}", (self.elsewhere / "deep" / "state" / "record.json").read_bytes())
        self.assertFalse((self.base / "state").exists())

    def test_nothing_is_made_inside_a_link_to_a_folder_that_does_not_exist(self):
        (self.base / "local").symlink_to(self.base / "not-yet")
        self.assertFalse(atomicwrite.replace(self.base / "local" / "state" / "record.json", "{}"))
        self.assertFalse((self.base / "not-yet").exists())


class TestTheOperatorsHookIsSetAsideAsItWas(_Sandbox):

    def settle(self, hooks):
        with mock.patch.object(hook, "_inside_what_saw_keeps", return_value=False):
            return hook._settle(hooks, "/usr/local/bin/saw", None, own=False)

    def test_a_disabled_hook_in_a_folder_that_cannot_change_stays_disabled(self):
        hooks = self.base / "hooks"
        hooks.mkdir()
        (hooks / "post-checkout").write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(hooks / "post-checkout", 0o644)
        os.chmod(hooks, 0o555)
        self.addCleanup(os.chmod, hooks, 0o755)
        self.settle(hooks)
        self.assertEqual(0o644, (hooks / "post-checkout").stat().st_mode & 0o777)

    def test_a_runnable_hook_with_another_name_is_set_aside_and_sawss_installed(self):
        hooks = self.base / "hooks"
        hooks.mkdir()
        (self.elsewhere / "post-checkout").write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(self.elsewhere / "post-checkout", 0o755)
        os.link(self.elsewhere / "post-checkout", hooks / "post-checkout")
        self.settle(hooks)
        self.assertTrue((hooks / "post-checkout.local").exists())
        self.assertIn("saw", (hooks / "post-checkout").read_text(encoding="utf-8"))
        self.assertEqual(0o755, (self.elsewhere / "post-checkout").stat().st_mode & 0o777)

    def test_a_hook_with_another_name_that_would_need_a_new_mode_is_put_back(self):
        hooks = self.base / "hooks"
        hooks.mkdir()
        (self.elsewhere / "secret").write_text("x", encoding="utf-8")
        os.chmod(self.elsewhere / "secret", 0o600)
        os.link(self.elsewhere / "secret", hooks / "post-checkout")
        actions = self.settle(hooks)
        self.assertEqual(0o600, (self.elsewhere / "secret").stat().st_mode & 0o777)
        self.assertTrue((hooks / "post-checkout").exists())
        self.assertFalse((hooks / "post-checkout.local").exists())
        self.assertIn("left as it is", " ".join(a.detail for a in actions))


class TestARefusedReportPathKeepsTheScan(_Sandbox):

    def test_a_sarif_path_through_a_refused_link_is_written_elsewhere_and_said(self):
        from contextlib import redirect_stderr
        from io import StringIO
        from stayawake.bots.security.models import ScanReport
        from stayawake.bots.security.sinks.sarif_sink import SarifSink
        (self.base / "out").symlink_to(self.elsewhere)
        self.as_root()
        said = StringIO()
        kept = self.base / "kept"
        kept.mkdir()
        with mock.patch("stayawake.utils.scratch.kept_dir", return_value=kept), redirect_stderr(said):
            SarifSink(self.base / "out" / "results.sarif").emit(ScanReport(results=[], generated_at="2026-10-11T00:00:00Z"))
        self.assertEqual([], self.landed_elsewhere())
        self.assertTrue((kept / "results.sarif").is_file())
        self.assertIn("reached through a link saw does not follow", said.getvalue())


class TestANameIsOneEntry(_Sandbox):

    def test_a_rename_move_or_new_folder_refuses_a_name_through_a_link(self):
        (self.base / "hooks").mkdir()
        (self.base / "hooks" / "pre-commit").write_text("x", encoding="utf-8")
        (self.base / "hooks" / "u").symlink_to(self.elsewhere)
        (self.elsewhere / "victim").write_text("v", encoding="utf-8")
        self.as_root()
        for attempt in (lambda: atomicwrite.rename_in(self.base / "hooks", "u/victim", "taken"),
                        lambda: atomicwrite.rename_in(self.base / "hooks", "pre-commit", "u/planted"),
                        lambda: atomicwrite.rename_in(self.base / "hooks", "pre-commit", "../elsewhere/x"),
                        lambda: atomicwrite.move_into(self.base / "hooks" / "pre-commit",
                                                      self.base / "hooks", "u/planted"),
                        lambda: atomicwrite.new_folder(self.base / "hooks", "u/made")):
            with self.assertRaises(OSError):
                attempt()
        self.assertEqual(["victim"], self.landed_elsewhere())
        self.assertTrue((self.base / "hooks" / "pre-commit").exists())


class TestAMoveBetweenDisksCopiesWhole(_Sandbox):

    def test_a_folder_with_a_link_inside_is_copied_and_the_source_removed(self):
        source = self.base / "hooks"
        (source / "inner").mkdir(parents=True)
        (source / "inner" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(source / "inner" / "pre-commit", 0o755)
        os.utime(source / "inner" / "pre-commit", (1_600_000_000, 1_600_000_000))
        (source / "inner" / "link").symlink_to("pre-commit")
        (self.base / "kept").mkdir()
        real_rename = os.rename

        def across_disks(src, dst, *args, **kwargs):
            if kwargs.get("dst_dir_fd") is not None:
                raise OSError(errno.EXDEV, "cross-device")
            return real_rename(src, dst, *args, **kwargs)
        with mock.patch.object(atomicwrite.os, "rename", side_effect=across_disks):
            atomicwrite.move_into(source, self.base / "kept", "hooks")
        moved = self.base / "kept" / "hooks" / "inner"
        self.assertFalse(source.exists())
        self.assertEqual("#!/bin/sh\n", (moved / "pre-commit").read_text(encoding="utf-8"))
        self.assertEqual(0o755, (moved / "pre-commit").stat().st_mode & 0o777)
        self.assertEqual(1_600_000_000, int((moved / "pre-commit").stat().st_mtime))
        self.assertEqual("pre-commit", os.readlink(moved / "link"))


class TestEveryWriterOfSawsOwnFilesGoesThroughIt(_Sandbox):
    """Under root, each writer meets a folder reached through a user's link and writes nothing there."""

    def setUp(self):
        super().setUp()
        (self.base / "saw").symlink_to(self.elsewhere)
        env = mock.patch.dict(os.environ, {"XDG_STATE_HOME": str(self.base),
                                           "XDG_CONFIG_HOME": str(self.base),
                                           "XDG_CACHE_HOME": str(self.base)})
        env.start()
        self.addCleanup(env.stop)
        self.as_root()

    def writes_nothing_elsewhere(self, write):
        before = self.landed_elsewhere()
        try:
            write()
        except OSError:
            pass
        self.assertEqual(before, self.landed_elsewhere())

    def test_the_capture_of_live_code(self):
        class Seen:
            ppid, uid, start_time = 1, 501, "t"
        self.writes_nothing_elsewhere(
            lambda: self.assertIsNone(live._capture({4242: (Seen, "code")}, self.base / "saw" / "captured")))

    def test_the_live_code_record(self):
        self.writes_nothing_elsewhere(
            lambda: self.assertFalse(liveledger.save(liveledger.Ledger(), self.base / "saw" / "live.json")))

    def test_the_autorun_baseline(self):
        with mock.patch.object(baseline, "is_ephemeral", return_value=False):
            self.writes_nothing_elsewhere(
                lambda: self.assertFalse(baseline.save_baseline({}, baseline.Baseline(), {})[0]))

    def test_the_watcher_records(self):
        self.writes_nothing_elsewhere(
            lambda: self.assertFalse(schedule.declare(["saw"], self.base / "saw" / "watch.json")))
        self.writes_nothing_elsewhere(
            lambda: self.assertFalse(schedule._write(self.base / "saw" / "agent.plist", "x")))

    def test_the_hook_install_record(self):
        self.writes_nothing_elsewhere(
            lambda: self.assertFalse(hookscript.declare("saw", None, self.base / "hooks")))

    def test_a_hook_set_aside(self):
        hooks = self.base / "repo-hooks"
        hooks.mkdir()
        (hooks / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        self.writes_nothing_elsewhere(lambda: self.assertIsNone(hookscript.set_aside(hooks / "pre-commit")))
        self.assertTrue((hooks / "pre-commit").exists())

    def test_an_installed_hook_and_the_scan_cache(self):
        (self.elsewhere / "hooks").mkdir()
        self.writes_nothing_elsewhere(lambda: self.assertFalse(
            hook._write_verified(self.base / "saw" / "hooks" / "pre-commit", "#!/bin/sh\n",
                                 self.base / "saw" / "hooks")))
        with mock.patch.object(hook, "_cache_path", return_value=self.base / "saw" / "scanned.json"):
            self.writes_nothing_elsewhere(lambda: hook._remember(self.base, ""))

    def test_reports_and_the_dependency_database(self):
        self.writes_nothing_elsewhere(lambda: io.write_json(self.base / "saw" / "latest.json", {}))
        self.writes_nothing_elsewhere(lambda: db.write_manifest(self.base / "saw" / "db", []))

    def test_the_app_credentials(self):
        self.writes_nothing_elsewhere(
            lambda: github_app._write_private_config(self.base / "saw" / "github-app.json", b"key"))


if __name__ == "__main__":
    unittest.main()

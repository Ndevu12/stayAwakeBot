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

    def test_a_link_at_the_files_own_name_is_refused(self):
        (self.base / "state").mkdir()
        (self.base / "state" / "record.json").symlink_to(self.elsewhere / "made-through-the-link")
        self.assertFalse(atomicwrite.replace(self.base / "state" / "record.json", "{}"))
        self.assertEqual([], self.landed_elsewhere())

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


class TestAMoveBetweenDisksCopiesWhole(_Sandbox):

    def test_a_folder_with_a_link_inside_is_copied_and_the_source_removed(self):
        source = self.base / "hooks"
        (source / "inner").mkdir(parents=True)
        (source / "inner" / "pre-commit").write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(source / "inner" / "pre-commit", 0o755)
        (source / "inner" / "link").symlink_to("pre-commit")
        (self.base / "kept").mkdir()
        real_rename = os.rename

        def across_disks(src, dst, *args, **kwargs):
            if kwargs.get("dst_dir_fd") is not None and kwargs.get("src_dir_fd") is None:
                raise OSError(errno.EXDEV, "cross-device")
            return real_rename(src, dst, *args, **kwargs)
        with mock.patch.object(atomicwrite.os, "rename", side_effect=across_disks):
            atomicwrite.move_into(source, self.base / "kept", "hooks")
        moved = self.base / "kept" / "hooks" / "inner"
        self.assertFalse(source.exists())
        self.assertEqual("#!/bin/sh\n", (moved / "pre-commit").read_text(encoding="utf-8"))
        self.assertEqual(0o755, (moved / "pre-commit").stat().st_mode & 0o777)
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

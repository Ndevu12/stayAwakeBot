#!/usr/bin/env python3
"""Where something is already where a control goes, `saw harden` moves it aside, beside where it was, and places the
control, and `saw harden --take-back` puts it back exactly; a known worm's staging kit there is deleted instead, never
through a link and never beyond its own disk, and never put back. Where only an administrator can do it, it says to run
it again with sudo."""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden
from stayawake.bots.security.harden import approvals as agentapprovals, denial, hold_aside, remove_kit
from stayawake.bots.security.harden import settings as editorsettings
from stayawake.utils import hostdenial
from tests.bots.security.test_harden import _hooks_already_there, locked

_KIT_MANIFEST = json.dumps({"dependencies": {"axios": "^1.7.0", "socket.io-client": "^4.7.0"}})
_KIT_LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/axios": {"version": "1.7.9"},
                                                            "node_modules/socket.io-client": {"version": "4.8.1"}}})


def _a_kit_named(where: Path) -> Path:
    where.mkdir()
    (where / "package.json").write_text(_KIT_MANIFEST, encoding="utf-8")
    (where / "package-lock.json").write_text(_KIT_LOCK, encoding="utf-8")
    (where / "node_modules" / "axios").mkdir(parents=True)
    (where / "node_modules" / "axios" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    return where


def _moved(path: Path, now=None):
    """Hold what is at `path` and move it aside, as harden does."""
    held = hold_aside.hold(path)
    try:
        return hold_aside.move_aside(path, held, now=now)
    finally:
        held.close()


def _recognised_by_name(path: Path) -> bool:
    """A stand-in for the audit's recognition: a real folder holding the kit's manifest."""
    if os.path.islink(path) or not path.is_dir():
        return False
    manifest = path / "package.json"
    return manifest.is_file() and not manifest.is_symlink() and manifest.read_text(encoding="utf-8") == _KIT_MANIFEST


class _Place(unittest.TestCase):
    """A home of its own, with a lock that reads back as set for the whole test, as the owner's lock does."""

    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(locked())
        self._fresh()

    def _fresh(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(self._clean, self.home)
        self.captured = self.home / "captured"
        self.target = self.home / ".node_modules"

    @staticmethod
    def _clean(home):
        for root, dirs, _files in os.walk(home):
            for name in dirs:
                try:
                    os.chmod(os.path.join(root, name), 0o700)
                except OSError:
                    pass
        shutil.rmtree(home, ignore_errors=True)

    def _place(self, *, owner_can_lock=True, privileged=False, recognises=_recognised_by_name):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(hostdenial, "lock_needs_privilege", return_value=not owner_can_lock))
            stack.enter_context(mock.patch.object(hostdenial, "privileged", return_value=privileged))
            stack.enter_context(mock.patch.object(denial, "_is_the_kit", side_effect=recognises))
            stack.enter_context(mock.patch("stayawake.bots.security.harden.live.capture_path",
                                           return_value=self.captured))
            if not owner_can_lock and not privileged:
                stack.enter_context(mock.patch.object(hostdenial, "set_immutable", return_value=False))
            return denial.apply_one(self.target)

    def _take_back(self, keeps_aside=lambda held: False):
        with mock.patch.object(hostdenial, "privileged", return_value=False):
            return denial.remove_one(self.target, keeps_aside=keeps_aside)

    def _held(self):
        return hold_aside.held_aside(self.target)

    def _removing(self):
        return sorted(p for p in self.home.iterdir() if p.name.startswith(self.target.name + remove_kit.REMOVING_MARK))


class TestWhatIsThereIsMovedAsideAndTheControlPlaced(_Place):
    def test_a_folder_of_anything_is_moved_aside_whole(self):
        self.target.mkdir()
        (self.target / "lib").mkdir()
        (self.target / "lib" / "own.js").write_text("mine", encoding="utf-8")
        outcome = self._place()
        self.assertEqual((outcome.state, outcome.moved_aside), (denial.SELF_ENFORCING, True))
        [held] = self._held()
        self.assertEqual((held / "lib" / "own.js").read_text(encoding="utf-8"), "mine")
        self.assertTrue(self.target.is_dir() and not any(self.target.iterdir()))

    def test_a_file_is_moved_aside_with_its_bytes(self):
        self.target.write_bytes(b"\x00\x01bytes")
        self._place()
        [held] = self._held()
        self.assertEqual(held.read_bytes(), b"\x00\x01bytes")

    def test_a_link_is_moved_aside_as_a_link_and_what_it_leads_to_is_untouched(self):
        victim = self.home / "victim"
        victim.mkdir()
        (victim / "KEEPME").write_text("x", encoding="utf-8")
        self.target.symlink_to(victim)
        self._place()
        [held] = self._held()
        self.assertEqual(os.readlink(held), str(victim))
        self.assertEqual({p.name for p in victim.iterdir()}, {"KEEPME"})

    def test_a_second_move_in_the_same_second_takes_the_next_name(self):
        self.target.write_text("one", encoding="utf-8")
        now = datetime.datetime(2026, 10, 16, 20, 30, 0, tzinfo=datetime.timezone.utc)
        first = _moved(self.target, now=now)
        self.target.write_text("two", encoding="utf-8")
        second = _moved(self.target, now=now)
        self.assertEqual(first.held.name, ".node_modules.saw-held-20261016T203000Z")
        self.assertEqual(second.held.name, ".node_modules.saw-held-20261016T203000Z-2")
        self.assertEqual((first.held.read_text(encoding="utf-8"), second.held.read_text(encoding="utf-8")), ("one", "two"))

    def test_where_the_control_cannot_be_placed_what_was_there_is_put_back(self):
        self.target.write_text("x", encoding="utf-8")
        with mock.patch.object(hostdenial, "lock_needs_privilege", return_value=False), \
                mock.patch.object(hostdenial, "set_immutable", return_value=False), \
                mock.patch.object(denial, "_is_the_kit", return_value=False):
            outcome = denial.apply_one(self.target)
        self.assertEqual(outcome.state, denial.UNKNOWN)
        self.assertFalse(outcome.moved_aside)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "x")
        self.assertEqual(self._held(), [])


class TestAMoveActsOnlyOnWhatWasChecked(_Place):
    def test_something_swapped_in_before_the_move_is_not_moved(self):
        for kind, make in (("file", lambda: self.target.write_text("first", encoding="utf-8")),
                           ("folder", lambda: (self.target.mkdir(), (self.target / "a").write_text("first")))):
            with self.subTest(kind=kind):
                self._fresh()
                make()
                held = hold_aside.hold(self.target)
                self.addCleanup(held.close)
                (shutil.rmtree if kind == "folder" else os.unlink)(self.target)
                self.target.write_text("swapped", encoding="utf-8")
                self.assertEqual(hold_aside.move_aside(self.target, held), hold_aside.Moved())
                self.assertEqual(self.target.read_text(encoding="utf-8"), "swapped")
                self.assertEqual(self._held(), [])

    def test_a_link_swapped_in_is_at_most_moved_aside_never_deleted_and_comes_back(self):
        self.target.symlink_to(self.home / "first")
        held = hold_aside.hold(self.target)
        os.unlink(self.target)
        self.target.symlink_to(self.home / "second")
        hold_aside.move_aside(self.target, held)
        if self._held():
            self.assertEqual(hold_aside.put_back(self.target, lambda h: False), hold_aside.PUT_BACK)
        self.assertEqual(os.readlink(self.target), str(self.home / "second"))

    def test_something_swapped_in_at_the_moment_of_the_rename_is_put_back(self):
        self.target.write_text("x", encoding="utf-8")
        other = self.home / "other"
        other.write_text("other", encoding="utf-8")
        aside = self.home / "aside"
        real_rename = hold_aside.atomicwrite.rename_beside
        calls = []

        def swap_then_rename(folder, name, new_name):
            if not calls:
                os.rename(self.target, aside)
                os.rename(other, self.target)
            calls.append(name)
            return real_rename(folder, name, new_name)
        held = hold_aside.hold(self.target)
        self.addCleanup(held.close)
        with mock.patch.object(hold_aside.atomicwrite, "rename_beside", side_effect=swap_then_rename):
            moved = hold_aside.move_aside(self.target, held)
        self.assertTrue(moved.mismatch)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "other")
        self.assertEqual(aside.read_text(encoding="utf-8"), "x")

    def test_where_only_an_administrator_can_lock_nothing_is_moved(self):
        self.target.write_text("x", encoding="utf-8")
        outcome = self._place(owner_can_lock=False)
        self.assertEqual(outcome.state, denial.NEEDS_ROOT)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "x")
        self.assertEqual(self._held(), [])


class TestARenameNeverReplacesAnything(unittest.TestCase):
    def test_a_name_that_is_taken_is_never_replaced_whatever_the_kernel_offers(self):
        from stayawake.utils import atomicwrite
        for kernel in (True, False):
            with self.subTest(kernel=kernel):
                folder = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, folder, True)
                (folder / "a").write_text("A", encoding="utf-8")
                (folder / "b").write_text("B", encoding="utf-8")
                patch = (contextlib.nullcontext() if kernel else
                         mock.patch.object(atomicwrite, "_kernel_rename_no_replace", return_value=False))
                with patch, self.assertRaises(FileExistsError):
                    atomicwrite.rename_beside(folder, "a", "b")
                self.assertEqual(((folder / "a").read_text(encoding="utf-8"), (folder / "b").read_text(encoding="utf-8")),
                                 ("A", "B"))


class TestTakingBackPutsBackExactly(_Place):
    def test_a_folder_a_file_and_a_link_come_back_exactly(self):
        victim = self.home / "victim"
        victim.mkdir()
        for label, make, check in (
            ("folder", lambda: (self.target.mkdir(), (self.target / "a").write_bytes(b"A")),
             lambda: (self.target / "a").read_bytes() == b"A"),
            ("file", lambda: self.target.write_bytes(b"\xffB"), lambda: self.target.read_bytes() == b"\xffB"),
            ("link", lambda: self.target.symlink_to(victim), lambda: os.readlink(self.target) == str(victim)),
        ):
            with self.subTest(label=label):
                self._fresh()
                make()
                self._place()
                outcome = self._take_back()
                self.assertEqual((outcome.state, outcome.put_back), (denial.REMOVED, hold_aside.PUT_BACK))
                self.assertTrue(check())
                self.assertEqual(self._held(), [])

    def test_the_newest_of_several_is_put_back(self):
        old = self.home / (self.target.name + hold_aside.HELD_ASIDE_MARK + "20200101T000000Z")
        old.write_text("old", encoding="utf-8")
        self.target.write_text("new", encoding="utf-8")
        self._place()
        self.assertEqual(self._take_back().put_back, hold_aside.PUT_BACK)
        self.assertEqual((self.target.read_text(encoding="utf-8"), old.read_text(encoding="utf-8")), ("new", "old"))

    def test_what_is_to_stay_aside_stays_aside(self):
        self.target.write_text("x", encoding="utf-8")
        self._place()
        outcome = self._take_back(keeps_aside=lambda held: True)
        self.assertEqual(outcome.put_back, hold_aside.KEPT_ASIDE)
        self.assertFalse(os.path.lexists(self.target))
        self.assertEqual(len(self._held()), 1)

    def test_what_cannot_be_judged_stays_aside(self):
        self.target.write_text("x", encoding="utf-8")
        self._place()

        def unreadable(held):
            raise PermissionError("refused")
        self.assertEqual(self._take_back(keeps_aside=unreadable).put_back, hold_aside.NOT_PUT_BACK)
        self.assertEqual(len(self._held()), 1)

    def test_nothing_is_put_back_over_something_else(self):
        self.target.write_text("x", encoding="utf-8")
        held = _moved(self.target).held
        self.target.write_text("new", encoding="utf-8")
        self.assertEqual(hold_aside.put_back(self.target, lambda h: False), hold_aside.PATH_TAKEN)
        self.assertEqual((self.target.read_text(encoding="utf-8"), held.read_text(encoding="utf-8")), ("new", "x"))

    def test_a_held_link_to_a_kit_stays_aside(self):
        kit = _a_kit_named(self.home / "kit-elsewhere")
        self.target.symlink_to(kit)
        _moved(self.target)
        self.assertEqual(hold_aside.put_back(self.target, denial._stays_aside), hold_aside.KEPT_ASIDE)
        self.assertFalse(os.path.lexists(self.target))

    def test_a_held_kit_stays_aside(self):
        _a_kit_named(self.target)
        _moved(self.target)
        self.assertEqual(hold_aside.put_back(self.target, denial._stays_aside), hold_aside.KEPT_ASIDE)


class TestAKnownStagingKitIsDeletedNotKept(_Place):
    def test_the_kit_is_deleted_its_facts_kept_and_the_control_placed(self):
        _a_kit_named(self.target)
        outcome = self._place()
        self.assertEqual((outcome.state, outcome.kit, outcome.moved_aside), (denial.SELF_ENFORCING, denial.KIT_REMOVED, False))
        self.assertEqual(self._held(), [])
        self.assertEqual(self._removing(), [])
        [record] = list(self.captured.glob("staging-kit-*.json"))
        facts = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(facts["packages"], [{"name": "axios", "version": "1.7.9"},
                                             {"name": "socket.io-client", "version": "4.8.1"}])
        self.assertEqual(len(facts["package_json_sha256"]), 64)
        self.assertIn("modified", facts)

    def test_a_link_inside_the_kit_is_removed_as_a_link_and_what_it_leads_to_is_untouched(self):
        victim = self.home / "victim"
        victim.mkdir()
        (victim / "KEEPME").write_text("x", encoding="utf-8")
        _a_kit_named(self.target)
        (self.target / "node_modules" / "trap").symlink_to(victim)
        (self.target / "trap-file").symlink_to(victim / "KEEPME")
        self.assertEqual(self._place().kit, denial.KIT_REMOVED)
        self.assertEqual({p.name for p in victim.iterdir()}, {"KEEPME"})
        self.assertEqual((victim / "KEEPME").read_text(encoding="utf-8"), "x")

    def test_a_mount_inside_the_kit_is_never_entered_and_the_rest_is_said_left(self):
        _a_kit_named(self.target)
        mounted = self.target / "node_modules" / "mounted"
        mounted.mkdir()
        (mounted / "VICTIM").write_text("x", encoding="utf-8")
        real_parent = os.path.realpath(self.home)
        now = datetime.datetime(2026, 10, 16, 21, 0, 0, tzinfo=datetime.timezone.utc)
        renamed = os.path.join(real_parent, ".node_modules.saw-removing-20261016T210000Z", "node_modules", "mounted")
        with mock.patch.object(remove_kit, "_mount_points", return_value=frozenset({renamed})), \
                mock.patch.object(remove_kit.datetime, "datetime", wraps=datetime.datetime) as clock:
            clock.now.return_value = now
            outcome = self._place()
        self.assertEqual((outcome.state, outcome.kit), (denial.UNKNOWN, denial.KIT_LEFT))
        [left] = self._removing()
        self.assertEqual((left / "node_modules" / "mounted" / "VICTIM").read_text(encoding="utf-8"), "x")

    def test_a_folder_on_another_disk_inside_the_kit_is_never_entered(self):
        _a_kit_named(self.target)
        other = self.target / "node_modules" / "other-disk"
        other.mkdir()
        (other / "VICTIM").write_text("x", encoding="utf-8")
        other_inode = other.lstat().st_ino
        real_stat, real_fstat = os.stat, os.fstat

        def on_another_device(found):
            if found.st_ino != other_inode:
                return found
            fields = list(found)
            fields[2] = found.st_dev + 1
            return os.stat_result(fields)
        with mock.patch.object(remove_kit.os, "stat", side_effect=lambda *a, **k: on_another_device(real_stat(*a, **k))), \
                mock.patch.object(remove_kit.os, "fstat", side_effect=lambda fd: on_another_device(real_fstat(fd))):
            outcome = self._place()
        self.assertEqual(outcome.kit, denial.KIT_LEFT)
        [left] = self._removing()
        self.assertTrue((left / "node_modules" / "other-disk" / "VICTIM").is_file())

    def test_a_link_to_a_kit_is_never_deleted(self):
        kit = _a_kit_named(self.home / "kit-elsewhere")
        self.target.symlink_to(kit)
        outcome = self._place(recognises=lambda p: True)
        self.assertNotEqual(outcome.kit, denial.KIT_REMOVED)
        self.assertTrue((kit / "package.json").is_file())

    def test_a_kit_another_account_owns_is_not_deleted(self):
        _a_kit_named(self.target)
        with mock.patch.object(remove_kit.operator, "acting_uid", return_value=os.getuid() + 1):
            outcome = self._place()
        self.assertNotEqual(outcome.kit, denial.KIT_REMOVED)
        self.assertTrue(any((p / "package.json").is_file() for p in (self.target, *self._held())))

    def test_a_folder_not_recognised_as_the_kit_is_never_deleted(self):
        self.target.mkdir()
        (self.target / "package.json").write_text(json.dumps({"name": "mine", "dependencies": {"axios": "1"}}),
                                                  encoding="utf-8")
        self.assertEqual(remove_kit.remove(self.target, self.captured), remove_kit.Removal())
        self.assertTrue((self.target / "package.json").is_file())

    def test_what_is_swapped_in_for_the_kit_is_judged_as_what_it_is(self):
        _a_kit_named(self.target)
        shutil.rmtree(self.target)
        self.target.mkdir()
        (self.target / "own.js").write_text("mine", encoding="utf-8")
        self.assertEqual(remove_kit.remove(self.target, self.captured), remove_kit.Removal())
        self.assertEqual((self.target / "own.js").read_text(encoding="utf-8"), "mine")

    def test_something_swapped_in_at_the_moment_of_the_rename_is_put_back_and_nothing_deleted(self):
        _a_kit_named(self.target)
        decoy = self.home / "decoy"
        decoy.mkdir()
        (decoy / "VICTIM").write_text("x", encoding="utf-8")
        kit_aside = self.home / "kit-aside"
        real_rename = remove_kit.atomicwrite.rename_beside
        calls = []

        def swap_then_rename(folder, name, new_name):
            if not calls:
                os.rename(self.target, kit_aside)
                os.rename(decoy, self.target)
            calls.append(name)
            return real_rename(folder, name, new_name)
        with mock.patch.object(remove_kit.atomicwrite, "rename_beside", side_effect=swap_then_rename):
            removal = remove_kit.remove(self.target, self.captured)
        self.assertTrue(removal.mismatch)
        self.assertEqual((self.target / "VICTIM").read_text(encoding="utf-8"), "x")
        self.assertTrue((kit_aside / "package.json").is_file())

    def test_where_only_an_administrator_can_lock_the_kit_is_still_deleted_and_sudo_is_asked(self):
        _a_kit_named(self.target)
        outcome = self._place(owner_can_lock=False)
        self.assertEqual((outcome.state, outcome.kit), (denial.NEEDS_ROOT, denial.KIT_REMOVED))
        self.assertFalse(os.path.lexists(self.target / "package.json"))
        self.assertEqual(self._removing(), [])


class TestTheKitAsTheAuditKnowsIt(_Place):
    """With the audit's own recognition, not a stand-in."""

    _RECOGNISES = staticmethod(denial._is_the_kit)

    def test_the_kit_as_it_was_found_on_a_host_is_deleted(self):
        _a_kit_named(self.target)
        for n in range(36):
            (self.target / "node_modules" / f"dep{n}").mkdir(exist_ok=True)
        outcome = self._place(recognises=self._RECOGNISES)
        self.assertEqual(outcome.kit, denial.KIT_REMOVED)
        self.assertFalse(os.path.lexists(self.target / "package.json"))
        self.assertEqual(self._removing(), [])

    def test_a_kit_naming_only_one_of_its_packages_is_deleted(self):
        for only in ("axios", "socket.io-client"):
            with self.subTest(only=only):
                self._fresh()
                self.target.mkdir()
                (self.target / "package.json").write_text(json.dumps({"dependencies": {only: "1"}}), encoding="utf-8")
                self.assertEqual(self._place(recognises=self._RECOGNISES).kit, denial.KIT_REMOVED)

    def test_a_folder_that_only_looks_like_it_is_moved_aside_and_never_deleted(self):
        for label, manifest in (
            ("it names itself", {"name": "mine", "dependencies": {"axios": "1"}}),
            ("it has a version", {"version": "1.0.0", "dependencies": {"axios": "1"}}),
            ("it has scripts", {"dependencies": {"axios": "1"}, "scripts": {"x": "y"}}),
            ("it names other packages too", {"dependencies": {"axios": "1", "lodash": "4"}}),
            ("it names nothing", {"dependencies": {}}),
        ):
            with self.subTest(label=label):
                self._fresh()
                self.target.mkdir()
                (self.target / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
                outcome = self._place(recognises=self._RECOGNISES)
                self.assertNotEqual(outcome.kit, denial.KIT_REMOVED)
                [held] = self._held()
                self.assertEqual(json.loads((held / "package.json").read_text(encoding="utf-8")), manifest)


class TestAKitHeldOrLeftBesideIsDeletedToo(_Place):
    _RECOGNISES = staticmethod(denial._is_the_kit)

    def _audit_reports_a_kit(self):
        from stayawake.bots.security.hygiene import host_artifacts
        with mock.patch.object(Path, "home", return_value=self.home):
            return any(i.id == "host-worm-staging-kit" for i in host_artifacts.check_host_artifacts())

    def test_a_kit_under_a_held_name_is_deleted_and_the_audit_no_longer_reports_it(self):
        _a_kit_named(self.home / (self.target.name + hold_aside.HELD_ASIDE_MARK + "20200101T000000Z"))
        self.assertTrue(self._audit_reports_a_kit())
        outcome = self._place(recognises=self._RECOGNISES)
        self.assertEqual(outcome.kit, denial.KIT_REMOVED)
        self.assertEqual((self._held(), self._removing()), ([], []))
        self.assertFalse(self._audit_reports_a_kit())

    def test_a_kit_left_mid_removal_is_deleted_and_the_audit_no_longer_reports_it(self):
        _a_kit_named(self.home / (self.target.name + remove_kit.REMOVING_MARK + "20200101T000000Z"))
        self.assertTrue(self._audit_reports_a_kit())
        self.assertEqual(self._place(recognises=self._RECOGNISES).kit, denial.KIT_REMOVED)
        self.assertEqual(self._removing(), [])
        self.assertFalse(self._audit_reports_a_kit())

    def test_a_held_kit_that_cannot_be_fully_deleted_stays_where_the_audit_reads_it(self):
        held = _a_kit_named(self.home / (self.target.name + hold_aside.HELD_ASIDE_MARK + "20200101T000000Z"))
        (held / "node_modules" / "other-disk").mkdir()
        other_inode = (held / "node_modules" / "other-disk").lstat().st_ino
        real_stat, real_fstat = os.stat, os.fstat

        def on_another_device(found):
            if found.st_ino != other_inode:
                return found
            fields = list(found)
            fields[2] = found.st_dev + 1
            return os.stat_result(fields)
        with mock.patch.object(remove_kit.os, "stat", side_effect=lambda *a, **k: on_another_device(real_stat(*a, **k))), \
                mock.patch.object(remove_kit.os, "fstat", side_effect=lambda fd: on_another_device(real_fstat(fd))):
            outcome = self._place(recognises=self._RECOGNISES)
        self.assertEqual(outcome.kit, denial.KIT_LEFT)
        from stayawake.bots.security.hygiene import staging_kit
        self.assertEqual(len(staging_kit.being_removed(self.target)), 1)
        self.assertTrue(self._audit_reports_a_kit())

    def test_something_held_that_is_not_a_kit_is_never_touched(self):
        held = self.home / (self.target.name + hold_aside.HELD_ASIDE_MARK + "20200101T000000Z")
        held.mkdir()
        (held / "own.js").write_text("mine", encoding="utf-8")
        outcome = self._place(recognises=self._RECOGNISES)
        self.assertEqual(outcome.kit, "")
        self.assertEqual((held / "own.js").read_text(encoding="utf-8"), "mine")

    def test_reading_what_a_kit_holds_never_waits_on_something_that_is_not_a_file(self):
        kit = _a_kit_named(self.home / "kit")
        os.unlink(kit / "package-lock.json")
        os.mkfifo(kit / "package-lock.json")
        facts = remove_kit.facts(kit, datetime.datetime(2026, 10, 16, tzinfo=datetime.timezone.utc))
        self.assertIsNone(facts["package_lock_sha256"])
        self.assertEqual(facts["packages"], [])


class TestWhatHardenSays(_Place):
    def _said(self, **place):
        with mock.patch.object(hostdenial, "lock_needs_privilege", return_value=not place.get("owner_can_lock", True)), \
                mock.patch.object(hostdenial, "privileged", return_value=False), \
                mock.patch.object(denial, "_is_the_kit", side_effect=_recognised_by_name), \
                mock.patch("stayawake.bots.security.harden.live.capture_path", return_value=self.captured):
            return harden.run(editor_pass=editorsettings.Correcting, agent_pass=agentapprovals.Correcting,
                              altered=lambda: [], saw_runs=lambda: True, supported=lambda: True, live=lambda: [],
                              folders=lambda: [self.target], apply=denial.apply_one,
                              settle_hooks=_hooks_already_there, stop=lambda: None, schedule_pass=lambda: None)[1]

    def test_it_says_it_moved_something_aside_and_how_to_put_it_back(self):
        self.target.write_text("x", encoding="utf-8")
        text = self._said()
        self.assertIn("so saw moved it aside, beside where it was, and placed the control", text)
        self.assertIn("`saw harden --take-back` puts it back", text)
        self.assertNotIn("something else is already there", text)
        self.assertNotIn(str(self.home), text)

    def test_it_says_it_deleted_a_known_worm_s_staging_kit_and_not_to_rotate_yet(self):
        _a_kit_named(self.target)
        text = self._said()
        self.assertIn("saw deleted a known worm's staging kit from this machine.", text)
        self.assertIn("Do NOT rotate any credential yet", text)
        self.assertNotIn(str(self.home), text)

    def test_taking_back_says_what_was_put_back_or_kept_aside(self):
        self.target.write_text("x", encoding="utf-8")
        self._place()
        with mock.patch.object(hostdenial, "privileged", return_value=False):
            _code, text = harden.take_back(folders=lambda: [self.target],
                                           remove=lambda p: denial.remove_one(p, keeps_aside=lambda h: False),
                                           unschedule=lambda: harden.schedule.NOTHING_TO_REMOVE,
                                           restore_editors=lambda: mock.Mock(done=True, restored=False, kept=False,
                                                                             failed=False, unreadable_record=False),
                                           restore_agents=lambda: mock.Mock(done=True, restored=False, failed=False,
                                                                            unreadable_record=False))
        self.assertIn("What saw had moved aside so a control could be placed has been put back.", text)
        self.assertEqual(self.target.read_text(encoding="utf-8"), "x")


if __name__ == "__main__":
    unittest.main()

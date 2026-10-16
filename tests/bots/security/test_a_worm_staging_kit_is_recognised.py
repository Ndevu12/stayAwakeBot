#!/usr/bin/env python3
"""The audit recognises a known worm's staging kit in a global module folder, in place or held aside by
saw harden, and reads it as a live compromise that holds credential rotation; any other contents of those
folders are graded exactly as before."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import host_artifacts as h
from stayawake.bots.security.hygiene import staging_kit
from stayawake.bots.security.hygiene.models import (ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN,
                                                    WORM_STAGING_KIT_ID, rotation_safety)

_KIT = {"dependencies": {"axios": "^1.18.1", "socket.io-client": "^4.8.3"}}


class _AHome(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="kit-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.prefix = self.home / "prefix"
        patches = [
            mock.patch.dict(os.environ, {"HOME": str(self.home),
                                         "XDG_CONFIG_HOME": str(self.home / ".config"),
                                         "XDG_CACHE_HOME": str(self.home / ".cache")}),
            mock.patch.object(h, "_npm_prefix_roots", lambda: [self.prefix]),
            mock.patch.object(h, "_temp_dirs", lambda: []),
            mock.patch.object(h, "_host_user_tag", lambda: None),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _folder(self, folder: Path, manifest=_KIT, packages=("axios", "socket.io-client")) -> Path:
        (folder / "node_modules").mkdir(parents=True)
        if manifest is not None:
            text = manifest if isinstance(manifest, str) else json.dumps(manifest)
            (folder / "package.json").write_text(text)
        for name in packages:
            package = folder / "node_modules" / name
            package.mkdir()
            (package / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0"}))
        return folder

    def _found(self, verify: bool = False) -> list:
        return h.check_host_artifacts(verify=verify)

    def _kits(self, verify: bool = False) -> list:
        return [i for i in self._found(verify) if i.id == WORM_STAGING_KIT_ID]


class TestTheKnownKitIsAlwaysALiveCompromise(_AHome):
    def test_the_kit_alone_and_beside_an_empty_folder_hold_rotation(self):
        self._folder(self.home / ".node_modules")
        for shape in ("kit alone", "kit and an empty folder"):
            if shape == "kit and an empty folder":
                (self.home / ".node_libraries").mkdir()
            for verify in (False, True):
                with self.subTest(shape=shape, verify=verify):
                    found = self._found(verify)
                    self.assertIn(WORM_STAGING_KIT_ID, {i.id for i in found})
                    self.assertEqual(rotation_safety({i.id for i in found}), ROTATION_UNSAFE_PERSISTENCE)
                    self.assertEqual(found[1:], h._graded_drop_files(verify))

    def test_a_kit_of_either_package_alone_is_the_kit(self):
        for dependencies in ({"axios": "^1"}, {"socket.io-client": "^4"}):
            with self.subTest(dependencies=dependencies):
                self.doCleanups()
                self.setUp()
                self._folder(self.home / ".node_modules", {"dependencies": dependencies})
                self.assertEqual(len(self._kits()), 1)

    def test_the_kit_in_every_global_module_folder_is_the_kit(self):
        for folder in (".node_libraries", "prefix/lib/node"):
            with self.subTest(folder=folder):
                self.doCleanups()
                self.setUp()
                self._folder(self.home / folder)
                self.assertEqual(len(self._kits()), 1)

    def test_the_finding_names_no_place_and_holds_rotation_in_words(self):
        self._folder(self.home / ".node_modules")
        kit = self._kits()[0]
        self.assertEqual((kit.severity, kit.title), ("warning", "A known worm's staging kit is on this host"))
        self.assertIn("ran on this host at some point", kit.detail)
        self.assertIn("`saw harden`", kit.remediation)
        self.assertIn("do NOT rotate any credential yet", kit.remediation)
        for text in (kit.title, kit.detail, kit.remediation):
            for place in (str(self.home), ".node_modules"):
                self.assertNotIn(place, text)

    def test_the_report_leads_with_the_live_compromise_runbook(self):
        from stayawake.bots.security import hygiene
        self._folder(self.home / ".node_modules")
        report = " ".join(hygiene.render(self._found(), width=100).split())
        self.assertIn("Active host persistence detected", report)
        self.assertIn("A known worm's staging kit is on this host", report)


class TestAKitHeldAsideIsStillOnTheHost(_AHome):
    def test_a_kit_saw_harden_held_aside_is_still_on_the_host(self):
        (self.home / ".node_modules").mkdir()
        for name in (".node_modules.saw-held-20261016T203000Z", ".node_modules.saw-held-20261016T203000Z-2"):
            self._folder(self.home / name)
        kits = self._kits()
        self.assertEqual([k.title for k in kits], ["A known worm's staging kit is held aside on this host"])
        self.assertIn("It is still on this host", kits[0].detail)
        self.assertEqual(rotation_safety({i.id for i in self._found()}), ROTATION_UNSAFE_PERSISTENCE)

    def test_a_kit_saw_harden_could_not_finish_removing_is_still_on_the_host(self):
        (self.home / ".node_modules").mkdir()
        self._folder(self.home / ".node_modules.saw-removing-20261016T210000Z-2")
        kits = self._kits()
        self.assertEqual([k.title for k in kits], ["A known worm's staging kit is on this host"])
        self.assertIn("could not finish removing it", kits[0].detail)
        self.assertEqual(rotation_safety({i.id for i in self._found()}), ROTATION_UNSAFE_PERSISTENCE)

    def test_something_else_moved_aside_is_not_a_finding(self):
        (self.home / ".node_modules").mkdir()
        project = {"name": "tools", "version": "1.0.0", "dependencies": {"axios": "^1"}}
        for mark in (".saw-held-", ".saw-removing-"):
            self._folder(self.home / f".node_modules{mark}20261016T203000Z", project)
        self.assertEqual(self._kits(), [])

    def test_a_kit_in_place_and_one_held_aside_are_both_named(self):
        self._folder(self.home / ".node_modules")
        self._folder(self.home / ".node_modules.saw-held-20261016T203000Z")
        self.assertEqual(len(self._kits()), 2)

    def test_a_link_moved_aside_is_never_the_kit(self):
        target = self._folder(self.home / "elsewhere")
        (self.home / ".node_modules.saw-held-20261016T203000Z").symlink_to(target)
        self.assertEqual(self._kits(), [])


class TestAnyOtherContentsAreGradedAsBefore(_AHome):
    def _graded_as_before(self):
        found = self._found()
        self.assertNotIn(WORM_STAGING_KIT_ID, {i.id for i in found})
        self.assertEqual(found, h._graded_drop_files())

    def test_an_old_global_install_layout_is_not_the_kit(self):
        old = self.home / ".node_modules" / "lib" / "node_modules" / "axios"
        old.mkdir(parents=True)
        (old / "package.json").write_text(json.dumps({"name": "axios", "version": "1.0.0"}))
        self._graded_as_before()

    def test_a_manifest_that_says_more_than_the_kit_is_not_the_kit(self):
        for manifest in ({"dependencies": {"axios": "^1", "lodash": "^4"}},
                         {"name": "my-app", "version": "1.0.0", "dependencies": {"axios": "^1"}},
                         {"dependencies": {"axios": "^1"}, "scripts": {"start": "node ."}},
                         {"dependencies": {"axios": "^1"}, "main": "index.js"},
                         {"dependencies": {"axios": "^1"}, "bin": {"x": "x.js"}},
                         {"devDependencies": {"axios": "^1"}},
                         {"dependencies": {}}, {"dependencies": ["axios"]}, {}, ["axios"],
                         "not json", '{"dependencies": {"axios": "^1"}}' + " " * (64 * 1024)):
            with self.subTest(manifest=str(manifest)[:60]):
                self.doCleanups()
                self.setUp()
                self._folder(self.home / ".node_modules", manifest)
                self._graded_as_before()

    def test_a_real_project_at_the_folder_is_not_the_kit(self):
        project = {"name": "dashboard", "version": "0.3.1", "private": True,
                   "dependencies": {"axios": "^1.6.0", "socket.io-client": "^4.7.0"}}
        self._folder(self.home / ".node_modules", project)
        self._graded_as_before()

    def test_a_folder_with_no_manifest_is_not_the_kit(self):
        self._folder(self.home / ".node_modules", None)
        self._graded_as_before()

    def test_a_manifest_or_folder_reached_through_a_link_is_never_the_kit(self):
        kit = self._folder(self.home / "elsewhere")
        folder = self.home / ".node_modules"
        folder.mkdir()
        (folder / "package.json").symlink_to(kit / "package.json")
        self._graded_as_before()
        shutil.rmtree(folder)
        folder.symlink_to(kit)
        self.assertEqual(self._kits(), [])


@unittest.skipIf(os.geteuid() == 0, "root reads a folder whatever its mode")
class TestAFolderThatCannotBeReadIsUnknown(_AHome):
    def test_an_unreadable_manifest_is_unknown_not_clean(self):
        folder = self._folder(self.home / ".node_modules")
        (folder / "package.json").chmod(0)
        self.addCleanup((folder / "package.json").chmod, 0o644)
        found = self._found()
        self.assertNotIn(WORM_STAGING_KIT_ID, {i.id for i in found})
        self.assertIn(rotation_safety({i.id for i in found}),
                      {ROTATION_UNSAFE_UNKNOWN, ROTATION_UNSAFE_PERSISTENCE})
        self.assertTrue(any(i.severity == "unknown" for i in found))


class TestReadingAManifestNeverWaits(_AHome):
    def _swapped(self, folder: Path, seen_as: Path):
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            return real_lstat(seen_as if Path(path) == folder / "package.json" else path, *args, **kwargs)
        return mock.patch.object(staging_kit.os, "lstat", side_effect=lstat)

    def _audit_within(self, seconds: float) -> list:
        import threading
        found = []
        audit = threading.Thread(target=lambda: found.extend(self._found()), daemon=True)
        audit.start()
        audit.join(seconds)
        self.assertFalse(audit.is_alive(), "the audit waited on what is in place of the manifest")
        return found

    def test_a_pipe_at_the_manifest_is_never_waited_on(self):
        folder = self._folder(self.home / ".node_modules", None)
        os.mkfifo(folder / "package.json")
        self.assertNotIn(WORM_STAGING_KIT_ID, {i.id for i in self._audit_within(5)})

    def test_a_pipe_swapped_in_after_the_manifest_was_first_seen_is_unknown_not_the_kit(self):
        folder = self._folder(self.home / ".node_modules", None)
        os.mkfifo(folder / "package.json")
        regular = self.home / "regular.json"
        regular.write_text(json.dumps(_KIT))
        with self._swapped(folder, regular):
            found = self._audit_within(5)
        self.assertNotIn(WORM_STAGING_KIT_ID, {i.id for i in found})
        self.assertTrue(any(i.severity == "unknown" for i in found))

    def test_a_file_swapped_in_after_the_manifest_was_first_seen_is_unknown_not_the_kit(self):
        folder = self._folder(self.home / ".node_modules")
        other = self.home / "other.json"
        other.write_text(json.dumps(_KIT))
        with self._swapped(folder, other):
            found = self._audit_within(5)
        self.assertNotIn(WORM_STAGING_KIT_ID, {i.id for i in found})
        self.assertTrue(any(i.severity == "unknown" for i in found))

    def test_the_shared_reader_reads_only_the_file_first_found(self):
        from stayawake.utils.pathsafe import read_regular_no_follow
        first, other = self.home / "first.json", self.home / "other.json"
        first.write_text("{}")
        other.write_text("{}")
        self.assertEqual(read_regular_no_follow(first, 64, same_as=os.lstat(first)), b"{}")
        self.assertIsNone(read_regular_no_follow(first, 64, same_as=os.lstat(other)))
        self.assertEqual(read_regular_no_follow(first, 64), b"{}")


@unittest.skipIf(os.geteuid() == 0, "root lists a folder whatever its mode")
class TestAFolderThatCannotBeListed(_AHome):
    def _closed(self, folder: Path):
        folder.chmod(0o311)
        self.addCleanup(folder.chmod, 0o755)

    def _unknown(self) -> list:
        return [i for i in self._found() if i.severity == "unknown"]

    def test_an_absent_folder_beside_one_that_cannot_be_listed_reads_as_before(self):
        (self.prefix / "lib").mkdir(parents=True)
        self._closed(self.prefix / "lib")
        self.assertEqual(self._unknown(), [])
        self.assertEqual(self._found(), h._graded_drop_files())

    def test_a_present_folder_beside_one_that_cannot_be_listed_is_unknown(self):
        (self.prefix / "lib" / "node").mkdir(parents=True)
        self._closed(self.prefix / "lib")
        self.assertEqual(len(self._unknown()), 1)

    def test_an_unreadable_kit_folder_is_named_once(self):
        folder = self._folder(self.home / ".node_modules")
        folder.chmod(0)
        self.addCleanup(folder.chmod, 0o755)
        self.assertEqual(len(self._unknown()), 1)


class TestTheKitsAreData(unittest.TestCase):
    def test_the_data_file_names_the_kit(self):
        kit, = staging_kit.kits()
        self.assertEqual((kit.manifest, kit.only_keys, kit.packages),
                         ("package.json", frozenset({"dependencies"}),
                          frozenset({"axios", "socket.io-client"})))

    def test_a_data_file_that_names_no_kit_is_refused(self):
        bad = Path(tempfile.mkdtemp(prefix="kits-")) / "staging_kits.yml"
        self.addCleanup(shutil.rmtree, bad.parent, True)
        for text in ("version: 1\n", "kits: []\n", "kits:\n  - manifest: package.json\n",
                     "kits:\n  - {manifest: a/b, only_keys: [x], packages: [y]}\n"):
            with self.subTest(text=text):
                bad.write_text(text)
                with mock.patch.object(staging_kit, "KITS_FILE", bad):
                    staging_kit.kits.cache_clear()
                    self.addCleanup(staging_kit.kits.cache_clear)
                    with self.assertRaises(ValueError):
                        staging_kit.kits()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""On Windows, harden holds what is where a denial goes, moves it aside and back, places the denial
and holds the folder it makes, refusing a link or junction on the way or at the name."""
from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.harden import denial, hold_aside
from stayawake.utils import hostdenial

WINDOWS_ONLY = unittest.skipUnless(os.name == "nt", "harden's Windows holds run only on Windows")
_NOW = datetime.datetime(2026, 11, 25, 12, 0, 0, tzinfo=datetime.timezone.utc)


def junction(link: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True,
                   capture_output=True)


@WINDOWS_ONLY
class TestHardenHoldsOnWindows(unittest.TestCase):

    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="saw-holds-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.target = self.home / ".node_modules"

    def held(self, path: Path):
        held = hold_aside.hold(path)
        if held is not None:
            self.addCleanup(held.close)
        return held

    def test_a_folder_is_held_moved_aside_and_put_back(self):
        self.target.mkdir()
        (self.target / "payload.js").write_text("x", encoding="utf-8")
        held = self.held(self.target)
        self.assertIsNotNone(held.fd)
        moved = hold_aside.move_aside(self.target, held, now=_NOW)
        self.assertIsNotNone(moved.held)
        self.assertFalse(os.path.lexists(self.target))
        self.assertTrue((moved.held / "payload.js").is_file())
        self.assertTrue(hold_aside.put_back_this(self.target, moved.held, hold_aside.seen_at(moved.held)))
        self.assertTrue((self.target / "payload.js").is_file())

    def test_a_file_is_held_and_moved_aside(self):
        self.target.write_text("x", encoding="utf-8")
        held = self.held(self.target)
        self.assertIsNotNone(held.fd)
        moved = hold_aside.move_aside(self.target, held, now=_NOW)
        self.assertEqual("x", moved.held.read_text(encoding="utf-8"))

    def test_nothing_reached_through_a_junction_is_held(self):
        real = self.home / "real"
        (real / ".node_modules").mkdir(parents=True)
        junction(self.home / "linked", real)
        self.assertIsNone(self.held(self.home / "linked" / ".node_modules"))
        self.assertTrue((real / ".node_modules").is_dir())

    def test_a_junction_at_the_location_is_moved_aside_itself_and_what_it_leads_to_is_untouched(self):
        real = self.home / "real"
        real.mkdir()
        (real / "KEEPME").write_text("x", encoding="utf-8")
        junction(self.target, real)
        held = self.held(self.target)
        self.assertIsNone(held.fd)
        moved = hold_aside.move_aside(self.target, held, now=_NOW)
        self.assertIsNotNone(moved.held)
        self.assertFalse(os.path.lexists(self.target))
        self.assertEqual(["KEEPME"], [p.name for p in real.iterdir()])

    def test_the_folder_a_denial_makes_is_held_and_removed_while_empty(self):
        self.target.mkdir()
        made = denial._held_open(self.target)
        self.assertIsNotNone(made)
        try:
            self.assertTrue(denial._remove_what_was_made(self.target, made))
        finally:
            os.close(made)
        self.assertFalse(os.path.lexists(self.target))

    def test_a_denial_is_placed_where_nothing_is_and_refuses_what_arrives(self):
        outcome = denial.apply_one(self.target)
        self.addCleanup(hostdenial.clear_immutable, self.target)
        self.assertIn(outcome.state, (denial.ENFORCING, denial.SELF_ENFORCING), outcome)
        with self.assertRaises(PermissionError):
            (self.target / "payload.js").write_text("x", encoding="utf-8")

    def test_a_folder_given_to_administrators_is_given_back_to_its_owner(self):
        from stayawake.utils import folders, winlock
        if not hostdenial.privileged():
            self.skipTest("giving a folder away needs an administrator")
        self.target.mkdir()
        owner = folders.owner_of(self.target)
        folders.give_to_root(self.target)
        self.assertEqual(winlock.ADMINISTRATORS, folders.owner_of(self.target).upper())
        folders.give_to(self.target, owner)
        self.assertEqual(owner.upper(), folders.owner_of(self.target).upper())
        self.assertTrue(folders.reachable_by(self.target, owner))

    def test_a_denial_holds_no_folder_reached_through_a_junction(self):
        real = self.home / "real"
        (real / ".node_modules").mkdir(parents=True)
        junction(self.home / "linked", real)
        self.assertIsNone(denial._held_open(self.home / "linked" / ".node_modules"))


if __name__ == "__main__":
    unittest.main()

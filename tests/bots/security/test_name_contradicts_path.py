#!/usr/bin/env python3
"""A launch item names an organisation and runs a path. Both halves were already read; neither is
suspicious alone — a name is a string, a path is a path. The contradiction between them is the
signal, and it costs nothing beyond comparing two values already in hand."""
from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.hygiene.autorun import surface
from stayawake.bots.security.hygiene.autorun.grade import (claimed_vendor, content_signal,
                                                           contradicts_its_name)


def _entry(name: str, program: str) -> surface.AutorunEntry:
    root = Path(tempfile.mkdtemp())
    path = root / f"{name}.plist"
    path.write_bytes(plistlib.dumps({"Label": name, "ProgramArguments": [program],
                                     "RunAtLoad": True}))
    return surface.AutorunEntry(location="user-launchagent", path=path, argv=[program],
                                body=path.read_text(encoding="utf-8", errors="replace"),
                                persistence=["RunAtLoad"])


class TestTheNameIsReadAsAClaim(unittest.TestCase):
    def test_a_reverse_dns_name_claims_an_organisation(self):
        self.assertEqual(claimed_vendor(_entry("com.apple.updated", "/usr/libexec/x")), "apple")

    def test_a_name_that_claims_nothing_is_not_forced_to(self):
        self.assertIsNone(claimed_vendor(_entry("my-backup-job", "/usr/local/bin/backup")))
        self.assertIsNone(claimed_vendor(_entry("com.singlepart", "/usr/local/bin/x")))


class TestNeitherHalfFiresAlone(unittest.TestCase):
    def test_an_organisation_running_its_own_path_is_ordinary(self):
        # Deliberately somewhere writable, so this isolates the naming half: an organisation keeping
        # its updater under the user's own library is the ordinary case on a developer machine.
        owned = Path(tempfile.mkdtemp()) / "Google" / "GoogleUpdater" / "Current" / "updater"
        owned.parent.mkdir(parents=True)
        owned.write_text("#!/bin/sh\n", encoding="utf-8")
        from stayawake.bots.security.hygiene import mechanism
        self.assertTrue(mechanism.is_user_writable(owned), "fixture no longer isolates the half")
        self.assertIsNone(contradicts_its_name(_entry("com.google.GoogleUpdater.wake", str(owned))))

    def test_an_organisation_running_a_place_only_it_can_write_is_ordinary(self):
        # The overwhelming real case: a system item whose path never names its owner. 773 launch
        # items on a developer host are this shape, and none of them may fire.
        self.assertIsNone(contradicts_its_name(
            _entry("com.apple.AMPArtworkAgent", "/System/Library/PrivateFrameworks/A/amp")))

    def test_an_unclaimed_name_in_a_writable_place_is_ordinary(self):
        entry = _entry("local-dev-helper", str(Path(tempfile.mkdtemp()) / "helper.sh"))
        self.assertIsNone(contradicts_its_name(entry))


class TestTheContradictionIsTheSignal(unittest.TestCase):
    def test_an_organisation_running_a_path_anyone_can_write_is_reported(self):
        entry = _entry("com.apple.softwareupdated", str(Path(tempfile.mkdtemp()) / "upd.sh"))
        reason = contradicts_its_name(entry)
        self.assertIsNotNone(reason, "the name and the path contradict and nothing said so")
        self.assertIn("apple", reason)

    def test_it_reaches_the_grader_as_a_decisive_reason(self):
        entry = _entry("com.apple.softwareupdated", str(Path(tempfile.mkdtemp()) / "upd.sh"))
        signal = content_signal(entry)
        self.assertTrue(signal.hit, "the contradiction did not carry a verdict")
        self.assertTrue(any("claims apple" in reason for reason in signal.reasons))

    def test_a_missing_path_is_not_a_contradiction(self):
        entry = surface.AutorunEntry(location="user-launchagent",
                                     path=Path("/tmp/com.apple.x.plist"), argv=[])
        self.assertIsNone(contradicts_its_name(entry))


if __name__ == "__main__":
    unittest.main()

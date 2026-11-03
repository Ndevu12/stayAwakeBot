#!/usr/bin/env python3
"""`saw watch` runs `saw harden` on every pass and prints what it said once; `saw harden
--take-back --ide` gives back only the editor settings, and a watch pass then leaves them until
`saw harden` runs again."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden, watch
from stayawake.bots.security.harden import settings as editorsettings


class TestWatchRunsHarden(unittest.TestCase):
    def setUp(self):
        watch._LAST_HARDEN.clear()

    def test_each_pass_runs_harden_and_leaves_given_back_editors(self):
        with mock.patch.object(harden, "run", return_value=(0, "in place")) as run:
            self.assertEqual("in place", watch.run_harden())
        self.assertIs(run.call_args.kwargs["editor_pass"], editorsettings.keep_in_place)

    def test_the_same_note_prints_once(self):
        with mock.patch.object(harden, "run", return_value=(3, "run again with sudo")):
            self.assertEqual("run again with sudo", watch.run_harden())
            self.assertEqual("", watch.run_harden())


class TestTheIdeControlsCanBeGivenBack(unittest.TestCase):
    def setUp(self):
        self.marker = Path(tempfile.mkdtemp()) / "editor-controls-given-back"
        patcher = mock.patch.object(editorsettings, "given_back_path", return_value=self.marker)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_giving_them_back_is_remembered_and_watch_leaves_them(self):
        done = editorsettings.TakingBack()
        with mock.patch.object(editorsettings, "take_back", return_value=done):
            code, _text = harden.take_back_ide()
        self.assertEqual(0, code)
        self.assertTrue(self.marker.exists())
        with mock.patch.object(editorsettings, "settle") as settle:
            editorsettings.keep_in_place()
        settle.assert_not_called()

    def test_saw_harden_puts_them_back_in_place(self):
        self.marker.write_text("given back\n")
        with mock.patch.object(editorsettings, "settle") as settle:
            editorsettings.put_in_place()
        settle.assert_called_once()
        self.assertFalse(self.marker.exists())

    def test_ide_without_take_back_is_refused(self):
        from stayawake.cli import build_parser
        a = build_parser().parse_args(["harden", "--ide"])
        self.assertEqual(2, a.func(a))


if __name__ == "__main__":
    unittest.main()

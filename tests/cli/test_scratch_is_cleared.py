#!/usr/bin/env python3
"""Every run clears what it made under the temporary root."""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from stayawake.cli import dispatch
from stayawake.utils import scratch
from tests.support.scratchroot import OwnTempRoot


def _run(argv: list[str]) -> tuple[int, str]:
    err = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(err):
        rc = dispatch.main(argv)
    return rc, err.getvalue()


class TestTheRunClearsItsScratch(OwnTempRoot):

    def test_a_directory_a_run_made_is_gone_afterwards(self):
        made = scratch.new_dir("a probe directory")
        root = scratch.root()
        _run(["search", "scan"])
        self.assertFalse(made.exists())
        self.assertFalse(root.exists())

    def test_a_kept_directory_survives_the_run(self):
        kept = scratch.kept_dir("something handed to the operator")
        _run(["search", "scan"])
        self.assertTrue(kept.exists())

    def test_it_clears_even_when_the_command_raises(self):
        made = scratch.new_dir("a probe directory")
        with mock.patch.object(dispatch, "build_parser", side_effect=None):
            pass
        with mock.patch("stayawake.cli.commands.search.run", side_effect=RuntimeError("boom")):
            _run(["search", "scan"])
        self.assertFalse(made.exists())

    def test_it_names_what_it_could_not_clear(self):
        with mock.patch.object(scratch, "release", return_value=["a worktree at /x: busy"]):
            _, err = _run(["search", "scan"])
        self.assertIn("left behind", err)
        self.assertIn("a worktree at /x", err)

    def test_a_failure_to_clear_never_fails_the_run(self):
        with mock.patch.object(scratch, "release", side_effect=OSError("nope")):
            rc, err = _run(["search", "scan"])
        self.assertEqual(0, rc)
        self.assertIn("left behind", err)


if __name__ == "__main__":
    unittest.main()

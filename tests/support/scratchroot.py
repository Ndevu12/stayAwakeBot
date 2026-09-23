#!/usr/bin/env python3
"""A temp root each test owns, so one test's scratch never decides another's outcome."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import scratch


class OwnTempRoot(unittest.TestCase):
    """Every case runs against a temp root the test owns."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="scratch-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        isolated = mock.patch.dict(os.environ, {"TMPDIR": str(self.tmp)})
        isolated.start()
        self.addCleanup(isolated.stop)
        tempfile.tempdir = None
        self.addCleanup(setattr, tempfile, "tempdir", None)
        scratch._root = None
        scratch._areas.clear()
        self.addCleanup(scratch._areas.clear)

    def _roots(self):
        return [p for p in self.tmp.iterdir() if p.name.startswith(scratch.ROOT_PREFIX)]

#!/usr/bin/env python3
"""A bare `saw fix` looks under the home folder, a folder whose `.git` link names a git directory
that is not there is scanned as a plain folder, and the host note names every folder it is about."""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from stayawake.bots.security import remediator, resolution, service
from stayawake.bots.security.host_note import scan_host_note
from stayawake.bots.security.resolution import resolve_local_targets
from stayawake.bots.security.targets import ScanOptions
from tests.support import samples


def _scan(path: Path) -> tuple[int, str, str]:
    cfgd = Path(tempfile.mkdtemp())
    (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"HOME": tempfile.mkdtemp()}), \
            redirect_stdout(out), redirect_stderr(err):
        rc = service.scan(str(cfgd / "c.yml"), no_stream=True, paths=[str(path)])
    return rc, out.getvalue(), err.getvalue()


class TestAGitLinkThatLeadsNowhereIsScannedAsAPlainFolder(unittest.TestCase):
    """What a package ships when it vendors a git submodule: `.git` names `../../.git/modules/x`."""

    def setUp(self):
        self.parent = Path(tempfile.mkdtemp())
        self.folder = self.parent / "site-packages" / "pkg" / "sdk-core"
        self.folder.mkdir(parents=True)
        (self.folder / ".git").write_text("gitdir: ../../../.git/modules/sdk-core\n", encoding="utf-8")
        (self.folder / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")

    def test_it_is_found_as_a_plain_folder(self):
        found = resolve_local_targets([str(self.parent)], ScanOptions())
        self.assertEqual([(t.root, t.is_repo) for t in found], [(self.folder.resolve(), False)])

    def test_its_scan_finishes_and_reads_clean(self):
        rc, out, err = _scan(self.folder)
        self.assertEqual(rc, 0, err)
        self.assertIn("1 targets · 0 infected", out)
        self.assertNotIn("could not be scanned", err)

    def test_a_payload_inside_it_is_still_reported(self):
        (self.folder / "evil.js").write_text(samples.marked_loader() + "\n", encoding="utf-8")
        _rc, out, _err = _scan(self.folder)
        self.assertIn("1 infected", out)

    def test_a_link_to_a_git_directory_that_is_there_is_a_repository(self):
        real = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", "--bare", str(real)], check=True)
        (self.folder / ".git").write_text(f"gitdir: {real}\n", encoding="utf-8")
        self.assertTrue(resolution.is_a_repository(self.folder))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root reads any file")
    def test_a_link_that_cannot_be_read_is_still_taken_as_a_repository(self):
        (self.folder / ".git").chmod(0)
        self.addCleanup((self.folder / ".git").chmod, 0o644)
        self.assertTrue(resolution.is_a_repository(self.folder))

    def test_a_git_directory_is_a_repository(self):
        (self.folder / ".git").unlink()
        (self.folder / ".git").mkdir()
        self.assertTrue(resolution.is_a_repository(self.folder))


class TestABareFixLooksUnderTheHomeFolder(unittest.TestCase):
    def test_with_nothing_named_or_configured_it_is_the_home_folder(self):
        home = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"HOME": home}):
            self.assertEqual(remediator._local_patterns({}, []), [str(Path(home))])

    def test_configured_targets_come_first(self):
        cfg = {"targets": {"local": ["~/code/*"]}}
        self.assertEqual(remediator._local_patterns(cfg, []), ["~/code/*"])

    def test_a_dot_is_the_folder_it_is_run_in(self):
        self.assertEqual(remediator._local_patterns({}, ["."]), ["."])


class TestTheHostNoteNamesEveryFolderItIsAbout(unittest.TestCase):
    def test_several_folders_are_counted_and_each_is_named_with_its_file(self):
        note = scan_host_note(infected=True, local_loaders=["~/a/lib/new.js", "~/b/app.js"],
                              folders=2)
        self.assertIn("2 folders on this machine hold malicious code", note)
        self.assertIn("~/a/lib/new.js", note)
        self.assertIn("~/b/app.js", note)
        self.assertIn("If you opened, installed or built one of them, that code may have run", note)
        self.assertIn("Run `saw audit` now", note)
        self.assertIn("Do not open, install or build those folders until `saw fix` has cleaned them",
                      note)

    def test_more_than_three_are_summed_up(self):
        files = [f"~/p{i}/x.js" for i in range(5)]
        note = scan_host_note(infected=True, local_loaders=files, folders=5)
        self.assertIn("~/p0/x.js, ~/p1/x.js, ~/p2/x.js, and 2 more", note)

    def test_one_folder_is_spoken_of_as_one(self):
        note = scan_host_note(infected=True, local_loaders=["~/a/app.js"], folders=1)
        self.assertIn("1 folder on this machine holds malicious code", note)
        self.assertIn("If you opened, installed or built it, that code may have run", note)


if __name__ == "__main__":
    unittest.main()

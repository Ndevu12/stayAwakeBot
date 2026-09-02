#!/usr/bin/env python3
"""#218 — an installed application's own JavaScript. No manifest lists it, no lockfile covers it
and removing `node_modules` never reaches it, so the repository and dependency scans cannot see it.

Grading rationale, the corpus the bounds were calibrated against, and the limits: `Ndevu12/saw#218`.
An uncorroborated hit stays `info`; only the opt-in corroboration makes it an active foothold."""
from __future__ import annotations

import contextlib
import dataclasses
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import app_bundle, audit_checks, host_artifacts, render
from stayawake.bots.security.hygiene.models import (ACTIVE_PERSISTENCE_IDS,
                                                    HOST_ARTIFACT_SCAN_BLOCKED_ID,
                                                    APP_BUNDLE_MODULE_UNREADABLE_ID, ROTATION_UNSAFE_IDS,
                                                    ROTATION_UNSAFE_UNKNOWN, APP_BUNDLE_SCAN_BLOCKED_ID,
                                                    rotation_safety)


def _raising(exc):
    def engine(_directory):
        raise exc
    return engine


@dataclasses.dataclass
class _Verdict:
    """A stand-in for the engine's `DirVerdict`, field for field.

    A `mock.Mock(markers=[])` answers that one attribute and stubs away the fields the verdict uses
    to say it could not finish. The engine needs its dependencies to import, hence a local mirror.
    """

    path: str = "/x"
    files: int = 0
    markers: list = dataclasses.field(default_factory=list)
    scanned_clean: bool = False
    too_large: bool = False
    partial: bool = False
    error: str | None = None
    unread: list = dataclasses.field(default_factory=list)

    @property
    def has_markers(self) -> bool:
        return bool(self.markers)


def _engine_loads() -> bool:
    """Whether the content-scan engine is importable here — a hole in the run, not a finding."""
    try:
        from stayawake.bots.security.verify import verify_dir      # noqa: F401
        return True
    except Exception:
        return False

_PAD = " " * 200
_CLEAN = "module.exports = function (a, b) { return a + b; };\n"


def _confirmed_payload() -> str:
    """Triggers a CONFIRMED loader signature, assembled from split tokens so this file carries no
    contiguous indicator for the self-scan to flag (the convention in test_verify.py)."""
    cc = "from" + "CharCode"
    run = "ev" + "al"
    return f"const x = String.{cc}(127) + String.{cc}(127); {run}(x);"


class _Host:
    """A throwaway host carrying one installed-application layout the enumerator has to find."""

    def __init__(self, relative: str = "Editor.app/Contents/Resources/app", *, data: bool = False):
        self.base = Path(tempfile.mkdtemp())
        self.data = data
        self.app = self.base / relative
        self.module_dir = self.app / "node_modules" / "some-pkg" / "dist"
        self.module_dir.mkdir(parents=True)
        (self.app / "package.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")

    def write(self, body: str, *, name: str = "index.js", where: Path | None = None) -> Path:
        target = (where or self.module_dir) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return target

    def _run(self, call):
        with mock.patch.object(app_bundle, "_bundle_bases",
                               return_value=[] if self.data else [self.base]), \
             mock.patch.object(app_bundle, "_data_bases",
                               return_value=[self.base] if self.data else []):
            return call()

    def check(self, *, verify: bool = False):
        return self._run(lambda: app_bundle.check_app_bundles(verify=verify))

    def roots(self):
        return self._run(lambda: [root for root, _depth in app_bundle.app_bundle_js_roots()])


def _appended(body_lines: list[str], pad: str = _PAD) -> str:
    return _CLEAN + "\r\n" + pad + "\n".join(body_lines)


class TestTheSurfaceIsEnumeratedByShape(unittest.TestCase):
    def test_an_application_nobody_named_is_still_found(self):
        # A name list would have to be right about software that did not exist when it shipped.
        host = _Host("SomethingNobodyListed.app/Contents/Resources/app")
        self.assertEqual([str(r) for r in host.roots()], [str(host.app)])

    def test_an_application_nested_two_folders_deep_is_found(self):
        host = _Host("Vendor/Suite/Foo.app/Contents/Resources/app")
        self.assertEqual([str(r) for r in host.roots()], [str(host.app)])

    def test_a_squirrel_style_per_version_install_is_found(self):
        host = _Host("Programs/slack/app-4.29.149/resources/app")
        self.assertEqual([str(r) for r in host.roots()], [str(host.app)])

    def test_a_per_version_data_directory_outside_the_bundle_is_found(self):
        # A layout that carries no `resources/app` component at all.
        host = _Host("discord/0.0.309/modules/discord_desktop_core", data=True)
        module = host.write(_appended(["z" * 200]), where=host.app)
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])
        self.assertIn(str(module), host.check()[0].detail)

    def test_two_names_for_one_tree_are_examined_once(self):
        # `/Applications/Applications` is a symlink to `/Applications` on macOS, so every bundle
        # matches twice — once directly and once through the link.
        host = _Host()
        os.symlink(host.base, host.base / "alias")
        self.assertEqual(len(host.roots()), 1, "one tree was examined under two names")

    def test_a_tree_the_user_cannot_write_is_still_examined(self):
        # An earlier version skipped these, which dropped every .deb, .rpm and .pkg install.
        host = _Host()
        host.write(_appended(["z" * 200]))
        os.chmod(host.app, 0o555)
        try:
            self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])
        finally:
            os.chmod(host.app, 0o755)

    def test_it_survives_a_base_that_does_not_exist(self):
        with mock.patch.object(app_bundle, "_bundle_bases",
                               return_value=[Path(tempfile.mkdtemp()) / "gone"]), \
             mock.patch.object(app_bundle, "_data_bases", return_value=[]):
            self.assertEqual(app_bundle.app_bundle_js_roots(), [])


class TestTheConcealmentIsWhatIsGraded(unittest.TestCase):
    def test_an_ordinary_module_says_nothing(self):
        host = _Host()
        host.write(_CLEAN)
        self.assertEqual(host.check(), [])

    def test_a_module_padded_and_appended_is_reported(self):
        host = _Host()
        host.write(_appended(["console.log('x'); // " + "y" * 64]))
        issues = host.check()
        self.assertEqual([i.id for i in issues], ["app-bundle-appended-module"])
        self.assertEqual(issues[0].severity, "info")

    def test_a_payload_that_spans_several_lines_is_still_found(self):
        # A rejected earlier rule required a single line; this pins that it stays rejected.
        host = _Host()
        host.write(_appended(["const a%d = %d;" % (i, i) for i in range(8)]))
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_a_pad_of_other_ecmascript_spaces_is_still_a_pad(self):
        for space, label in ((" ", "space"), ("\t", "tab"), ("\v", "vertical tab"),
                             ("\f", "form feed"), (" ", "no-break space")):
            with self.subTest(pad=label):
                host = _Host()
                host.write(_appended(["z" * 200], pad=space * 200))
                self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_a_payload_larger_than_any_tail_window_is_still_found(self):
        # A fixed tail window bounds what can be examined; a regression pin, not a threshold.
        host = _Host()
        host.write(_CLEAN * 200 + "\r\n" + _PAD + "z" * (128 * 1024))
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_a_trailing_newline_does_not_hide_it(self):
        host = _Host()
        host.write(_appended(["z" * 200]) + "\n")
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_an_uppercase_extension_is_examined(self):
        # `require('./dist/index')` resolves `index.JS` on a case-insensitive volume.
        host = _Host()
        host.write(_appended(["z" * 200]), name="index.JS")
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_a_module_behind_a_symlinked_directory_is_examined(self):
        # pnpm, `npm link` and electron-builder all emit symlinked `node_modules` entries.
        host = _Host()
        outside = Path(tempfile.mkdtemp()) / "pkg"
        (outside / "dist").mkdir(parents=True)
        (outside / "dist" / "index.js").write_text(_appended(["z" * 200]), encoding="utf-8")
        os.symlink(outside, host.app / "node_modules" / "linked")
        self.assertEqual([i.id for i in host.check()], ["app-bundle-appended-module"])

    def test_indented_source_that_keeps_going_is_not_the_shape(self):
        # The calibrated false-positive class — see `saw#218` for the corpus.
        host = _Host()
        host.write("const f = () => {\n" + _PAD + "doThing(a,\n" + _PAD + "  b);\n};\n"
                   + "// trailing\n" * 20)
        self.assertEqual(host.check(), [])

    def test_a_short_pad_is_not_the_shape(self):
        host = _Host()
        host.write(_CLEAN + "\n" + " " * 10 + "z" * 200)
        self.assertEqual(host.check(), [])

    def test_trailing_whitespace_with_nothing_after_it_is_not_the_shape(self):
        host = _Host()
        host.write(_CLEAN + _PAD + "\n")
        self.assertEqual(host.check(), [])

    def test_a_file_that_cannot_be_read_is_reported_rather_than_crashing(self):
        host = _Host()
        target = host.write(_appended(["z" * 200]))
        os.chmod(target, 0o000)
        try:
            ids = [i.id for i in host.check()]
        finally:
            os.chmod(target, 0o644)
        self.assertEqual(ids, ["app-bundle-module-unreadable"])

    def test_non_javascript_in_the_same_tree_is_not_examined(self):
        host = _Host()
        host.write(_appended(["z" * 200]), name="notes.txt")
        self.assertEqual(host.check(), [])


class TestMarkersEscalateAndNothingElseDoes(unittest.TestCase):
    def _planted(self):
        host = _Host()
        host.write(_appended([_confirmed_payload()]))
        return host

    @unittest.skipUnless(_engine_loads(), "the content-scan engine is not importable here")
    def test_confirmed_markers_make_it_an_active_foothold(self):
        issues = self._planted().check(verify=True)
        self.assertEqual([i.id for i in issues], ["app-bundle-payload"])
        self.assertEqual(issues[0].severity, "warning")

    def test_the_content_scan_is_opt_in(self):
        # The corroborating scan is slow, so a default audit names the flag rather than paying it.
        self.assertEqual([i.id for i in self._planted().check()], ["app-bundle-appended-module"])
        self.assertIn("--verify", self._planted().check()[0].detail)

    def test_that_finding_gates_credential_rotation(self):
        # Rotating while a foothold is live is the reported wiper trigger, so this id has to reach
        # the rotation verdict rather than merely printing.
        self.assertIn("app-bundle-payload", ACTIVE_PERSISTENCE_IDS)
        self.assertIn("app-bundle-payload", ROTATION_UNSAFE_IDS)

    def test_markers_without_the_shape_are_not_this_finding(self):
        # This check grades an APPEND. A marker elsewhere in a bundle is a different claim and is
        # not licensed to borrow this one's rotation gate.
        host = _Host()
        host.write(_confirmed_payload())
        self.assertEqual(host.check(verify=True), [])


class TestAScanThatCouldNotRunIsNotAScanThatFoundNothing(unittest.TestCase):
    """`--verify` is the operator asking for the harder look. Every failure of the engine used to
    be answered with the empty list a clean scan returns, so the run reported the weak finding —
    whose own advice is to run `--verify` — over a scan that never happened."""

    def _planted(self):
        host = _Host()
        host.write(_appended([_confirmed_payload()]))
        return host

    @contextlib.contextmanager
    def _engine(self, verify_dir):
        stub = types.ModuleType("stayawake.bots.security.verify")
        stub.verify_dir = verify_dir
        with mock.patch.dict(sys.modules, {"stayawake.bots.security.verify": stub}):
            yield

    def _blocked_by(self, exc):
        with self._engine(_raising(exc)):
            return self._planted().check(verify=True)

    def test_an_engine_that_will_not_run_leaves_the_hole_as_its_own_item(self):
        issues = self._blocked_by(RuntimeError("signature store unreadable"))
        self.assertEqual([i.id for i in issues],
                         ["app-bundle-appended-module", APP_BUNDLE_SCAN_BLOCKED_ID])
        self.assertEqual(issues[0].severity, "info")
        self.assertEqual(issues[1].severity, "unknown")
        self.assertIn("signature store unreadable", issues[1].detail)

    def test_an_engine_that_will_not_import_is_reported_the_same_way(self):
        with mock.patch.dict(sys.modules, {"stayawake.bots.security.verify": None}):
            ids = [i.id for i in self._planted().check(verify=True)]
        self.assertIn(APP_BUNDLE_SCAN_BLOCKED_ID, ids)

    def test_it_never_tells_the_operator_to_run_what_they_just_ran(self):
        for issue in self._blocked_by(RuntimeError("boom")):
            self.assertNotIn("--verify", issue.remediation)
        detail = self._blocked_by(RuntimeError("boom"))[0].detail
        self.assertNotIn("`saw audit --verify` looks harder", detail)
        self.assertIn("did not complete", detail)

    def test_the_run_is_never_reported_as_having_found_nothing(self):
        text = render(self._blocked_by(RuntimeError("boom")), width=90)
        self.assertNotIn("no findings", text)
        self.assertIn("looks modified", text)

    def test_it_withholds_the_rotation_all_clear(self):
        # Rotating while a live foothold sits in an application bundle is the reported wiper
        # trigger, and a scan that did not run cannot say there is none.
        self.assertIn(APP_BUNDLE_SCAN_BLOCKED_ID, ROTATION_UNSAFE_IDS)
        self.assertEqual(rotation_safety({APP_BUNDLE_SCAN_BLOCKED_ID}), ROTATION_UNSAFE_UNKNOWN)
        self.assertNotIn(APP_BUNDLE_SCAN_BLOCKED_ID, ACTIVE_PERSISTENCE_IDS,
                         "not confirmed persistence — it is a hole, and must not outrank one")
        ids = {i.id for i in self._blocked_by(RuntimeError("boom"))}
        self.assertEqual(rotation_safety(ids), ROTATION_UNSAFE_UNKNOWN)

    def test_one_item_for_the_run_however_many_modules(self):
        """Counting the item alone did not pin this: the reason was listed once per module inside
        a single item, which is the same noise one layer down."""
        host = self._planted()
        host.write(_appended([_confirmed_payload()]), name="other.js")
        with self._engine(_raising(RuntimeError("boom"))):
            issues = host.check(verify=True)
        ids = [i.id for i in issues]
        self.assertEqual(ids.count(APP_BUNDLE_SCAN_BLOCKED_ID), 1)
        self.assertEqual(ids.count("app-bundle-appended-module"), 2)
        hole = next(i for i in issues if i.id == APP_BUNDLE_SCAN_BLOCKED_ID)
        self.assertEqual(hole.detail.count("RuntimeError: boom"), 1)

    def test_causes_that_differ_are_all_named(self):
        host = self._planted()
        host.write(_appended([_confirmed_payload()]), name="other.js")
        causes = iter([RuntimeError("first cause"), RuntimeError("second cause")])

        def engine(_directory):
            raise next(causes)

        with self._engine(engine):
            issues = host.check(verify=True)
        hole = next(i for i in issues if i.id == APP_BUNDLE_SCAN_BLOCKED_ID)
        self.assertIn("first cause", hole.detail)
        self.assertIn("second cause", hole.detail)

    def test_a_scan_that_ran_and_found_nothing_says_so(self):
        with self._engine(lambda _d: _Verdict(scanned_clean=True)):
            issues = self._planted().check(verify=True)
        self.assertEqual([i.id for i in issues], ["app-bundle-appended-module"])
        self.assertIn("no confirmed markers", issues[0].detail)
        self.assertFalse({i.id for i in issues} & ROTATION_UNSAFE_IDS)

    def test_only_a_clean_scan_clears_a_module(self):
        cases = {
            "too large": _Verdict(too_large=True),
            "a pipe or device present": _Verdict(partial=True,
                                                 unread=["a device or pipe must not be opened"]),
            "something went unread": _Verdict(partial=True),
            "a read gap": _Verdict(error="permission denied"),
            "no field set at all": _Verdict(),
        }
        for label, verdict in cases.items():
            with self.subTest(verdict=label):
                with self._engine(lambda _d, v=verdict: v):
                    issues = self._planted().check(verify=True)
                ids = [i.id for i in issues]
                self.assertIn(APP_BUNDLE_SCAN_BLOCKED_ID, ids, f"{label} is not a clean scan")
                shape = next(i for i in issues if i.id == "app-bundle-appended-module")
                self.assertNotIn("no confirmed markers", shape.detail)
                self.assertEqual(rotation_safety(set(ids)), ROTATION_UNSAFE_UNKNOWN)
                hole = next(i for i in issues if i.id == APP_BUNDLE_SCAN_BLOCKED_ID)
                self.assertNotIn("modules: .", hole.detail,
                                 "a hole with a blank reason tells the operator nothing")

    def test_the_reason_the_scan_gave_reaches_the_operator(self):
        with self._engine(lambda _d: _Verdict(partial=True, unread=["archives are not opened"])):
            issues = self._planted().check(verify=True)
        hole = next(i for i in issues if i.id == APP_BUNDLE_SCAN_BLOCKED_ID)
        self.assertIn("archives are not opened", hole.detail)

    def test_a_marker_wins_over_an_incomplete_scan(self):
        with self._engine(lambda _d: _Verdict(markers=["loader-decoder-fn"], partial=True)):
            ids = [i.id for i in self._planted().check(verify=True)]
        self.assertEqual(ids, ["app-bundle-payload"])

    @unittest.skipUnless(_engine_loads(), "the content-scan engine is not importable here")
    def test_the_stand_in_still_matches_the_engine(self):
        """Fields AND the derived reads on top of them — comparing only fields let the stand-in
        ship without `has_markers`, which the other consumer of this verdict asks for first."""
        from stayawake.bots.security.verify import DirVerdict

        def derived(cls):
            return {n for n, v in vars(cls).items() if isinstance(v, property)}

        self.assertEqual({f.name for f in dataclasses.fields(_Verdict)},
                         {f.name for f in dataclasses.fields(DirVerdict)})
        # The reads on top of the fields, which is where `has_markers` went missing. NOT `dir()`:
        # a field given a default here to keep the fixtures short becomes a class attribute and
        # shows up as a difference that means nothing.
        self.assertEqual(derived(_Verdict), derived(DirVerdict))

    def test_not_asking_for_the_scan_is_unchanged(self):
        issues = self._planted().check()
        self.assertEqual([i.id for i in issues], ["app-bundle-appended-module"])
        self.assertIn("--verify", issues[0].detail)

    def test_an_interrupt_stops_the_audit_rather_than_one_module(self):
        """Swallowing it here cost one interrupt per file to stop a run, and everything the run
        went on to report would carry scans nobody performed."""
        with self._engine(_raising(KeyboardInterrupt())), self.assertRaises(KeyboardInterrupt):
            self._planted().check(verify=True)


class TestCoverageIsNeverSilentlyBounded(unittest.TestCase):
    def test_a_module_whose_tail_never_ends_is_reported_not_dropped(self):
        # It was not graded, so it is not a clean result for that module.
        host = _Host()
        host.write("x" * 4096)
        with mock.patch.object(app_bundle, "_MAX_TAIL_BYTES", 512):
            issues = host.check()
        self.assertEqual([i.id for i in issues], ["app-bundle-partly-examined"])
        self.assertIn("lookback", issues[0].detail)

    def test_stopping_early_is_reported(self):
        host = _Host()
        for index in range(4):
            host.write(_CLEAN, name=f"m{index}.js")
        with mock.patch.object(app_bundle, "_MAX_FILES_PER_ROOT", 2):
            issues = host.check()
        self.assertEqual([i.id for i in issues], ["app-bundle-partly-examined"])

    def test_one_oversized_tree_does_not_abandon_the_applications_after_it(self):
        # The budget used to be per RUN and to break out of every loop, so a `resources/app`
        # symlinked at a developer checkout starved every application that came after it.
        host = _Host()
        for index in range(6):
            host.write(_CLEAN, name=f"m{index}.js")
        planted = _Host()
        planted.base = host.base                        # a second application on the same host
        planted.app = host.base / "Later.app" / "Contents" / "Resources" / "app"
        planted.module_dir = planted.app / "node_modules" / "pkg" / "dist"
        planted.module_dir.mkdir(parents=True)
        planted.write(_appended(["z" * 200]))
        with mock.patch.object(app_bundle, "_MAX_FILES_PER_ROOT", 2):
            found = [i.id for i in host.check()]
        self.assertIn("app-bundle-appended-module", found)
        self.assertIn("app-bundle-partly-examined", found)

    def test_a_line_of_invisible_characters_is_not_content(self):
        # The finding claims a character count. Counting the bytes after the indent made a line
        # with nothing visible on it read as content, and a claim the tool cannot support.
        host = _Host()
        host.write(_CLEAN + "\n" + " " * 60 + "\u00a0" * 60 + "\n")
        self.assertEqual(host.check(), [])


class TestItIsPartOfAnAudit(unittest.TestCase):
    def test_the_probe_is_registered(self):
        self.assertIn("application bundles", [label for label, _check in audit_checks()])


class TestAModuleThatCouldNotBeReadIsNotAModuleThatHeldNothing(unittest.TestCase):
    """The tier below the content scan: it decides whether that scan runs at all, and it answered
    an unreadable file exactly as it answered one it read and found nothing."""

    def _planted_beside(self, make):
        host = _Host()
        host.write(_appended([_confirmed_payload()]), name="readable.js")
        make(host.module_dir / "zz.js")
        return host

    def test_an_unreadable_module_never_hides_a_readable_one(self):
        host = self._planted_beside(lambda p: None)
        hidden = host.write(_appended([_confirmed_payload()]), name="hidden.js")
        os.chmod(hidden, 0o000)
        try:
            issues = host.check()
        finally:
            os.chmod(hidden, 0o644)
        ids = [i.id for i in issues]
        self.assertIn("app-bundle-appended-module", ids)
        self.assertIn(APP_BUNDLE_MODULE_UNREADABLE_ID, ids)

    def test_it_withholds_the_rotation_all_clear(self):
        self.assertIn(APP_BUNDLE_MODULE_UNREADABLE_ID, ROTATION_UNSAFE_IDS)
        self.assertEqual(rotation_safety({APP_BUNDLE_MODULE_UNREADABLE_ID}), ROTATION_UNSAFE_UNKNOWN)
        host = _Host()
        hidden = host.write(_appended([_confirmed_payload()]), name="hidden.js")
        os.chmod(hidden, 0o000)
        try:
            note = next(i for i in host.check() if i.id == APP_BUNDLE_MODULE_UNREADABLE_ID)
        finally:
            os.chmod(hidden, 0o644)
        self.assertEqual(note.severity, "unknown",
                         "a hole, not a finding — the report groups the two differently")

    def test_the_bounds_this_tool_chooses_are_not_the_same_claim(self):
        self.assertNotIn("app-bundle-partly-examined", ROTATION_UNSAFE_IDS)

    def test_anything_that_is_not_a_regular_file_is_not_read(self):
        d = Path(tempfile.mkdtemp())
        (d / "adir.js").mkdir()
        os.mkfifo(d / "pipe.js")
        (d / "dangling.js").symlink_to(d / "nothing-here")
        self.assertEqual(app_bundle._tail_lines(d / "adir.js")[1], app_bundle.UNREADABLE)
        self.assertEqual(app_bundle._tail_lines(d / "pipe.js")[1], app_bundle.UNREADABLE)
        # Nothing behind a dangling link to read, which is the rule the engine states for the same
        # case — and an Electron cache tree churns `.js` under an audit, so grading the churn as a
        # hole would raise the rotation gate on it.
        self.assertEqual(app_bundle._tail_lines(d / "dangling.js")[1], app_bundle.READ)
        self.assertEqual(app_bundle._tail_lines(d / "gone.js")[1], app_bundle.READ)

    def test_a_pipe_named_like_a_module_does_not_stop_the_audit(self):
        """In a subprocess: if the guard regresses, this fails on the timeout instead of hanging."""
        host = _Host()
        host.write(_appended([_confirmed_payload()]))
        os.mkfifo(host.module_dir / "zz.js")
        src = str(Path(app_bundle.__file__).resolve().parents[4])
        script = ("import sys; sys.path.insert(0, %r)\n"
                  "from stayawake.bots.security.hygiene.app_bundle import _tail_lines, UNREADABLE\n"
                  "from pathlib import Path\n"
                  "assert _tail_lines(Path(%r))[1] == UNREADABLE\n"
                  "print('done')") % (src, str(host.module_dir / "zz.js"))
        done = subprocess.run([sys.executable, "-c", script], capture_output=True,
                              text=True, timeout=20)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("done", done.stdout)


class TestWhatTheWalkCouldNotReachIsReportedToo(unittest.TestCase):
    """A counter for files the reader could not read, over a walk that dropped whole subtrees in
    silence: an unreadable FILE failed closed while its unreadable PARENT failed open, and anything
    able to write a module can chmod the directory holding it."""

    def _planted(self):
        host = _Host()
        host.write(_appended([_confirmed_payload()]), name="payload.js")
        return host

    def test_locking_the_directory_is_no_longer_the_way_past_it(self):
        host = self._planted()
        os.chmod(host.module_dir, 0o000)
        try:
            ids = [i.id for i in host.check()]
        finally:
            os.chmod(host.module_dir, 0o755)
        self.assertIn(APP_BUNDLE_MODULE_UNREADABLE_ID, ids,
                      "locking the parent must fail closed, as locking the file does")

    def test_a_base_that_will_not_open_is_not_an_empty_surface(self):
        """`Path.glob` reports a base it cannot list as one holding nothing, so a single chmod took
        every application under it out of the surface with nothing said."""
        host = self._planted()
        os.chmod(host.base, 0o000)
        try:
            ids = [i.id for i in host.check()]
        finally:
            os.chmod(host.base, 0o755)
        self.assertIn(APP_BUNDLE_MODULE_UNREADABLE_ID, ids)

    def test_it_names_them_so_they_can_be_cleared(self):
        """A count alone raises a gate with no way to act on it, which is alarm fatigue against a
        gate whose whole purpose is to be believed. The sibling unknown-tier finding names them."""
        host = self._planted()
        hidden = host.write(_appended([_confirmed_payload()]), name="hidden.js")
        os.chmod(hidden, 0o000)
        try:
            note = next(i for i in host.check() if i.id == APP_BUNDLE_MODULE_UNREADABLE_ID)
        finally:
            os.chmod(hidden, 0o644)
        self.assertIn(str(hidden), note.detail)

    def test_a_bound_reached_on_the_last_module_of_a_directory_is_still_reported(self):
        """The inner break never runs there, so one truncation in five was reported as nothing."""
        host = _Host()
        for n in range(3):
            host.write(_CLEAN, name=f"m{n}.js")
        host.write(_appended([_confirmed_payload()]),
                   where=host.module_dir / "deeper", name="payload.js")
        with mock.patch.object(app_bundle, "_MAX_FILES_PER_ROOT", 3):
            ids = [i.id for i in host.check()]
        self.assertIn("app-bundle-partly-examined", ids)
        self.assertNotIn("app-bundle-appended-module", ids, "the walk really did stop short")

class TestTheSiblingSurfaceAnswersTheSameWay(unittest.TestCase):
    """The host-artifact probe is the other `verify_dir` consumer and had the same defect: it threw
    away the reason a scan failed, so `--verify` over a broken engine printed the fallback whose
    own advice is to run `--verify`."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.artifact = self.d / ".node_modules"
        self.artifact.mkdir()
        (self.artifact / "x.js").write_text("y")

    @contextlib.contextmanager
    def _only_this_artifact(self):
        with mock.patch.object(host_artifacts, "_global_folders", lambda: [self.artifact]), \
             mock.patch.object(host_artifacts, "_host_user_tag", lambda: None), \
             mock.patch.object(host_artifacts, "_sideloaded_python_dir", lambda unread: None), \
             mock.patch.object(host_artifacts, "_staged_secret_scanner",
                               lambda dirs, unread: None):
            yield

    def test_a_scan_that_blew_up_is_not_the_advice_to_run_it(self):
        with self._only_this_artifact(), \
             mock.patch.object(host_artifacts, "_verify_weak_artifact",
                               _raising(RuntimeError("engine gone"))):
            issues = host_artifacts.check_host_artifacts(verify=True)
        ids = {i.id for i in issues}
        self.assertIn(HOST_ARTIFACT_SCAN_BLOCKED_ID, ids)
        self.assertEqual(rotation_safety(ids), ROTATION_UNSAFE_UNKNOWN)

    def test_an_artifact_that_is_not_a_scannable_directory_still_falls_back(self):
        with self._only_this_artifact(), \
             mock.patch.object(host_artifacts, "_verify_weak_artifact", lambda item: None):
            ids = {i.id for i in host_artifacts.check_host_artifacts(verify=True)}
        self.assertNotIn(HOST_ARTIFACT_SCAN_BLOCKED_ID, ids)
        self.assertIn("host-drop-artifact-weak", ids)

    def test_it_never_claims_a_scan_of_the_rest(self):
        stub = types.ModuleType("stayawake.bots.security.verify")
        stub.verify_dir = lambda _p: _Verdict(
            partial=True, unread=["a device or pipe must not be opened"])
        with mock.patch.dict(sys.modules, {"stayawake.bots.security.verify": stub}), \
             self._only_this_artifact():
            issues = host_artifacts.check_host_artifacts(verify=True)
        weak = next(i for i in issues if i.id == "host-drop-artifact-weak")
        self.assertNotIn("found no worm markers", weak.detail + weak.remediation)
        self.assertIn("not fully scanned", weak.detail + weak.remediation)

if __name__ == "__main__":
    unittest.main()

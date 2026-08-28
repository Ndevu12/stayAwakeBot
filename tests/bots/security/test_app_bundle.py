#!/usr/bin/env python3
"""#218 — an installed application's own JavaScript. No manifest lists it, no lockfile covers it
and removing `node_modules` never reaches it, so the repository and dependency scans cannot see it.

Grading rationale, the corpus the bounds were calibrated against, and the limits: `Ndevu12/saw#218`.
An uncorroborated hit stays `info`; only the opt-in corroboration makes it an active foothold."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import app_bundle, audit_checks
from stayawake.bots.security.hygiene.models import ACTIVE_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS

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

    def test_a_file_that_cannot_be_read_is_skipped_rather_than_crashing(self):
        host = _Host()
        target = host.write(_appended(["z" * 200]))
        os.chmod(target, 0o000)
        try:
            self.assertEqual(host.check(), [])
        finally:
            os.chmod(target, 0o644)

    def test_non_javascript_in_the_same_tree_is_not_examined(self):
        host = _Host()
        host.write(_appended(["z" * 200]), name="notes.txt")
        self.assertEqual(host.check(), [])


class TestMarkersEscalateAndNothingElseDoes(unittest.TestCase):
    def _planted(self):
        host = _Host()
        host.write(_appended([_confirmed_payload()]))
        return host

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


if __name__ == "__main__":
    unittest.main()

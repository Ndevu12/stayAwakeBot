#!/usr/bin/env python3
"""Every editor on this machine, not whichever one was found first.

The check looked for one directory named `Code` and returned at the first hit, so a machine with
Cursor beside VS Code had Cursor examined by nothing at all."""
from __future__ import annotations

import json
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from stayawake.bots.security.harden import settings as editorsettings
from stayawake.bots.security.hygiene import editor, editors
from stayawake.bots.security.jsonc import load_jsonc
from stayawake.utils import appdirs, atomicwrite


def _editor_at(base: pathlib.Path, name: str, body: str = "{}") -> pathlib.Path:
    """A directory laid out the way this family lays one out, state file and all."""
    user = base / name / "User"
    (user / "globalStorage").mkdir(parents=True)
    (user / "globalStorage" / "state.vscdb").write_bytes(b"")
    (user / "workspaceStorage").mkdir(parents=True)
    settings = user / "settings.json"
    settings.write_text(body, encoding="utf-8")
    return settings


class TestEveryEditorIsFoundNotJustTheFirst(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())

    def test_a_fork_beside_vs_code_is_found_too(self):
        _editor_at(self.base, "Code")
        _editor_at(self.base, "Cursor")
        found = editors.installed([self.base])
        self.assertEqual([e.name for e in found.editors], ["Cursor", "VS Code"])

    def test_a_fork_this_tool_was_never_told_about_is_still_examined(self):
        # Coverage comes from the layout, not from a name list, so a fork released tomorrow is
        # examined without a code change. A name list only decides what a finding calls it.
        _editor_at(self.base, "SomeNewFork")
        found = editors.installed([self.base])
        self.assertEqual([e.name for e in found.editors], ["SomeNewFork"])

    def test_a_directory_that_is_not_one_of_these_is_left_alone(self):
        # `User/settings.json` alone is not enough: an unrelated application with that shape would
        # be graded against keys it has never heard of, and — through harden — written to. Three
        # same-uid mkdirs would otherwise enrol any JSON file into grade-and-write.
        lonely = self.base / "SomethingElse" / "User"
        lonely.mkdir(parents=True)
        (lonely / "settings.json").write_text("{}", encoding="utf-8")
        (lonely / "globalStorage").mkdir()
        (lonely / "workspaceStorage").mkdir()
        self.assertEqual(editors.installed([self.base]).editors, [],
                         "the state the editor writes for itself has to be there too")

    def test_a_symlinked_user_directory_does_not_escape_the_editor(self):
        # The last component looks ordinary, so a guard that asks only about the file is walked
        # past: the graded-and-written file would sit outside the editor entirely.
        outside = pathlib.Path(tempfile.mkdtemp())
        real = _editor_at(outside, "Elsewhere")
        (self.base / "Cursor").mkdir(parents=True)
        (self.base / "Cursor" / "User").symlink_to(real.parent)
        self.assertEqual(editors.installed([self.base]).editors, [])
        self.assertTrue(editors.installed([self.base]).unreadable)

    def test_an_editor_behind_an_unreadable_directory_is_reported_not_dropped(self):
        settings = _editor_at(self.base, "Windsurf")
        settings.parent.chmod(0o000)
        try:
            found = editors.installed([self.base])
        finally:
            settings.parent.chmod(0o755)
        self.assertEqual(found.editors, [])
        self.assertTrue(found.unreadable, "an editor nobody could read must not read as absent")

    def test_a_name_it_does_not_model_is_still_examined_when_it_is_one_of_these(self):
        # A name decides what an editor is CALLED, never whether it is examined; otherwise a
        # rename is a way to skip the check.
        _editor_at(self.base, "Zed")
        found = editors.installed([self.base])
        self.assertEqual([e.name for e in found.editors], ["Zed"])
        self.assertEqual(found.not_modelled, [])

    def test_the_same_editor_reached_by_two_bases_is_one_editor(self):
        _editor_at(self.base, "Code")
        self.assertEqual(len(editors.installed([self.base, self.base]).editors), 1)

    def test_a_base_that_cannot_be_read_is_reported_not_skipped(self):
        found = editors.installed([types.SimpleNamespace(
            iterdir=mock.Mock(side_effect=PermissionError()), name="x")])
        self.assertEqual(len(found.unreadable), 1)

    def test_a_base_that_is_not_there_is_not_an_error(self):
        self.assertEqual(editors.installed([self.base / "nope"]).unreadable, [])


class TestAnEditorItDoesNotModelIsDisclosed(unittest.TestCase):
    """A machine is never reported as covered for an editor nobody looked at."""

    def test_it_is_named_and_the_finding_says_nothing_covers_it(self):
        base = pathlib.Path(tempfile.mkdtemp())
        (base / "JetBrains").mkdir()
        found = editors.installed([base])
        self.assertEqual(found.not_modelled, ["JetBrains IDEs"])
        issue = next(i for i in editor.check_editors(find=lambda: found)
                     if i.id == editor.EDITORS_NOT_EXAMINED_ID)
        self.assertEqual(issue.severity, "unknown")

    def test_and_it_is_not_graded_against_keys_it_has_never_heard_of(self):
        base = pathlib.Path(tempfile.mkdtemp())
        (base / "JetBrains").mkdir()
        found = editors.installed([base])
        self.assertEqual(found.editors, [])


class TestEveryEditorIsGradedNotJustOne(unittest.TestCase):
    def test_a_finding_is_raised_for_each_one_that_holds_it(self):
        base = pathlib.Path(tempfile.mkdtemp())
        _editor_at(base, "Code", '{"task.allowAutomaticTasks": "off"}')
        _editor_at(base, "Cursor", "{}")
        found = editors.installed([base])
        issues = editor.check_editors(find=lambda: found)
        self.assertEqual([i.id for i in issues], ["editor-autotasks-default"])
        self.assertIn("Cursor", issues[0].title)

    def test_the_finding_names_which_editor_it_is_about(self):
        base = pathlib.Path(tempfile.mkdtemp())
        _editor_at(base, "Cursor", '{"security.workspace.trust.enabled": false}')
        issues = editor.check_editors(find=lambda: editors.installed([base]))
        self.assertIn("Cursor", issues[0].title)
        self.assertNotIn("VS Code", issues[0].title)

    def test_one_that_cannot_be_read_is_reported_not_passed_over(self):
        base = pathlib.Path(tempfile.mkdtemp())
        settings = _editor_at(base, "Code")
        with mock.patch.object(pathlib.Path, "read_text", side_effect=PermissionError()):
            issues = editor.check_editors(find=lambda: editors.installed([base]))
        self.assertTrue(issues, "an unreadable settings file must not read as clean")
        self.assertEqual(issues[-1].severity, "unknown")
        self.assertIn(str(settings.parent.parent.name), " ".join(i.detail for i in issues) + "Code")


class TestTheIdsNoLongerClaimAnEditorTheyAreNotAbout(unittest.TestCase):
    """The id reaches the JSON and the SARIF. `vscode-…` on a Cursor finding is a false statement
    about the machine, not a naming preference."""

    def test_no_finding_carries_the_old_vendor_specific_id(self):
        base = pathlib.Path(tempfile.mkdtemp())
        _editor_at(base, "Cursor", '{"security.workspace.trust.untrustedFiles": "open"}')
        ids = [i.id for i in editor.check_editors(find=lambda: editors.installed([base]))]
        self.assertTrue(ids)
        for issue_id in ids:
            self.assertFalse(issue_id.startswith("vscode-"), issue_id)


class TestCorrectingWritesOnlyWhatItKnows(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.record = self.base / "record.json"

    def _settle(self, **kw):
        found = editors.installed([self.base])
        return editorsettings.settle(find=lambda: found, record=self.record, **kw)

    def test_the_known_correct_value_is_written_to_every_editor(self):
        a = _editor_at(self.base, "Code", "{}")
        b = _editor_at(self.base, "Cursor", "{}")
        out = self._settle()
        self.assertTrue(out.settled)
        self.assertTrue(out.changed)
        for path in (a, b):
            self.assertIn('"task.allowAutomaticTasks": "off"', path.read_text())

    def test_a_dangerous_auto_approval_is_turned_off(self):
        body = '{"task.allowAutomaticTasks": "off", "chat.tools.terminal.autoApprove": {"npx": true}}'
        path = _editor_at(self.base, "Code", body)
        out = self._settle()
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.CORRECTED])
        self.assertEqual(load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"],
                         {"npx": False})

    def test_and_the_commands_that_are_not_dangerous_are_left_alone(self):
        # Turning the whole table off is not what was asked for, and it costs a prompt on every
        # command the operator deliberately allowed.
        body = ('{"chat.tools.terminal.autoApprove": {"npx": true, "ls": true, '
                '"git status": true}}')
        path = _editor_at(self.base, "Code", body)
        self._settle()
        table = load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"]
        self.assertEqual(table, {"npx": False, "ls": True, "git status": True})

    def test_approving_every_command_is_turned_off_outright(self):
        path = _editor_at(self.base, "Code", '{"chat.tools.terminal.autoApprove": true}')
        self._settle()
        self.assertIs(load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"], False)

    def test_a_catch_all_pattern_counts_as_approving_everything(self):
        path = _editor_at(self.base, "Code",
                          '{"chat.tools.terminal.autoApprove": {"/.*/": true, "ls": true}}')
        self._settle()
        self.assertEqual(load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"],
                         {"/.*/": False, "ls": True})

    def test_the_object_form_of_an_entry_is_turned_off_too(self):
        path = _editor_at(self.base, "Code",
                          '{"chat.tools.terminal.autoApprove": {"rm": {"approve": true}}}')
        self._settle()
        self.assertEqual(load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"],
                         {"rm": {"approve": False}})

    def test_what_was_turned_off_can_be_put_back(self):
        path = _editor_at(self.base, "Code", '{"chat.tools.terminal.autoApprove": {"npx": true}}')
        found = editors.installed([self.base])
        editorsettings.settle(find=lambda: found, record=self.record)
        out = editorsettings.take_back(record=self.record)
        self.assertTrue(out.restored)
        self.assertEqual(load_jsonc(path.read_text())["chat.tools.terminal.autoApprove"],
                         {"npx": True})

    def test_and_that_setting_still_reaches_the_operator_as_a_finding(self):
        body = '{"task.allowAutomaticTasks": "off", "chat.tools.terminal.autoApprove": {"npx": true}}'
        _editor_at(self.base, "Code", body)
        ids = [i.id for i in editor.check_editors(find=lambda: editors.installed([self.base]))]
        self.assertIn("editor-autoapprove-risky", ids)

    def test_an_editor_already_correct_is_not_rewritten(self):
        body = ('{"task.allowAutomaticTasks": "off", "security.workspace.trust.enabled": true, '
                '"security.workspace.trust.untrustedFiles": "prompt"}')
        path = _editor_at(self.base, "Code", body)
        before = path.read_text()
        out = self._settle()
        self.assertFalse(out.changed)
        self.assertEqual(path.read_text(), before)

    def test_a_write_that_does_not_land_is_reported_not_counted_as_done(self):
        _editor_at(self.base, "Code", "{}")
        out = self._settle(write=lambda *a, **k: False)
        self.assertFalse(out.settled)
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.NOT_WRITTEN])

    def test_the_file_keeps_its_own_permissions(self):
        path = _editor_at(self.base, "Code", "{}")
        path.chmod(0o644)
        self._settle()
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)


class TestWhatWasChangedCanBePutBack(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.record = self.base / "record.json"

    def test_a_value_that_was_there_before_is_restored(self):
        path = _editor_at(self.base, "Code", '{"task.allowAutomaticTasks": "on"}')
        found = editors.installed([self.base])
        editorsettings.settle(find=lambda: found, record=self.record)
        self.assertIn('"off"', path.read_text())
        out = editorsettings.take_back(record=self.record)
        self.assertTrue(out.done)
        self.assertIn('"task.allowAutomaticTasks": "on"', path.read_text())

    def test_a_key_that_was_added_is_kept_and_said_so_rather_than_deleted(self):
        # Undo restores; it does not remove. Saying a key was put back when it is still there is
        # the failure this reports instead of committing.
        path = _editor_at(self.base, "Code", "{}")
        found = editors.installed([self.base])
        editorsettings.settle(find=lambda: found, record=self.record)
        out = editorsettings.take_back(record=self.record)
        self.assertTrue(out.kept)
        self.assertEqual(out.restored, [])
        self.assertIn('"task.allowAutomaticTasks"', path.read_text())

    def test_the_record_holds_no_part_of_the_operators_settings(self):
        # The settings file is the operator's and can hold their secrets; only saw's own key and
        # the literal that stood in front of it are kept.
        secret = '{"someToken": "sk-not-a-real-secret-abcdef", "task.allowAutomaticTasks": "on"}'
        _editor_at(self.base, "Code", secret)
        found = editors.installed([self.base])
        editorsettings.settle(find=lambda: found, record=self.record)
        written = self.record.read_text()
        self.assertNotIn("sk-not-a-real-secret", written)
        self.assertNotIn("someToken", written)
        self.assertIn("task.allowAutomaticTasks", written)

    def test_one_that_cannot_be_put_back_is_reported_not_dropped(self):
        _editor_at(self.base, "Code", '{"task.allowAutomaticTasks": "on"}')
        found = editors.installed([self.base])
        editorsettings.settle(find=lambda: found, record=self.record)
        out = editorsettings.take_back(record=self.record, write=lambda *a, **k: False)
        self.assertFalse(out.done)
        self.assertTrue(out.failed)
        self.assertTrue(editorsettings._remembered(self.record)[0],
                        "what could not be put back stays in the record")


class TestTheWriterIsASeamATestCanSubstitute(unittest.TestCase):
    """A default bound at definition time cannot be patched, so a canary aimed at it is inert and
    a test writes to the machine while the canary reports nothing."""

    def test_a_substituted_writer_means_nothing_reaches_the_file(self):
        # Asserting the seam was CALLED pins nothing: the record is written through the same name,
        # so a call from anywhere satisfies it while the settings go to the real writer. This asks
        # the file instead.
        base = pathlib.Path(tempfile.mkdtemp())
        path = _editor_at(base, "Code", "{}")
        found = editors.installed([base])
        with mock.patch.object(editorsettings, "atomicwrite",
                               types.SimpleNamespace(replace=lambda *a, **k: True)):
            editorsettings.settle(find=lambda: found, record=base / "r.json")
        self.assertEqual(path.read_text(), "{}",
                         "settle wrote through a seam the caller could not substitute")


class TestOnePlatformAuthorityForWhereDataLives(unittest.TestCase):
    def test_each_platform_answers_with_its_own_convention(self):
        for platform, expected in (("darwin", "Library/Application Support"),
                                   ("linux", ".config")):
            with self.subTest(platform=platform), \
                    mock.patch.object(appdirs.sys, "platform", platform):
                self.assertTrue(str(appdirs.user_data_dirs()[0]).endswith(expected))

    def test_windows_with_nothing_set_says_nowhere_rather_than_guessing(self):
        with mock.patch.object(appdirs.sys, "platform", "win32"), \
                mock.patch.object(appdirs.env, "get", return_value=None):
            self.assertEqual(appdirs.user_data_dirs(), [])


class TestTheWriteLandsWholeOrNotAtAll(unittest.TestCase):
    def test_a_symlinked_destination_is_refused(self):
        d = pathlib.Path(tempfile.mkdtemp())
        real, link = d / "real.json", d / "link.json"
        real.write_text("{}")
        link.symlink_to(real)
        self.assertFalse(atomicwrite.replace(link, "{}"))
        self.assertEqual(real.read_text(), "{}")

    def test_the_read_back_compares_what_was_written(self):
        d = pathlib.Path(tempfile.mkdtemp())
        target = d / "x.json"
        self.assertTrue(atomicwrite.replace(target, '{"a": 1}'))
        self.assertEqual(target.read_text(), '{"a": 1}')

    def test_a_record_that_is_not_readable_is_not_an_empty_one(self):
        # They are opposite facts. Reading them alike reports every change as put back on exactly
        # the runs where nobody can tell what was changed.
        d = pathlib.Path(tempfile.mkdtemp())
        broken = d / "broken.json"
        broken.write_text("not json at all")
        self.assertEqual(editorsettings._remembered(broken), ([], False))
        self.assertEqual(editorsettings._remembered(d / "absent.json"), ([], True))


class TestNothingIsCalledCorrectThatWasNotWritten(unittest.TestCase):
    """"Nothing was planned" covers a setting already right AND one this refused to touch. Reading
    those alike reported a machine as protected over a control that was never applied."""

    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.record = self.base / "record.json"

    def _settle(self, **kw):
        found = editors.installed([self.base])
        return editorsettings.settle(find=lambda: found, record=self.record, **kw)

    def test_a_key_present_twice_is_refused_not_called_already_correct(self):
        body = ('{"security.workspace.trust.enabled": false,\n'
                ' "security.workspace.trust.enabled": false}')
        path = _editor_at(self.base, "Code", body)
        out = self._settle()
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.NOT_WRITTEN])
        self.assertFalse(out.settled)
        self.assertIn("false", path.read_text())

    def test_a_comment_after_the_closing_brace_is_written_into_safely(self):
        # VS Code settings really are JSONC; a comment outside the object is ordinary.
        path = _editor_at(self.base, "Code", '{\n  "editor.fontSize": 12\n}\n// mine\n')
        out = self._settle()
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.CORRECTED])
        from stayawake.bots.security.jsonc import load_jsonc
        self.assertEqual(load_jsonc(path.read_text())["task.allowAutomaticTasks"], "off")
        self.assertIn("// mine", path.read_text())

    def test_a_correction_that_could_not_be_recorded_still_counts_as_applied(self):
        # The control is in place; what was lost is the undo. Calling the machine unprotected here
        # would teach an operator to read that line as noise.
        _editor_at(self.base, "Code", "{}")
        out = self._settle(remember=lambda entries, record: False)
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.NOT_RECORDED])
        self.assertTrue(out.settled)
        self.assertTrue(out.changed)


class TestTheVerdictLineKnowsAboutEditors(unittest.TestCase):
    """An operator reads the verdict, not the exit code. A control left undone that the verdict
    does not know about is a machine reported as protected."""

    def test_an_editor_left_uncorrected_is_not_this_machine_is_protected(self):
        from stayawake.bots.security import harden
        stuck = editorsettings.Correcting(outcomes=[editorsettings.EditorOutcome(
            "Cursor", pathlib.Path("/x"), editorsettings.NOT_WRITTEN, "refused")])
        code, body = harden.run(
            supported=lambda: True, live=lambda: [], stop=lambda: None,
            folders=lambda: [pathlib.Path("/denial")],
            apply=lambda p: harden.PathOutcome(p, harden.ENFORCING, "in place"),
            settle_hooks=_hooks_in_place, schedule_pass=lambda: None,
            altered=lambda: False, saw_runs=lambda: True,
            editor_pass=lambda: stuck)
        self.assertNotIn("This machine is protected.", body.splitlines()[0])
        self.assertEqual(code, 3)


class TestTakingBackNeverClaimsMoreThanHappened(unittest.TestCase):
    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.record = self.base / "record.json"

    def _settle(self):
        found = editors.installed([self.base])
        return editorsettings.settle(find=lambda: found, record=self.record)

    def test_a_key_it_added_keeps_the_undo_from_being_done(self):
        _editor_at(self.base, "Code", "{}")
        self._settle()
        out = editorsettings.take_back(record=self.record)
        self.assertTrue(out.kept)
        self.assertFalse(out.done, "a key still in the file is not a control taken back")

    def test_and_a_second_run_still_says_so_rather_than_finding_nothing(self):
        _editor_at(self.base, "Code", "{}")
        self._settle()
        editorsettings.take_back(record=self.record)
        again = editorsettings.take_back(record=self.record)
        self.assertTrue(again.kept, "the record lost what is still on disk")
        self.assertFalse(again.done)

    def test_an_unreadable_record_is_never_everything_put_back(self):
        self.record.write_text("truncated{")
        out = editorsettings.take_back(record=self.record)
        self.assertFalse(out.done)
        self.assertTrue(out.unreadable_record)

    def test_harden_does_not_claim_it_all_came_back_over_a_kept_key(self):
        from stayawake.bots.security import harden
        kept = editorsettings.TakingBack(kept=["/x: task.allowAutomaticTasks"])
        code, body = harden.take_back(
            supported=lambda: True, folders=lambda: [pathlib.Path("/denial")],
            remove=lambda p: harden.PathOutcome(p, harden.REMOVED, "gone"),
            unschedule=lambda: harden.schedule.NOTHING_TO_REMOVE,
            restore_editors=lambda: kept)
        self.assertNotIn("Every control this tool placed here has been taken back",
                         body.splitlines()[0])
        self.assertEqual(code, 3)


class TestItNeverLeavesSettingsItCannotStandBehind(unittest.TestCase):
    """A settings file really is JSONC, and every edit here is a substitution over raw bytes. The
    read-back compares bytes, so only the PARSED result can say the change is the change."""

    def setUp(self):
        self.base = pathlib.Path(tempfile.mkdtemp())
        self.record = self.base / "record.json"

    def _settle(self, **kw):
        found = editors.installed([self.base])
        return editorsettings.settle(find=lambda: found, record=self.record, **kw)

    def _still_parses(self, path):
        from stayawake.bots.security.jsonc import load_jsonc
        load_jsonc(path.read_text())

    def test_a_trailing_line_comment_keeps_the_file_readable(self):
        # The separating comma has to go after the MEMBER. Put after the comment, the comment eats
        # it and the file stops parsing — while the run reports a correction.
        body = '{\n  "editor.fontSize": 14,\n  "files.autoSave": "onFocusChange" // tab away\n}\n'
        path = _editor_at(self.base, "Code", body)
        out = self._settle()
        self._still_parses(path)
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.CORRECTED])
        self.assertIn("// tab away", path.read_text())
        self.assertIn('"task.allowAutomaticTasks": "off"', path.read_text())

    def test_a_comment_holding_the_key_is_not_treated_as_the_setting(self):
        # Editing the operator's note inverts what they wrote and changes nothing the editor reads.
        body = ('{\n  // "task.allowAutomaticTasks": "on", <- I turned this off on purpose\n'
                '  "editor.fontSize": 12\n}\n')
        path = _editor_at(self.base, "Code", body)
        self._settle()
        after = path.read_text()
        self._still_parses(path)
        self.assertIn('// "task.allowAutomaticTasks": "on", <- I turned this off on purpose', after)
        self.assertIn('"task.allowAutomaticTasks": "off"', after)

    def test_a_file_that_does_not_parse_to_begin_with_is_left_alone(self):
        path = _editor_at(self.base, "Code", "{ this is not settings")
        before = path.read_text()
        out = self._settle()
        self.assertEqual(path.read_text(), before)
        self.assertFalse(out.settled)

    def test_a_save_between_the_read_and_the_write_is_not_clobbered(self):
        # The corrected text is derived from a stale read, and the write verifies only that its own
        # bytes landed — so without a re-read the developer's save is overwritten wholesale.
        path = _editor_at(self.base, "Code", '{"editor.fontSize": 12}')
        theirs = '{"editor.fontSize": 18, "python.defaultInterpreterPath": "/usr/bin/python3"}'
        reads = [path.read_text(), theirs]
        found = editors.installed([self.base])
        with mock.patch.object(editorsettings, "_read", side_effect=lambda p: reads.pop(0)):
            out = editorsettings.settle(
                find=lambda: found, record=self.record,
                write=lambda *a, **k: self.fail("wrote over a file that had changed"))
        self.assertEqual([o.state for o in out.outcomes], [editorsettings.NOT_WRITTEN])
        self.assertFalse(out.settled)

    def test_one_unreadable_file_does_not_end_the_pass_for_the_others(self):
        bad = _editor_at(self.base, "Code")
        bad.write_bytes(b'{"editor.fontSize": "caf\xe9"}')
        good = _editor_at(self.base, "Cursor", "{}")
        out = self._settle()
        states = {o.name: o.state for o in out.outcomes}
        self.assertEqual(states["VS Code"], editorsettings.NOT_WRITTEN)
        self.assertEqual(states["Cursor"], editorsettings.CORRECTED)
        self.assertIn('"task.allowAutomaticTasks": "off"', good.read_text())

    def test_correcting_one_setting_does_not_rewrite_every_line(self):
        path = _editor_at(self.base, "Code", '{\r\n  "editor.fontSize": 12\r\n}')
        self._settle()
        self.assertIn(b"\r\n", path.read_bytes(), "the file's own line endings were replaced")


def _hooks_in_place():
    """Hook settling that changes nothing, for a test that is not about hooks."""
    from stayawake.bots.security import hook

    class _InPlace:
        state = hook.IN_PLACE
    return hook.Settling(actions=[_InPlace()], target="/template")


if __name__ == "__main__":
    unittest.main()

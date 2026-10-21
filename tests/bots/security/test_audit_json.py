#!/usr/bin/env python3
"""`saw audit --json` carries the same audit the report shows, for a program to read."""
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from stayawake import cli
from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene.models import HygieneIssue
from stayawake.bots.security.hygiene.outcome import BLOCKED, FOUND, CheckOutcome, blocked_issue
from stayawake.utils import exitcodes


def _issue(issue_id, severity, title, detail="Detail.", fix="Fix it.", **extra):
    return HygieneIssue(issue_id, severity, title, detail, fix, **extra)


def _flowed(issues) -> str:
    return " ".join(hygiene.render(issues).split())


class TestTheDocumentMatchesTheReport(unittest.TestCase):
    def test_a_clean_audit_says_rotation_is_safe(self):
        document = hygiene.as_document([])
        self.assertEqual(document["rotation"]["verdict"], "safe")
        self.assertEqual(document["rotation"]["to_confirm"], [])
        self.assertEqual(document["findings"], [])
        self.assertIn(document["rotation"]["sentence"], hygiene.render([]))

    def test_every_shown_line_is_in_the_document(self):
        weak = _issue("host-drop-artifact-weak", "info", "A weak drop", "Left in two places.",
                      "Confirm it is yours.", command="saw audit --verify")
        editor = _issue("editor-autotasks-on", "warning", "An editor runs tasks", "It runs them.",
                        "Turn them off.")
        unread = _issue("persistence-surface-unverified", "unknown", "A location was not read",
                        "Could not read the start-up list.", "Read it by hand.")
        blocked = blocked_issue("cached credentials", "The keychain did not answer.",
                                certifies_surface=False)
        issues = [weak, editor, unread, blocked]
        outcomes = [
            CheckOutcome("host drop-files", FOUND, (weak,)),
            CheckOutcome("editor settings", FOUND, (editor,)),
            CheckOutcome("OS-service persistence", "unknown", (unread,)),
            CheckOutcome("cached credentials", BLOCKED, (blocked,), "The keychain did not answer."),
        ]
        document = hygiene.as_document(outcomes)
        report = _flowed(issues)
        blob = json.dumps(document)
        for issue in issues:
            self.assertIn(issue.title, blob)
            self.assertIn(issue.detail, blob)
            self.assertIn(issue.remediation, blob)
        self.assertIn(document["rotation"]["sentence"], report)
        for note in document["scope_notes"]:
            self.assertIn(" ".join(note.split()), report)
        self.assertEqual(document["rotation"]["verdict"], "unsafe")
        self.assertEqual(document["rotation"]["to_confirm"], ["host-drop-artifact-weak"])
        self.assertEqual(document["incomplete"], [{
            "probe": "cached credentials",
            "reason": blocked.detail,
            "title": blocked.title,
            "fix": blocked.remediation,
        }])
        self.assertEqual([item["command"] for item in document["findings"] if "command" in item],
                         ["saw audit --verify"])

    def test_a_finding_to_confirm_is_safe_once_confirmed(self):
        weak = _issue("autorun-entry-returned", "info", "An autorun entry came back", "It returned.",
                      "Confirm it is yours.")
        document = hygiene.as_document([CheckOutcome("autorun surface", FOUND, (weak,))])
        self.assertEqual(document["rotation"]["verdict"], "safe-once-confirmed")
        self.assertEqual(document["rotation"]["to_confirm"], ["autorun-entry-returned"])
        self.assertEqual(document["findings"][0]["confidence"], "weak")
        self.assertIn("safe once you confirm", document["rotation"]["sentence"])

    def test_a_blocked_start_up_check_stays_unsafe(self):
        blocked = blocked_issue("OS-service persistence", "The list did not answer.",
                                certifies_surface=True)
        document = hygiene.as_document([
            CheckOutcome("OS-service persistence", BLOCKED, (blocked,), "The list did not answer.")])
        self.assertEqual(document["rotation"]["verdict"], "unsafe")
        self.assertEqual(document["incomplete"][0]["probe"], "OS-service persistence")

    def test_a_blocked_probe_with_nothing_unsafe_is_incomplete(self):
        blocked = blocked_issue("cached credentials", "The keychain did not answer.",
                                certifies_surface=False)
        document = hygiene.as_document([
            CheckOutcome("cached credentials", BLOCKED, (blocked,), "The keychain did not answer.")])
        self.assertEqual(document["rotation"]["verdict"], "incomplete")
        self.assertIn("rotating credentials is safe", document["rotation"]["sentence"])

    def test_active_persistence_is_unsafe_and_shown_critical(self):
        live = _issue("os-service-persistence", "warning", "A service is installed", "It starts.",
                      "Remove it.")
        document = hygiene.as_document([
            CheckOutcome("OS-service persistence", FOUND, (live,))])
        self.assertEqual(document["rotation"]["verdict"], "unsafe")
        self.assertEqual(document["findings"][0]["severity"], "critical")
        self.assertEqual(document["findings"][0]["confidence"], "confirmed")


class TestTheCommandPrintsIt(unittest.TestCase):
    def _run(self, argv, outcomes):
        with mock.patch("stayawake.cli.commands.audit.hygiene.audit_checks",
                        return_value=[("cached credentials", lambda: [])]), \
             mock.patch("stayawake.cli.commands.audit.hygiene.run_check",
                        side_effect=outcomes), \
             mock.patch("stayawake.bots.security.hygiene.document.live_process_scope_note",
                        return_value=""), \
             redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_stdout_is_the_document_and_the_exit_follows_the_report(self):
        live = _issue("os-service-persistence", "warning", "A service", "Detail.", "Fix.")
        code, stdout = self._run(
            ["audit", "--json", "--no-stream"],
            [CheckOutcome("OS-service persistence", FOUND, (live,))])
        printed = json.loads(stdout)
        self.assertEqual(code, exitcodes.ROTATION_UNSAFE)
        self.assertEqual(list(printed), ["schema_version", "rotation", "findings", "incomplete",
                                         "scope_notes"])
        self.assertEqual(printed["schema_version"], 1)
        self.assertEqual(printed["rotation"]["verdict"], "unsafe")
        self.assertEqual(printed["findings"][0]["id"], "os-service-persistence")

    def test_a_warning_the_operator_asked_to_gate_does_not_change_the_verdict(self):
        editor = _issue("editor-autotasks-on", "warning", "An editor", "Detail.", "Fix.")
        code, stdout = self._run(
            ["audit", "--json", "--fail", "--no-stream"],
            [CheckOutcome("editor settings", FOUND, (editor,))])
        self.assertEqual(code, exitcodes.FINDINGS)
        self.assertEqual(json.loads(stdout)["rotation"]["verdict"], "safe")


if __name__ == "__main__":
    unittest.main()

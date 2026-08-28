#!/usr/bin/env python3
"""Code handed to a running interpreter never touches the disk, so every check that reads files is
looking in the wrong place. The kernel's argv is the only copy."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.hygiene import audit_checks, process
from stayawake.bots.security.hygiene.models import ROTATION_UNSAFE_IDS
from stayawake.bots.security.obfuscation.entry import analyze_file
from stayawake.utils.procsnap import Process, Snapshot


def _loader() -> str:
    """A dynamic-exec sink, assembled from split tokens so this file carries no contiguous
    indicator for the self-scan to flag (the convention in test_verify.py)."""
    charcode = "from" + "CharCode"
    run = "ev" + "al"
    return f"{run}(String.{charcode}(118,97,114,32,120))"


def _snapshot(*processes: Process, unreadable: int = 0, supported: bool = True) -> Snapshot:
    return Snapshot(processes=list(processes), unreadable=unreadable, supported=supported)


def _check(snapshot: Snapshot):
    with mock.patch.object(process, "_snapshot", return_value=snapshot):
        return process.check_live_processes()


class TestTheInstrumentWorks(unittest.TestCase):
    def test_a_known_loader_in_argv_is_found(self):
        # The control. Without it, "found nothing" and "the check is broken" are the same result.
        issues = _check(_snapshot(Process(pid=42, argv=("node", "-e", _loader()))))
        self.assertEqual([i.id for i in issues], ["live-obfuscated-process"])
        self.assertIn("42", issues[0].detail)

    def test_it_gates_credential_rotation(self):
        self.assertIn("live-obfuscated-process", ROTATION_UNSAFE_IDS)

    def test_the_probe_is_part_of_an_audit(self):
        self.assertIn("running processes", [label for label, _c in audit_checks()])


class TestItGradesTheCodeAndNotTheCommandLine(unittest.TestCase):
    def test_an_ordinary_process_says_nothing(self):
        self.assertEqual(_check(_snapshot(
            Process(pid=1, argv=("/usr/bin/node", "/opt/app/server.js", "--port", "8080")),
            Process(pid=2, argv=("/bin/zsh", "-l")))), [])

    def test_a_long_ordinary_command_line_is_not_a_finding(self):
        # The hazard a bare entropy rule would hit: editors and language servers carry enormous
        # argv. None of it is code the interpreter was told to run.
        argv = ("node", "/Applications/Some.app/out/server.js") + tuple(
            f"--flag-{n}=/very/long/path/segment/{n}" for n in range(40))
        self.assertEqual(_check(_snapshot(Process(pid=3, argv=argv))), [])

    def test_a_payload_quoted_as_a_search_pattern_is_not_running_code(self):
        # `grep '<pattern>' file` carries the indicator in argv and executes none of it. Grading the
        # whole command line instead of the argument the interpreter was handed reports the analyst.
        self.assertEqual(_check(_snapshot(
            Process(pid=10, argv=("grep", "-rn", _loader(), "src/")))), [])

    def test_a_dense_argument_is_not_obfuscation_on_its_own(self):
        # An argv is one long dense line by construction, so the whole-file density tier fires on
        # ordinary ones. Only the self-evident constructs are decisive here.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        dense = (alphabet * 50)[:3000]
        self.assertTrue(analyze_file(dense).obfuscated,
                        "fixture no longer reaches the tier this test exists to exclude")
        self.assertFalse(analyze_file(dense, constructs_only=True).obfuscated)
        self.assertEqual(_check(_snapshot(Process(pid=11, argv=("sh", "-c", dense)))), [])

    def test_the_code_argument_comes_from_the_shared_authority(self):
        # Re-deriving which argument is code is how two consumers end up disagreeing; this pins that
        # the probe asks the same resolver the start-up checks ask.
        with mock.patch.object(process, "resolve_invocation",
                               wraps=process.resolve_invocation) as resolver:
            _check(_snapshot(Process(pid=4, argv=("sh", "-c", "echo hi"))))
        resolver.assert_called_once_with(("sh", "-c", "echo hi"))

    def test_one_process_yields_one_finding(self):
        payload = _loader()
        issues = _check(_snapshot(Process(pid=5, argv=("sh", "-c", payload, "-c", payload))))
        self.assertEqual(len(issues), 1)


class TestItNeverReadsRefusalAsClean(unittest.TestCase):
    def test_a_process_it_could_not_read_is_never_graded(self):
        # Refused and "runs no arguments" are the same empty list to a caller that only checks
        # truthiness. The refusal is asked about first, so a grade is never formed from a non-answer.
        refused = Process(pid=6, argv=("sh", "-c", _loader()), argv_unreadable=True)
        with mock.patch.object(process, "resolve_invocation") as resolver:
            self.assertEqual(_check(_snapshot(refused)), [])
        resolver.assert_not_called()

    def test_the_refusals_are_disclosed(self):
        note = _snapshot(Process(pid=6, argv_unreadable=True), unreadable=1).scope_note()
        self.assertIn("did not yield their arguments", note)

    def test_a_platform_that_cannot_be_read_says_so(self):
        with mock.patch.object(process, "_snapshot",
                               return_value=_snapshot(supported=False)):
            note = process.live_process_scope_note()
        self.assertIn("cannot be read", note)
        self.assertIn("no start-up command was examined", note)

    def test_a_full_reading_discloses_nothing(self):
        with mock.patch.object(process, "_snapshot",
                               return_value=_snapshot(Process(pid=7, argv=("sh", "-l")))):
            self.assertEqual(process.live_process_scope_note(), "")


class TestTheCapturedArgumentIsBounded(unittest.TestCase):
    def test_a_short_argument_is_carried_whole(self):
        payload = _loader()
        issues = _check(_snapshot(Process(pid=8, argv=("node", "-e", payload))))
        self.assertIn(payload, issues[0].detail)

    def test_a_long_one_is_cut_and_says_so(self):
        payload = _loader() + ";" + "x" * 4000
        detail = _check(_snapshot(Process(pid=9, argv=("node", "-e", payload))))[0].detail
        self.assertLess(len(detail), 500)
        self.assertIn("[…]", detail)


if __name__ == "__main__":
    unittest.main()


class TestAnAuditOnlyReports(unittest.TestCase):
    """`saw audit` audits and reports. Reading a process is not a licence to act on one, and a
    finding here names a live process — which is exactly where that line is easiest to cross."""

    _ACTS_ON_A_PROCESS = ("os.kill", "signal.", "SIGKILL", "SIGTERM", "SIGSTOP",
                          ".terminate(", ".kill(", "psutil")

    def _sources(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[3] / "src/stayawake"
        return [(p, p.read_text(encoding="utf-8"))
                for p in [*(root / "bots/security/hygiene").rglob("*.py"),
                          root / "utils/procsnap.py"]]

    def test_nothing_in_the_audit_path_can_signal_a_process(self):
        for path, text in self._sources():
            body = "\n".join(line for line in text.splitlines()
                             if not line.lstrip().startswith("#"))
            for token in self._ACTS_ON_A_PROCESS:
                with self.subTest(module=path.name, token=token):
                    self.assertNotIn(token, body, f"{path.name} can act on a process")

    def test_the_finding_does_not_promise_the_tool_will_act(self):
        issue = _check(_snapshot(Process(pid=12, argv=("node", "-e", _loader()))))[0]
        said = f"{issue.title} {issue.detail} {issue.remediation}".lower()
        for claim in ("we killed", "stopped it", "terminated", "has been ended"):
            self.assertNotIn(claim, said)


class TestAPlatformItCannotReadIsNotClean(unittest.TestCase):
    """The probe is also registered as unimplemented off POSIX, but that registry answers a
    different question from the one this probe depends on — whether the kernel will hand over
    arguments. They agree on the platforms we run and diverge elsewhere, so the probe asks its own
    reader rather than trusting the registry to have been right about a platform nobody tested."""

    def test_it_says_so_rather_than_finding_nothing(self):
        issues = _check(_snapshot(Process(pid=13, argv=("node", "-e", _loader())), supported=False))
        self.assertEqual([i.id for i in issues], ["process-arguments-not-readable"])

    def test_that_withholds_the_rotation_all_clear(self):
        self.assertIn("process-arguments-not-readable", ROTATION_UNSAFE_IDS)

    def test_the_registry_still_covers_the_platform_it_knows(self):
        from stayawake.bots.security import hygiene
        self.assertIn("running processes", hygiene._POSIX_ONLY_PROBES)

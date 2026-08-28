#!/usr/bin/env python3
"""#238 — a probe that returns nothing is saying one of two very different things: *I looked and
there was nothing*, or *I could not look*. Collapsed into an empty list they are the same answer,
and the run reports the surface as enumerated and clean over probes that never ran.

Every probe now ends in a STATE, and one that could not answer can never leave the run at exit 0."""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest import mock

from stayawake.bots.security import hygiene
from stayawake.bots.security.hygiene import credentials, mechanism, runner
from stayawake.bots.security.hygiene.models import (BLOCKED_ID, BLOCKED_SURFACE_ID,
                                                    ROTATION_UNSAFE_IDS)
from stayawake.bots.security.hygiene.outcome import (BLOCKED, CHECKED_CLEAN, FOUND, UNKNOWN,
                                                     run_probe)


def _issue(id_: str = "x", severity: str = "warning"):
    return hygiene.HygieneIssue(id=id_, severity=severity, title="t", detail="d", remediation="r")


class TestAProbeEndsInAState(unittest.TestCase):
    def test_finding_nothing_is_checked_clean_not_merely_empty(self):
        outcome = run_probe("p", lambda: [])
        self.assertEqual(outcome.state, CHECKED_CLEAN)
        self.assertEqual(outcome.issues, ())

    def test_finding_something_is_found(self):
        self.assertEqual(run_probe("p", lambda: [_issue()]).state, FOUND)

    def test_reporting_that_it_could_not_establish_something_is_unknown(self):
        self.assertEqual(run_probe("p", lambda: [_issue(severity="unknown")]).state, UNKNOWN)


class TestABlockedProbeKeepsWhatItLearned(unittest.TestCase):
    """A probe reads several things and usually only one of them goes blind. Dropping its findings
    to report the hole would trade one dishonest answer for another."""

    def test_the_state_is_blocked_and_the_reason_is_carried(self):
        outcome = run_probe("p", lambda: [], predicate=lambda: "the field order differs.")
        self.assertEqual(outcome.state, BLOCKED)
        self.assertEqual(outcome.reason, "the field order differs.")
        self.assertFalse(outcome.established)

    def test_a_blocked_probe_says_the_surface_was_not_covered(self):
        outcome = run_probe("p", lambda: [], predicate=lambda: "the field order differs.")
        self.assertIn("the field order differs.", outcome.issues[0].detail)
        self.assertIn("did not cover", outcome.issues[0].detail)
        self.assertEqual(outcome.issues[0].severity, "unknown")

    def test_it_reads_as_a_condition_of_this_host_not_a_fault_in_the_tool(self):
        # An operator reading a security report should not be told the tool may have failed its own
        # checks. What happened is that this machine did not let a check finish.
        outcome = run_probe("shell startup files", lambda: [], predicate=lambda: "x.")
        rendered = " ".join([outcome.issues[0].title, outcome.issues[0].detail,
                             outcome.issues[0].remediation]).lower()
        for internal in ("self-test", "meaningless", "discriminator", "predicate"):
            self.assertNotIn(internal, rendered, f"{internal!r} reached the operator")

    def test_what_it_did_establish_survives_the_block(self):
        outcome = run_probe("p", lambda: [_issue("real-finding")],
                            predicate=lambda: "one half went blind.")
        self.assertEqual([i.id for i in outcome.issues], ["real-finding", BLOCKED_ID])

    def test_a_self_test_that_itself_fails_is_a_block_not_a_crash(self):
        def explodes():
            raise RuntimeError("boom")
        outcome = run_probe("p", lambda: [], predicate=explodes)
        self.assertEqual(outcome.state, BLOCKED)
        self.assertIn("RuntimeError", outcome.reason)


class TestOneBrokenProbeDoesNotTakeTheOthersWithIt(unittest.TestCase):
    def test_a_probe_that_raises_is_blocked_and_named(self):
        def explodes():
            raise OSError("no such tool")
        outcome = run_probe("shell startup files", explodes)
        self.assertEqual(outcome.state, BLOCKED)
        self.assertIn("OSError", outcome.reason)
        self.assertIn("shell startup files", outcome.issues[0].title)

    def test_the_rest_of_the_audit_still_runs(self):
        def explodes():
            raise ValueError("x")
        with mock.patch.object(hygiene, "audit_checks",
                               return_value=[("a", explodes), ("b", lambda: [_issue("later")])]):
            ids = [i.id for i in hygiene.audit()]
        self.assertIn("later", ids, "a broken probe swallowed the probes after it")

    def test_an_operator_interrupt_is_not_reported_as_a_defect(self):
        def interrupted():
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            run_probe("p", interrupted)


class TestABlockedProbeNeverLeavesTheRunAtZero(unittest.TestCase):
    def _rc(self, probes):
        buf = io.StringIO()
        with mock.patch("stayawake.bots.security.hygiene.audit_checks", return_value=probes), \
             mock.patch("stayawake.lib.auth.resolve_token", return_value=(None, None)), \
             redirect_stdout(buf):
            from stayawake import cli
            return cli.main(["audit", "--no-stream"]), buf.getvalue()

    def test_a_clean_run_is_still_zero(self):
        rc, _ = self._rc([("probe", lambda: [])])
        self.assertEqual(rc, 0)

    def test_a_blocked_probe_is_a_run_that_could_not_complete(self):
        # "cached credentials" is classified as certifying no start-up surface, so the gap is in
        # what the run covered rather than a hazard in what it found — 2, not 3, and never 0.
        def explodes():
            raise OSError("tool missing")
        rc, out = self._rc([("cached credentials", explodes)])
        self.assertEqual(rc, 2, "a probe that never answered left the run reporting success")
        self.assertIn("Not checked", out)

    def test_a_blocked_start_up_surface_probe_withholds_the_rotation_all_clear(self):
        # Stronger than a coverage gap: the surface was not established, which is what 3 means.
        self.assertIn(BLOCKED_SURFACE_ID, ROTATION_UNSAFE_IDS)

        def explodes():
            raise OSError("launchctl missing")
        rc, out = self._rc([("self-hosted runner", explodes)])
        self.assertEqual(rc, 3)
        self.assertNotIn("persistence surface enumerated and clean", out)

    def test_a_blocked_probe_that_certifies_nothing_does_not_claim_rotation_is_unsafe(self):
        def explodes():
            raise OSError("security missing")
        rc, _ = self._rc([("cached credentials", explodes)])
        self.assertEqual(rc, 2, "a credential-store gap was reported as a rotation hazard")


class TestTheSelfTestRegistryCannotDrift(unittest.TestCase):
    def test_every_registered_predicate_names_a_probe_that_exists(self):
        labels = {label for label, _check in hygiene.audit_checks()}
        self.assertLessEqual(set(hygiene._PREDICATES), labels,
                             "a self-test names a probe the audit does not run")

    def test_both_entry_points_apply_it_through_one_function(self):
        # The streaming CLI and the all-at-once path used to hand-assemble their own loops, which is
        # how a probe once got silently dropped from one of them.
        seen = []
        with mock.patch.object(hygiene, "run_check",
                               side_effect=lambda label, check: seen.append(label) or
                               hygiene.CheckOutcome(label, CHECKED_CLEAN)):
            hygiene.audit()
        self.assertEqual(seen, [label for label, _c in hygiene.audit_checks()])


class TestTheRunnerDiscriminatorReadsWhatTheCheckReads(unittest.TestCase):
    """The bug this exists for: a tool's field order changes, the parse stops separating anything,
    and the probe reports what a clean host reports. An earlier version of this self-test
    re-implemented the parse with a weaker test — "contains a dot" — so it passed over a live
    registration while the extractor read a column of file paths."""

    def _launchctl(self, stdout, rc=0):
        def fake(cmd, **_kw):
            if cmd[0] == "launchctl":
                return subprocess.CompletedProcess(cmd, rc, stdout, "")
            raise FileNotFoundError(cmd[0])
        return mock.patch.object(runner.subprocess, "run", side_effect=fake)

    _NORMAL = ("PID\tStatus\tLabel\n"
               "-\t0\tcom.apple.some.agent\n94559\t-9\tcom.apple.progressd\n")
    # The refuted case: one extra trailing column. The label is still present and still registered;
    # the column the extractor reads now holds a program path.
    _REORDERED = ("PID\tStatus\tLabel\tProgram\n"
                  "-\t0\tactions.runner.acme.buildbox\t/usr/local/bin/runsvc.sh\n"
                  "-\t0\tcom.apple.x\t/usr/libexec/x\n")

    def test_labels_in_the_expected_column_pass(self):
        with self._launchctl(self._NORMAL):
            self.assertIsNone(runner.services_predicate())

    def test_a_grown_column_is_reported_even_though_a_dot_still_appears(self):
        with self._launchctl(self._REORDERED):
            reason = runner.services_predicate()
        self.assertIsNotNone(reason, "the column moved and the discriminator called it healthy")
        self.assertIn("not in a form this check can read", reason)

    def test_that_is_exactly_the_case_the_extractor_misses(self):
        # The pairing is the point: the self-test has to fire precisely where the check goes blind.
        with self._launchctl(self._REORDERED):
            self.assertEqual(runner._runner_services(), [], "fixture no longer models the miss")
            self.assertIsNotNone(runner.services_predicate())

    def test_the_two_read_the_same_column(self):
        # Re-deriving the field index in the self-test is how the two drift apart; both call this.
        self.assertEqual(runner._launchctl_fields(self._NORMAL),
                         ["com.apple.some.agent", "com.apple.progressd"])

    def test_a_column_of_version_strings_is_not_a_column_of_labels(self):
        # The rule was "dotted and not a path", which a version satisfies. A grown listing whose
        # new last column is a version scored every row label-shaped, so the self-test certified a
        # parse that had stopped seeing a live `actions.runner.*` registration.
        rows = "".join(f"-\t0\tcom.apple.a{i}\t1.{i}.0\n" for i in range(6))
        versions = ("PID\tStatus\tLabel\tVersion\n"
                    "-\t0\tactions.runner.acme.buildbox\t2.317.0\n" + rows)
        with self._launchctl(versions):
            self.assertEqual(runner._runner_services(), [], "fixture no longer models the miss")
            reason = runner.services_predicate()
        self.assertIsNotNone(reason, "a column of versions passed as a column of service names")

    def test_one_label_shaped_row_among_many_is_not_enough(self):
        # `any()` was the first rule and it is satisfied by a single dotted token anywhere in a
        # listing of file paths — which is what a grown column looks like most of the time.
        rows = "".join(f"-\t0\tcom.apple.a{i}\t/usr/libexec/a{i}\n" for i in range(4))
        mostly_paths = "PID\tStatus\tLabel\tProgram\n" + rows + "-\t0\tcom.apple.b\tlogin.keychain\n"
        with self._launchctl(mostly_paths):
            reason = runner.services_predicate()
        self.assertIsNotNone(reason, "one label-shaped row in five passed the whole listing")

    def test_a_manager_that_lists_nothing_is_reported(self):
        with self._launchctl("PID\tStatus\tLabel\n"):
            self.assertIn("nothing to read", runner.services_predicate())

    def test_a_byte_the_locale_cannot_decode_does_not_end_the_listing(self):
        # A real subprocess, not a mock: mocking `subprocess.run` skips the decode, which is where
        # this fails. Without errors="replace" the read raises and the whole probe reads as blocked.
        out = runner._run_tool(["/bin/sh", "-c", "printf 'PID\\tStatus\\tLabel\\n-\\t0\\tcom.a\\200b\\n'"])
        self.assertIsNotNone(out, "an undecodable byte was read as a tool that did not answer")
        self.assertEqual(len(runner._launchctl_fields(out)), 1)

    def test_every_listing_the_check_reads_is_self_tested(self):
        # An earlier self-test probed one of the four `systemctl` invocations the check depends on,
        # so a broken column in any of the other three went untested.
        names = [name for name, _cmd, _fields in runner._service_listings()]
        self.assertEqual(names, ["launchctl",
                                 "systemctl system list-units", "systemctl system list-unit-files",
                                 "systemctl user list-units", "systemctl user list-unit-files"])

    def test_a_broken_column_in_the_user_scope_is_caught(self):
        broken = "/usr/lib/systemd/x.sh loaded active running x\n" * 4

        def fake(cmd, **_kw):
            if cmd[0] == "launchctl":
                raise FileNotFoundError("launchctl")
            if "--user" in cmd:
                return subprocess.CompletedProcess(cmd, 0, broken, "")
            return subprocess.CompletedProcess(cmd, 0, "sshd.service loaded active running x\n", "")
        with mock.patch.object(runner.subprocess, "run", side_effect=fake):
            reason = runner.services_predicate()
        self.assertIsNotNone(reason, "the user scope was never checked")
        self.assertIn("user", reason)

    def test_one_idle_listing_among_several_is_not_a_block(self):
        # An idle user manager legitimately lists no services; only every answering listing coming
        # back empty means there was nothing to read.
        def fake(cmd, **_kw):
            if cmd[0] == "launchctl":
                raise FileNotFoundError("launchctl")
            if "--user" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "sshd.service loaded active running x\n", "")
        with mock.patch.object(runner.subprocess, "run", side_effect=fake):
            self.assertIsNone(runner.services_predicate())

    def test_a_host_with_no_service_manager_is_not_blocked(self):
        # A service-registered runner cannot exist where no service manager does, and the
        # install-directory half of the check ran regardless.
        def missing(cmd, **_kw):
            raise FileNotFoundError(cmd[0])
        with mock.patch.object(runner.subprocess, "run", side_effect=missing):
            self.assertIsNone(runner.services_predicate())

    def test_a_program_path_is_not_mistaken_for_a_label(self):
        self.assertFalse(runner._label_shaped("/Users/x/actions-runner/runsvc.sh"))
        self.assertTrue(runner._label_shaped("actions.runner.acme.buildbox"))


class TestTheKeychainDiscriminatorUsesAKnownAnswer(unittest.TestCase):
    def _security(self, rc):
        return mock.patch.object(credentials, "_run",
                                 return_value=subprocess.CompletedProcess(["security"], rc, "", ""))

    def test_a_host_that_cannot_exist_must_come_back_absent(self):
        with mock.patch("sys.platform", "darwin"), self._security(44):
            self.assertIsNone(credentials.keychain_predicate())

    def test_a_tool_that_matches_anything_is_reported(self):
        with mock.patch("sys.platform", "darwin"), self._security(0):
            reason = credentials.keychain_predicate()
        self.assertIsNotNone(reason, "a tool answering yes to an impossible query passed its test")
        self.assertIn("did not answer as expected", reason)

    def test_a_tool_that_does_not_run_is_reported(self):
        with mock.patch("sys.platform", "darwin"), \
             mock.patch.object(credentials, "_run", return_value=None):
            self.assertIn("did not run", credentials.keychain_predicate())

    def test_it_says_nothing_off_the_platform_that_has_that_tool(self):
        with mock.patch("sys.platform", "linux"):
            self.assertIsNone(credentials.keychain_predicate())


class TestTheGitDiscriminatorAsksAboutTheFileNotTheTool(unittest.TestCase):
    """The discriminator is whether a global config EXISTS, not whether git answers. An earlier
    version asked git, and stock git exits 128 with a message on stderr when there is no global
    config at all — so a fresh account, container or CI image was reported "rotation UNSAFE"."""

    def _home(self):
        home = tempfile.mkdtemp()
        return mock.patch.dict(os.environ, {"HOME": home, "XDG_CONFIG_HOME": home + "/xdg"},
                               clear=False), home

    def test_a_fresh_account_with_no_global_config_is_clean(self):
        patch, _home = self._home()
        with patch, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
            self.assertIsNone(mechanism.git_config_predicate())

    def test_a_config_that_exists_and_lists_is_clean(self):
        patch, home = self._home()
        Path(home, ".gitconfig").write_text("[user]\n\tname = x\n", encoding="utf-8")
        with patch, mock.patch.object(
                mechanism.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, "", "")):
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
            self.assertIsNone(mechanism.git_config_predicate())

    def test_a_config_that_exists_and_git_cannot_be_run_is_reported(self):
        # Reachable whenever `saw` runs with a reduced PATH — launchd, cron, a GUI-spawned process
        # — while the user's git and its configuration are both live.
        patch, home = self._home()
        Path(home, ".gitconfig").write_text("[core]\n\tfsmonitor = x\n", encoding="utf-8")

        def missing(cmd, **_kw):
            raise FileNotFoundError("git")
        with patch, mock.patch.object(mechanism.subprocess, "run", side_effect=missing):
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
            reason = mechanism.git_config_predicate()
        self.assertIsNotNone(reason, "a live config nobody read was graded clean")
        self.assertIn("could not be run", reason)

    def test_a_config_that_exists_and_git_refuses_to_list_is_reported(self):
        patch, home = self._home()
        Path(home, ".gitconfig").write_text("[core]\n\tfsmonitor = x\n", encoding="utf-8")
        with patch, mock.patch.object(
                mechanism.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 128, "", "fatal: bad config")):
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
            self.assertIn("would not list it", mechanism.git_config_predicate())

    def test_a_configuration_inside_an_unreadable_directory_still_counts_as_existing(self):
        # `Path.is_file()` answers False for a path it may not stat on this interpreter, so an
        # unreadable `~/.config/git` holding a live exec-on-every-command entry — one git itself
        # refuses to read — came back as "no configuration at all", and the run certified clean.
        patch, home = self._home()
        cfg_dir = Path(home, "xdg", "git")
        cfg_dir.mkdir(parents=True)
        (cfg_dir / "config").write_text("[core]\n\tfsmonitor = x\n", encoding="utf-8")
        os.chmod(cfg_dir, 0o000)
        try:
            with patch:
                os.environ.pop("GIT_CONFIG_GLOBAL", None)
                self.assertTrue(mechanism._has_global_git_config(),
                                "a configuration nobody may stat was read as no configuration")
                self.assertIsNotNone(mechanism.git_config_predicate())
        finally:
            os.chmod(cfg_dir, 0o755)

    def test_a_configuration_the_check_can_read_does_not_block_the_self_test(self):
        # A self-test that decodes more strictly than the check it guards blocks a host the check
        # reads without trouble.
        patch, home = self._home()
        Path(home, ".gitconfig").write_bytes("[user]\n\tname = Jos\xe9 Nu\xf1ez\n".encode("latin-1"))
        with patch:
            os.environ.pop("GIT_CONFIG_GLOBAL", None)
            self.assertIsNone(mechanism.git_config_predicate(),
                              "the self-test refused a file the check reads without trouble")
            self.assertEqual(mechanism.check_git_config_execution(), [])

    def test_the_override_variable_is_the_one_git_itself_uses(self):
        patch, home = self._home()
        elsewhere = Path(home, "custom-gitconfig")
        elsewhere.write_text("[user]\n", encoding="utf-8")
        with patch, mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(elsewhere)}):
            self.assertEqual(mechanism._global_git_config_paths(), [elsewhere])


class TestEverySurfaceProbeReachesTheRotationVerdict(unittest.TestCase):
    """Tying the surface flag to the self-test registry let four probes that read the start-up
    surface block while the report kept printing "persistence surface enumerated and clean"."""

    def test_a_probe_with_no_self_test_still_gates_when_it_goes_quiet(self):
        def explodes():
            raise OSError("x")
        for label in ("persistence surface coverage", "autorun surface", "OS-service persistence",
                      "shell startup files", "SSH authorized_keys", "VS Code settings",
                      "host drop-files"):
            with self.subTest(probe=label):
                ids = {i.id for i in hygiene.run_check(label, explodes).issues}
                self.assertTrue(ids & ROTATION_UNSAFE_IDS,
                                f"{label} went quiet and the all-clear was still printed")

    def test_a_probe_that_certifies_nothing_does_not_gate(self):
        def explodes():
            raise OSError("x")
        ids = {i.id for i in hygiene.run_check("cached credentials", explodes).issues}
        self.assertFalse(ids & ROTATION_UNSAFE_IDS)

    def test_every_registered_probe_is_classified_one_way_or_the_other(self):
        # Both directions, and no allowlist. Classifying only the surface probes let `host
        # drop-files` — whose findings drive the rotation verdict — default to "certifies nothing",
        # so the report kept printing "read the host persistence surface and known drop-paths" in
        # the run where the drop-path probe had died.
        labels = {label for label, _c in hygiene.audit_checks()}
        classified = set(hygiene._SURFACE_PROBES) | set(hygiene._NON_SURFACE_PROBES)
        self.assertEqual(labels - classified, set(), "a probe is classified nowhere")
        self.assertEqual(classified - labels, set(), "a classification names no registered probe")
        self.assertEqual(hygiene._SURFACE_PROBES & hygiene._NON_SURFACE_PROBES, frozenset())

    def test_a_probe_nobody_classified_defaults_to_gating(self):
        # The safe default: an unclassified probe going quiet withholds the all-clear rather than
        # being silently trusted, which is the direction this whole change exists to fix.
        def explodes():
            raise OSError("x")
        ids = {i.id for i in hygiene.run_check("a probe added later", explodes).issues}
        self.assertTrue(ids & ROTATION_UNSAFE_IDS)


class TestTheDestroyedHomeHeadlineOutranksABlockedCheck(unittest.TestCase):
    def test_it_leads_and_the_block_is_still_mentioned(self):
        report = hygiene.render([_issue("persistence-surface-not-established", "unknown"),
                                 _issue(BLOCKED_ID, "unknown")], color=False, width=90)
        head = report.splitlines()[0]
        self.assertIn("nothing was there to examine", head)
        self.assertIn("did not run", head)


if __name__ == "__main__":
    unittest.main()

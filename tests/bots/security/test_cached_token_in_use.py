#!/usr/bin/env python3
"""Whether git uses a cached github.com token, and what the audit says when it cannot tell."""
import contextlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security.hygiene import credentials as C
from stayawake.bots.security.hygiene.models import INCIDENT_TRIGGER_IDS, ROTATION_UNSAFE_IDS


class GitReadsTheCachedToken(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.config = self.home / ".gitconfig"
        self.config.write_text("")
        self.shims = self.home / "bin"
        self.shims.mkdir()
        self.ran = self.home / "ran"
        env = mock.patch.dict(os.environ, {
            "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / "xdg"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(self.config),
            "GIT_ASKPASS": str(self._shim("askpass")), "SSH_ASKPASS": str(self._shim("ssh-askpass")),
            "PATH": f"{self.shims}{os.pathsep}{os.environ.get('PATH', '')}"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("GIT_CONFIG", None)
        for name in [n for n in os.environ if n.startswith(("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_",
                                                            "GIT_CONFIG_VALUE_", "GIT_CONFIG_PARAMETERS"))]:
            os.environ.pop(name)
        self.repositories: list[Path] = []
        seeded = mock.patch.object(C.hookscript, "seeded_repositories", return_value=self.repositories)
        seeded.start()
        self.addCleanup(seeded.stop)

    def _shim(self, name: str) -> Path:
        """A program on PATH that records that it ran. Takes its file name. Returns its path."""
        path = self.shims / name
        path.write_text(f"#!/bin/sh\necho {name} >> '{self.ran}'\necho password=secret\n")
        path.chmod(0o755)
        return path

    def _answer(self, config: str, store=C._MACOS_STORE):
        self.config.write_text(config)
        return C._https_token_status(store)

    def test_a_helper_that_reads_the_store_means_in_use(self):
        self.assertIs(self._answer("[credential]\n\thelper = osxkeychain\n"), True)

    def test_a_helper_named_by_its_path_reads_the_store(self):
        self.assertIs(self._answer("[credential]\n\thelper = /usr/local/bin/git-credential-osxkeychain\n"),
                      True)
        windows = "[credential]\n\thelper = C:/Program\\\\ Files/Git/mingw64/bin/git-credential-manager.exe\n"
        self.assertIs(self._answer(windows, C._WINDOWS_STORE), True)

    def test_a_helper_for_github_alone_that_reads_the_store_means_in_use(self):
        self.assertIs(self._answer('[credential "https://github.com"]\n\thelper = osxkeychain\n'), True)

    def test_a_helper_for_every_host_reads_the_store(self):
        self.assertIs(self._answer('[credential ""]\n\thelper = osxkeychain\n'), True)

    def test_a_helper_git_applies_to_github_reads_the_store(self):
        for scope in ("https://*.com", "https://user@github.com:443/org", "github.com", "https://GitHub.com",
                      "https://github.com.", "https://*.com./", "https://github%2ecom"):
            with self.subTest(scope=scope):
                self.assertIs(self._answer(f'[credential "{scope}"]\n\thelper = osxkeychain\n'), True)

    def test_a_helper_for_another_host_leaves_the_token_unused(self):
        self.assertIs(self._answer('[credential "https://gitlab.com"]\n\thelper = osxkeychain\n'), False)
        self.assertIs(self._answer('[credential "https://*.github.com"]\n\thelper = osxkeychain\n'), False)
        self.assertIs(self._answer('[credential "https://github.com.example"]\n\thelper = osxkeychain\n'), False)

    def test_each_linux_helper_reads_the_linux_store(self):
        self.assertIs(self._answer("[credential]\n\thelper = gnome-keyring\n", C._LINUX_STORE), True)

    def test_the_config_is_read_as_git_reads_it(self):
        other = self.home / "other"
        other.write_text("")
        with mock.patch.dict(os.environ, {"GIT_CONFIG": str(other)}):
            self.assertIs(self._answer("[credential]\n\thelper = osxkeychain\n"), True)

    def test_no_helper_means_unused(self):
        self.assertIs(self._answer(""), False)

    def test_the_removal_steps_own_reset_means_unused(self):
        self.assertIs(self._answer("[credential]\n\thelper = osxkeychain\n\thelper =\n"), False)

    def test_helpers_that_read_elsewhere_mean_unused(self):
        self.assertIs(self._answer("[credential]\n\thelper = store\n\thelper = cache --timeout=60\n"),
                      False)

    def test_a_helper_of_unknown_reach_is_never_called_unused(self):
        for helper in ('"!f() { echo; }; f"', "manager", "/opt/bin/git-credential-custom"):
            with self.subTest(helper=helper):
                self.assertIsNone(self._answer(f"[credential]\n\thelper = {helper}\n"))
        self.assertIsNone(self._answer('[credential "https://github.com"]\n\thelper = !gh auth git-credential\n'))

    def test_a_conditional_include_is_never_called_unused(self):
        self.assertIsNone(self._answer('[includeIf "gitdir:~/work/"]\n\tpath = ~/.gitconfig-work\n'))

    def test_a_config_git_cannot_read_is_never_called_unused(self):
        self.assertIsNone(self._answer("[credential\n\thelper = store\n"))
        self.assertIsNone(self._answer("[credential]\n\thelper\n"))

    def test_git_that_does_not_run_is_never_called_unused(self):
        with mock.patch.object(C, "git_run", return_value=None):
            self.assertIsNone(self._answer(""))

    def test_the_check_runs_no_program_git_config_names(self):
        helper = self._shim("git-credential-osxkeychain")
        self._shim("git-credential-tattle")
        self.assertIs(self._answer(f"[credential]\n\thelper = {helper}\n"), True)
        self.assertIsNone(self._answer("[credential]\n\thelper = tattle\n"))
        self.assertIs(self._answer(""), False)
        self.assertFalse(self.ran.exists(), self.ran.read_text() if self.ran.exists() else "")

    def test_gh_as_gits_helper_is_named(self):
        self._shim("gh")
        hosts = self.home / "xdg" / "gh" / "hosts.yml"
        hosts.parent.mkdir(parents=True)
        hosts.write_text("github.com:\n    oauth_token: secret\n")
        self.config.write_text("")
        self.assertFalse(C._gh_configured())
        self.config.write_text('[credential "https://github.com"]\n\thelper =\n'
                               '\thelper = !/opt/homebrew/bin/gh auth git-credential\n')
        self.assertTrue(C._gh_configured())
        self.config.write_text('[credential "https://gitlab.com"]\n\thelper = !gh auth git-credential\n')
        self.assertFalse(C._gh_configured())
        self.assertFalse(self.ran.exists())

    def test_a_token_git_reads_is_never_offered_a_delete(self):
        self.config.write_text("[credential]\n\thelper = osxkeychain\n")
        with mock.patch.object(C, "_gh_configured", return_value=True):
            finding = C._keychain_finding(C._MACOS_STORE)
        self.assertIn("IN USE", finding.detail)
        self.assertIsNone(finding.command)

    def test_a_helper_of_unknown_reach_reads_as_could_not_tell(self):
        self.config.write_text("[credential]\n\thelper = \"!f() { echo; }; f\"\n")
        with mock.patch.object(C, "_gh_configured", return_value=False):
            finding = C._keychain_finding(C._MACOS_STORE)
        self.assertIn("Could not tell", finding.detail)
        self.assertNotIn("looks unused", finding.detail)
        self.assertIn("GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= GCM_INTERACTIVE=never git credential fill",
                      finding.command)

    def _repository(self, config: str) -> Path:
        """A repository saw's hooks have seen, whose own config is `config`. Returns its root."""
        root = self.home / f"repo{len(self.repositories)}"
        (root / ".git").mkdir(parents=True)
        (root / ".git" / "config").write_text(config)
        self.repositories.append(root)
        return root

    def test_a_helper_one_repository_sets_reads_the_store(self):
        self._repository("[credential]\n\thelper = osxkeychain\n")
        self.assertIs(self._answer(""), True)

    def test_a_repository_that_clears_its_helpers_leaves_the_token_unused(self):
        self._repository("[credential]\n\thelper =\n")
        self.assertIs(self._answer(""), False)

    def test_a_linked_worktree_reads_its_repositorys_config(self):
        main = self.home / "main"
        (main / ".git" / "worktrees" / "w").mkdir(parents=True)
        (main / ".git" / "config").write_text("[credential]\n\thelper = osxkeychain\n")
        (main / ".git" / "worktrees" / "w" / "commondir").write_text("../..\n")
        linked = self.home / "linked"
        linked.mkdir()
        (linked / ".git").write_text(f"gitdir: {main / '.git' / 'worktrees' / 'w'}\n")
        self.repositories.append(linked)
        self.assertIs(self._answer(""), True)

    def test_a_worktree_config_counts_only_when_the_repository_turns_it_on(self):
        root = self._repository("[credential]\n\thelper = osxkeychain\n")
        (root / ".git" / "config.worktree").write_text("[credential]\n\thelper =\n\thelper = store\n")
        self.assertIs(self._answer(""), True)
        (root / ".git" / "config").write_text("[credential]\n\thelper = osxkeychain\n"
                                              "[extensions]\n\tworktreeConfig = true\n")
        self.assertIs(self._answer(""), False)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs a named pipe")
    def test_a_repository_whose_git_entry_is_not_a_file_or_directory_is_never_called_unused(self):
        root = self.home / "piped"
        root.mkdir()
        os.mkfifo(root / ".git")
        self.repositories.append(root)
        self.assertIsNone(self._answer(""))

    def test_a_repository_that_includes_another_file_is_never_called_unused(self):
        self._repository("[include]\n\tpath = ../elsewhere\n")
        self.assertIsNone(self._answer(""))

    def test_a_repository_whose_git_directory_cannot_be_found_is_never_called_unused(self):
        root = self.home / "pointer"
        root.mkdir()
        (root / ".git").write_text("not a pointer\n")
        self.repositories.append(root)
        self.assertIsNone(self._answer(""))

    def test_a_helper_the_environment_sets_reads_the_store(self):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "Credential.Helper",
                                          "GIT_CONFIG_VALUE_0": "osxkeychain"}):
            self.assertIs(self._answer(""), True)
        with mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": "'credential.helper'='osxkeychain'"}):
            self.assertIs(self._answer(""), True)

    def test_the_environment_clearing_the_helpers_leaves_the_token_unused(self):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": "'credential.helper'=''"}):
            self.assertIs(self._answer("[credential]\n\thelper = osxkeychain\n"), False)

    def test_config_the_environment_names_but_git_would_refuse_is_never_called_unused(self):
        with mock.patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": "'credential.helper"}):
            self.assertIsNone(self._answer(""))
        with mock.patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1"}):
            self.assertIsNone(self._answer(""))


@contextlib.contextmanager
def _secret_service(*answers, searches_locked=False):
    """Has the Secret Service give `answers`, one per call, in order, and search locked collections
    or not. Yields the patched runner."""
    with mock.patch.object(C, "_secret_service_searches_locked_items", return_value=searches_locked), \
         mock.patch.object(C, "_run", side_effect=[mock.Mock(returncode=0, stdout=a) for a in answers]) as run:
        yield run


class GitsOwnEntry(unittest.TestCase):
    def _probe(self, probe, returncode=0, stdout=""):
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=returncode, stdout=stdout)) as run:
            answer = probe()
        return answer, run.call_args.args[0]

    def test_the_macos_lookup_and_removal_name_gits_entry(self):
        answer, argv = self._probe(C._macos_keychain_has_github)
        self.assertIs(answer, True)
        self.assertEqual(argv[-6:], ["-s", "github.com", "-r", "htps", "-t", "dflt"])
        self.assertIn("-s github.com -r htps -t dflt", C._MACOS_STORE.delete_command)

    def test_the_linux_removal_names_gits_entry(self):
        self.assertIn("secret-tool clear server github.com protocol https", C._LINUX_STORE.delete_command)
        with _secret_service("(<[objectpath '/c/login']>,)", "(<false>,)", "(@ao [], @ao [])") as run:
            self.assertIs(C._linux_secret_has_github(), False)
        self.assertIn("{'server': 'github.com', 'protocol': 'https'}", run.call_args.args[0])

    def test_the_windows_removal_names_each_entry_git_keeps(self):
        listing = ("    Target: LegacyGeneric:target=git:https://github.com\n"
                   "    Target: LegacyGeneric:target=git:https://octo@github.com\n"
                   "    Target: LegacyGeneric:target=git:https://gitlab.com\n")
        with mock.patch.object(C.sys, "platform", "win32"), \
             mock.patch.object(C, "_run", return_value=mock.Mock(returncode=0, stdout=listing)):
            store, present = C._detect_cached_credential()
        self.assertIs(present, True)
        self.assertIn("cmdkey /delete:git:https://github.com ", store.delete_command)
        self.assertIn("cmdkey /delete:git:https://octo@github.com ", store.delete_command)
        for line in store.delete_command.splitlines():
            self.assertTrue(line.startswith("MSYS_NO_PATHCONV=1 cmdkey /delete:"), line)
        self.assertNotIn("gitlab", store.delete_command)

    def test_a_windows_entry_named_with_an_email_address_is_named_in_the_removal(self):
        self.assertIn("cmdkey /delete:git:https://a@b.com@github.com ",
                      C._windows_removal(["git:https://a@b.com@github.com"]))

    def test_a_windows_entry_whose_name_a_command_cannot_carry_is_taken_from_the_list(self):
        for target in ("git:https://a&b@github.com", "git:https://%USERPROFILE%@github.com",
                       "git:https://John Doe@github.com"):
            with self.subTest(target=target):
                listing = f"    Target: LegacyGeneric:target={target}\n"
                with mock.patch.object(C.sys, "platform", "win32"), \
                     mock.patch.object(C, "_run", return_value=mock.Mock(returncode=0, stdout=listing)):
                    store, present = C._detect_cached_credential()
                self.assertIs(present, True)
                self.assertNotIn(target, store.delete_command)
                self.assertIn("cmdkey /list", store.delete_command)

    def test_output_a_tool_writes_in_another_encoding_is_still_read(self):
        r = C._run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'J\\x81rgen')"])
        self.assertEqual(r.returncode, 0)
        self.assertTrue(r.stdout.startswith("J"))


class AStoreNotRead(unittest.TestCase):
    def setUp(self):
        self.data = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data, True)
        env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.data), "HOME": str(self.data)})
        env.start()
        self.addCleanup(env.stop)

    def _answer(self, probe, returncode, stdout=""):
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=returncode, stdout=stdout)):
            return probe()

    def test_the_macos_keychain_answers_present_absent_or_not_known(self):
        self.assertIs(self._answer(C._macos_keychain_has_github, 44), False)
        self.assertIsNone(self._answer(C._macos_keychain_has_github, 1))
        with mock.patch.object(C, "_run", return_value=None):
            self.assertIsNone(C._macos_keychain_has_github())

    def test_a_linux_store_kept_on_disk_but_not_answering_is_not_known(self):
        self.assertIs(self._answer(C._linux_secret_has_github, 1), False)
        (self.data / "keyrings").mkdir()
        (self.data / "keyrings" / "login.keyring").write_text("")
        self.assertIsNone(self._answer(C._linux_secret_has_github, 1))

    def test_windows_answers_present_absent_or_not_known(self):
        found = "Currently stored credentials:\n\n    Target: git:https://github.com\n    Type: Generic\n"
        self.assertEqual(self._answer(C._windows_credential_has_github, 0, found), ["git:https://github.com"])
        self.assertEqual(self._answer(C._windows_credential_has_github, 0, "Currently stored credentials:\n\n* NONE *\n"), [])
        german = "Derzeit gespeicherte Anmeldeinformationen:\n\n* KEINE *\n"
        self.assertEqual(self._answer(C._windows_credential_has_github, 0, german), [])
        self.assertIsNone(self._answer(C._windows_credential_has_github, 1))

    def test_a_store_that_searches_locked_collections_is_read_with_one_locked(self):
        answers = ("(<[objectpath '/c/login', '/c/session']>,)", "(<true>,)", "(<false>,)", "(@ao [], @ao [])")
        with _secret_service(*answers, searches_locked=True):
            self.assertIs(C._linux_secret_has_github(), False)
        with _secret_service("(<[objectpath '/c/login']>,)", "(<true>,)", "(@ao [], @ao [])",
                             searches_locked=True):
            self.assertIs(C._linux_secret_has_github(), False)
        with _secret_service("(<@ao []>,)", searches_locked=True):
            self.assertIs(C._linux_secret_has_github(), False)
        with _secret_service("(<@ao []>,)"):
            self.assertIsNone(C._linux_secret_has_github())

    def test_the_store_that_searches_locked_collections_is_recognised(self):
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=0, stdout="(uint32 4242,)")) as run:
            with mock.patch.object(C.Path, "read_text", return_value="gnome-keyring-d\n") as comm:
                self.assertIs(C._secret_service_searches_locked_items(), True)
            argv = run.call_args.args[0]
            self.assertEqual(argv[argv.index("--dest") + 1], "org.freedesktop.DBus")
            self.assertEqual(argv[-1], "org.freedesktop.secrets")
            with mock.patch.object(C.Path, "read_text", return_value="keepassxc\n"):
                self.assertIs(C._secret_service_searches_locked_items(), False)

    def test_a_locked_linux_store_is_not_searched_and_not_called_empty(self):
        with _secret_service("(<[objectpath '/c/login']>,)", "(<true>,)") as run:
            self.assertIsNone(C._linux_secret_has_github())
        self.assertFalse(any("SearchItems" in " ".join(c.args[0]) for c in run.call_args_list))

    def test_an_entry_a_locked_collection_may_hold_is_not_called_absent(self):
        answers = ("(<[objectpath '/c/login', '/c/vault']>,)", "(<false>,)", "(<true>,)", "(@ao [], @ao [])")
        with _secret_service(*answers):
            self.assertIsNone(C._linux_secret_has_github())
        found = ("(<[objectpath '/c/login', '/c/vault']>,)", "(<false>,)", "(<true>,)",
                 "([objectpath '/c/login/7'], @ao [])")
        with _secret_service(*found):
            self.assertIs(C._linux_secret_has_github(), True)

    def test_an_unread_store_is_reported_as_not_known(self):
        with mock.patch.object(C, "_detect_cached_credential", return_value=(C._MACOS_STORE, None)), \
             mock.patch.object(C, "_git_credentials_file_with_github", return_value=False):
            issues = C.check_credentials()
        self.assertEqual([(i.id, i.severity) for i in issues], [("cached-github-keychain-unread", "unknown")])
        self.assertIn("unlocked", issues[0].remediation)


class ThePlaintextFile(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        self.file = self.home / ".git-credentials"

    def test_a_github_entry_is_found_without_saw_reading_the_file(self):
        self.file.write_text("https://user:not-a-real-token@github.com\n")
        with mock.patch.object(C, "_run", wraps=C._run) as run:
            self.assertIs(C._git_credentials_file_with_github(), True)
        self.assertIs(run.call_args.kwargs.get("capture"), False)
        self.file.write_text("https://user:not-a-real-token@gitlab.com\n")
        self.assertIs(C._git_credentials_file_with_github(), False)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a file its owner cannot open")
    def test_a_file_that_cannot_be_opened_is_reported_as_not_known(self):
        self.file.write_text("https://user:not-a-real-token@github.com\n")
        self.file.chmod(0)
        self.addCleanup(self.file.chmod, 0o600)
        with mock.patch.object(C, "_run", return_value=mock.Mock(returncode=1)):
            self.assertIsNone(C._git_credentials_file_with_github())

    def test_no_file_means_no_plaintext_credential(self):
        self.assertIs(C._git_credentials_file_with_github(), False)

    def test_a_file_that_cannot_be_searched_is_reported_as_not_known(self):
        self.file.write_text("")
        with mock.patch.object(C, "_run", return_value=None):
            self.assertIsNone(C._git_credentials_file_with_github())
        with mock.patch.object(C, "_detect_cached_credential", return_value=None), \
             mock.patch.object(C, "_git_credentials_file_with_github", return_value=None):
            issues = C.check_credentials()
        self.assertEqual([(i.id, i.severity) for i in issues], [("git-credentials-unread", "unknown")])

    def test_a_store_or_file_not_read_never_raises_the_exposure_banner_or_blocks_rotation(self):
        for issue_id in ("git-credentials-unread", "cached-github-keychain-unread"):
            self.assertNotIn(issue_id, INCIDENT_TRIGGER_IDS)
            self.assertNotIn(issue_id, ROTATION_UNSAFE_IDS)


if __name__ == "__main__":
    unittest.main()

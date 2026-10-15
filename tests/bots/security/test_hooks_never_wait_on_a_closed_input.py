#!/usr/bin/env python3
"""saw's hook scripts never wait when git gives them no input: under every shell they run saw and the
person's own hook and finish, and with an input they hand both the exact bytes and arguments. Hooks an
earlier saw installed are recognised as saw's and brought up to date."""
from __future__ import annotations

import contextlib
import io
import os
import shutil
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security import hook, hookscript
from tests.bots.security.test_hook import _Isolated

_SHELLS = [s for s in ("/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh") if os.access(s, os.X_OK)]
_SAW = "/usr/local/bin/saw"
_NAMES = [(_SAW, None), ("/opt/my tools/saw", "/home/me/my config.yml"),
          ("/tmp/b in 'q\"$x/saw", "/tmp/c fg/it's.yaml")]


def _reads_input(script: str) -> bool:
    return '"$(cat)"' in script


class _HookFolder(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="hook-input-"))
        self.addCleanup(shutil.rmtree, self.folder, True)

    def _recorder(self, name: str) -> Path:
        path = self.folder / name
        path.write_text(f'#!/bin/sh\ncat > "{self.folder}/{name}-input"\n'
                        f'printf "%s\\n" "$@" > "{self.folder}/{name}-args"\nexit 0\n')
        os.chmod(path, 0o755)
        return path

    def _script(self, event: str, text: str) -> Path:
        path = self.folder / event
        path.write_text(text)
        os.chmod(path, 0o755)
        self._recorder(f"{event}.local")
        return path

    def _run(self, shell: str, script: Path, args: list[str], *, given: bytes | None):
        closed = given is None
        proc = subprocess.Popen([shell, str(script), *args], cwd=self.folder,
                                stdin=None if closed else subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                                preexec_fn=(lambda: os.close(0)) if closed else None)
        try:
            out, _ = proc.communicate(input=given, timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            self.fail(f"{script.name} under {shell} was still waiting on its input after 20 seconds")
        return proc.returncode, out

    def _read(self, name: str) -> str:
        return (self.folder / name).read_text()


class TestEveryScriptThatReadsInputNeverWaitsForIt(_HookFolder):
    def test_with_no_input_saw_and_your_own_hook_still_run_and_the_hook_finishes(self):
        self.assertIn("/bin/sh", _SHELLS)
        saw = self._recorder("saw")
        for event in hookscript.HOOKS:
            text = hookscript.render(event, str(saw), None)
            if not _reads_input(text):
                continue
            script = self._script(event, text)
            for shell in _SHELLS:
                with self.subTest(event=event, shell=shell):
                    for leftover in self.folder.glob("*-input"):
                        leftover.unlink()
                    code, _out = self._run(shell, script, ["origin", "url"], given=None)
                    self.assertEqual(code, 0)
                    self.assertEqual(self._read("saw-input"), "")
                    self.assertEqual(self._read(f"{event}.local-input"), "")

    def test_with_an_input_saw_and_your_own_hook_get_the_exact_bytes_and_arguments(self):
        saw = self._recorder("saw")
        given = ("a" * 40 + " " + "b" * 40 + "\n" + "c" * 40 + " " + "d" * 40 + " extra\n").encode()
        for event in hookscript.HOOKS:
            text = hookscript.render(event, str(saw), None)
            if not _reads_input(text):
                continue
            script = self._script(event, text)
            for shell in _SHELLS:
                with self.subTest(event=event, shell=shell):
                    code, _out = self._run(shell, script, ["origin", "url with space"], given=given)
                    self.assertEqual(code, 0)
                    self.assertEqual(self._read("saw-input").encode(), given)
                    self.assertEqual(self._read(f"{event}.local-input").encode(), given)
                    self.assertEqual(self._read(f"{event}.local-args"), "origin\nurl with space\n")
                    self.assertTrue(self._read("saw-args").endswith(f"{event}\norigin\nurl with space\n"))

    def test_no_script_reads_its_input_except_through_the_shared_reader(self):
        for event in hookscript.HOOKS:
            for saw, config in _NAMES:
                lines = hookscript.render(event, saw, config).splitlines(keepends=True)
                for n, line in enumerate(lines):
                    if "$(cat)" in line:
                        with self.subTest(event=event, saw=saw):
                            self.assertGreater(n, 0)
                            self.assertEqual(lines[n - 1], hookscript._INPUT_GUARD)


class TestTheInputIsLeftAloneWhereTheSystemCannotTell(_HookFolder):
    def test_with_no_way_to_see_the_input_a_given_input_still_arrives_whole(self):
        saw = self._recorder("saw")
        given = ("a" * 40 + " " + "b" * 40 + "\n").encode()
        text = hookscript.render("post-rewrite", str(saw), None).replace("/dev/fd", str(self.folder / "no-fd"))
        script = self._script("post-rewrite", text)
        code, _out = self._run("/bin/sh", script, ["amend"], given=given)
        self.assertEqual(code, 0)
        self.assertEqual(self._read("saw-input").encode(), given)


class TestEveryScriptAnEarlierSawInstalledIsRecognised(unittest.TestCase):
    def test_each_reads_as_saws_and_out_of_date_and_the_current_one_as_in_place(self):
        folder = Path(tempfile.mkdtemp(prefix="hook-earlier-"))
        self.addCleanup(shutil.rmtree, folder, True)
        for event in hookscript.HOOKS:
            for saw, config in _NAMES:
                path = folder / event
                for text, want in ([(hookscript.render(event, saw, config), hookscript.PRISTINE)]
                                   + [(e, hookscript.OUTDATED) for e in hookscript.render_earlier(event, saw, config)]):
                    with self.subTest(event=event, saw=saw, want=want):
                        path.write_text(text)
                        os.chmod(path, 0o755)
                        self.assertEqual(hookscript.verdict(path, (saw, config)), want)
                        self.assertEqual(hookscript.saw_command(text)[0], saw)

    def test_a_script_one_byte_away_from_one_of_saws_is_never_taken_for_saws(self):
        for event in hookscript.HOOKS:
            expected = (_SAW, None)
            for text in [hookscript.render(event, *expected)] + hookscript.render_earlier(event, *expected):
                for n in range(len(text)):
                    near = text[:n] + text[n + 1:]
                    if hookscript.is_installed(near, expected) or hookscript._is_previous(near, expected):
                        self.fail(f"{event}: deleting byte {n} ({text[n]!r}) still reads as saw's")


class TestTheScriptsEarlierSawsShippedAreRecognised(unittest.TestCase):
    def test_every_script_an_earlier_saw_shipped_reads_as_saws_and_out_of_date(self):
        import json
        shipped = json.loads((Path(__file__).parent / "data" / "hook_scripts_earlier_saws_installed.json").read_text())
        expected = (shipped["saw"], shipped["config"])
        folder = Path(tempfile.mkdtemp(prefix="hook-shipped-"))
        self.addCleanup(shutil.rmtree, folder, True)
        for event, scripts in shipped["oldest_first"].items():
            for text in scripts:
                with self.subTest(event=event, generation=scripts.index(text)):
                    self.assertIn(text, hookscript.render_earlier(event, *expected))
                    path = folder / event
                    path.write_text(text)
                    os.chmod(path, 0o755)
                    self.assertEqual(hookscript.verdict(path, expected), hookscript.OUTDATED)


class TestHooksAnEarlierSawInstalledAreBroughtUpToDate(_Isolated):
    def test_install_rewrites_every_earlier_script_quietly_and_uninstall_removes_them(self):
        saw = hook._saw_executable()
        for earlier in range(2):
            with self.subTest(generation=earlier):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(hook.install(), 0)
                for event in ("post-rewrite", "pre-push"):
                    path = hook._hooks_dir() / event
                    path.write_text(hookscript.render_earlier(event, saw, None)[earlier])
                    os.chmod(path, 0o755)
                self.assertEqual(hookscript.altered_hooks(), [])
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(hook.install(), 0)
                self.assertNotIn("had been changed", out.getvalue())
                for event in hookscript.HOOKS:
                    self.assertEqual(hookscript.verdict(hook._hooks_dir() / event), hookscript.PRISTINE)
                kept = hookscript.set_aside_dir()
                self.assertFalse(kept.exists() and any(kept.iterdir()))
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(hook.uninstall(), 0)


if __name__ == "__main__":
    unittest.main()

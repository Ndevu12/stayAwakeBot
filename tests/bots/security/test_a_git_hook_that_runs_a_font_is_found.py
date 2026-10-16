#!/usr/bin/env python3
"""A git hook or a git setting that runs a font file reads as a known payload, and `saw fix` takes such a
setting out as it takes out one carrying a known loader; a hook that only names a font in a comment, or
calls a font tool plainly, does not."""
from __future__ import annotations

import stat
import unittest

from stayawake.bots.security.models import CONFIRMED
from tests.bots.security.test_fix_takes_out_what_git_runs_from_a_payload import _GitSettingsCheckout, _said
from tests.bots.security.test_git_exec_surface import ExecSurfaceSandbox
from tests.support.samples import FONT_PAYLOAD


class TestAGitHookThatRunsAFontIsFound(ExecSurfaceSandbox):
    def _confirmed(self, body: str, name: str) -> list:
        repo = self.repo(name)
        self.hook(repo / ".git" / "hooks", "pre-commit", "#!/bin/sh\n" + body)
        return self.graded(repo)[CONFIRMED]

    def test_a_hook_that_runs_the_implants_font_reads_confirmed(self):
        for n, body in enumerate((f"node {FONT_PAYLOAD}\n",
                                  f"nohup node {FONT_PAYLOAD} >/dev/null 2>&1 &\n",
                                  f'echo checking\nnode "{FONT_PAYLOAD}"\n')):
            with self.subTest(body=body):
                self.assertTrue(self._confirmed(body, f"runs{n}"))

    def test_a_font_named_only_in_a_comment_stays_silent(self):
        self.assertEqual(self._confirmed(f"# node {FONT_PAYLOAD}\necho done\n", "comment"), [])

    def test_a_plain_call_of_a_font_tool_is_not_a_payload(self):
        self.assertEqual(self._confirmed(f"pyftsubset {FONT_PAYLOAD} --flavor=woff2\n", "tool"), [])

    def test_a_font_tool_in_a_hook_that_renames_programs_reads_confirmed(self):
        for n, first in enumerate(("export PATH=./bin:$PATH\n", 'pyftsubset() { node "$@"; }\n',
                                   "alias pyftsubset=node\n", 'function pyftsubset { node "$@"; }\n')):
            with self.subTest(first=first):
                self.assertTrue(self._confirmed(first + f"pyftsubset {FONT_PAYLOAD}\n", f"renamed{n}"))

    def test_a_setting_that_runs_a_font_reads_confirmed(self):
        for n, setting in enumerate((f"[alias]\n\tbuild = !node {FONT_PAYLOAD}\n",
                                     f"[core]\n\tfsmonitor = node {FONT_PAYLOAD}\n")):
            with self.subTest(setting=setting):
                repo = self.repo(f"setting{n}")
                self.append_config(repo, setting)
                self.assertTrue(self.graded(repo)[CONFIRMED])

    def test_a_program_a_setting_runs_that_runs_a_font_reads_confirmed(self):
        repo = self.repo("program")
        self.write(repo, "tools/page.sh", f"#!/bin/sh\nnode {FONT_PAYLOAD}\n")
        self.append_config(repo, "[core]\n\tpager = ./tools/page.sh\n")
        self.assertTrue(self.graded(repo)[CONFIRMED])


class TestSawFixTakesOutASettingThatRunsAFont(_GitSettingsCheckout):
    def test_an_alias_and_an_fsmonitor_that_run_a_font_are_taken_out(self):
        self.configure(f"[alias]\n\tbuild = !node {FONT_PAYLOAD}\n"
                       f"[core]\n\tfsmonitor = node {FONT_PAYLOAD}\n")
        result = self.checkout()
        self.assertEqual(self.values("alias.build"), [])
        self.assertEqual(self.values("core.fsmonitor"), [])
        self.assertIn(".git/config", result.removed.stripped)

    def test_a_hook_file_that_runs_a_font_is_left_and_named(self):
        hook = self.root / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text(f"#!/bin/sh\nnode {FONT_PAYLOAD}\n", encoding="utf-8")
        hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
        result = self.checkout()
        self.assertTrue(hook.exists())
        self.assertFalse(result.complete)
        self.assertIn("hooks directory", _said(result))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""A program deno or bun runs is the one saw reads, whether it is a script after `run` or `serve`, code
after `eval`, or a program read from standard input; a live process running such code is checked."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.bots.security.hygiene import process
from stayawake.utils.invocation import resolve_invocation
from stayawake.utils.procsnap import Process, Snapshot
from tests.support.samples import FROM_CHAR_CODE, joined


def _loader() -> str:
    return joined("ev", "al(String.", FROM_CHAR_CODE, "(118,97,114,32,120))")


def _live(*argvs: tuple[str, ...]):
    snapshot = Snapshot(processes=[Process(pid=n, argv=argv) for n, argv in enumerate(argvs, 10)],
                        unreadable=0, supported=True)
    with mock.patch.object(process, "_snapshot", return_value=snapshot):
        return process.check_live_processes()


class TestTheProgramBunOrDenoRunsIsRead(unittest.TestCase):
    def test_the_script_a_run_subcommand_names_is_the_one_read(self):
        for argv in (("deno", "run", "-A", "./x.ts"), ("deno", "run", "--config", "deno.json", "--allow-net",
                                                         "./x.ts"),
                     ("deno", "run", "--import-map=map.json", "-c", "deno.json", "./x.ts"),
                     ("deno", "serve", "--port", "8000", "./x.ts"), ("deno", "./x.ts"),
                     ("bun", "run", "./x.ts"), ("bun", "run", "--cwd", "./app", "./x.ts"),
                     ("bun", "--cwd", "./app", "./x.ts"), ("bun", "./x.ts"),
                     ("bun", "--console-depth", "5", "run", "./x.ts")):
            with self.subTest(argv=argv):
                self.assertEqual(resolve_invocation(argv).payload_path, "./x.ts")
        self.assertEqual(resolve_invocation(("deno", "run", "serve")).payload_path, "serve")

    def test_a_program_read_from_standard_input_is_seen(self):
        for argv in (("deno", "run", "-"), ("deno", "run", "-A", "-"), ("bun", "run", "-")):
            with self.subTest(argv=argv):
                self.assertTrue(resolve_invocation(argv).reads_stdin)

    def test_code_handed_to_deno_eval_or_bun_print_is_read_as_code(self):
        for argv in (("deno", "eval", "console.log(1)"), ("deno", "eval", "--print", "console.log(1)"),
                     ("bun", "-p", "console.log(1)"), ("bun", "--print", "console.log(1)")):
            with self.subTest(argv=argv):
                self.assertEqual(resolve_invocation(argv).code_args, ("console.log(1)",))

    def test_a_preloaded_file_and_other_interpreters_read_as_before(self):
        for argv, path in ((("bun", "-r", "./setup.ts", "./app.ts"), "./setup.ts"),
                           (("node", "-r", "./setup.js", "app.js"), "./setup.js"),
                           (("bun", "-c", "/tmp/.x/l.js"), "/tmp/.x/l.js"),
                           (("bun", "--config", "/tmp/.x/l.js"), "/tmp/.x/l.js")):
            with self.subTest(argv=argv):
                self.assertEqual(resolve_invocation(argv).payload_path, path)
        self.assertEqual(resolve_invocation(("node", "./run", "x")).payload_path, "./run")
        self.assertEqual(resolve_invocation(("python3", "run", "x")).payload_path, "run")


class TestALiveProgramRunByDenoOrBunIsChecked(unittest.TestCase):
    def test_code_deno_evaluates_in_a_live_process_is_found(self):
        self.assertTrue(_live(("deno", "eval", _loader())))

    def test_a_program_deno_or_bun_reads_from_standard_input_is_found(self):
        for argv in (("deno", "run", "-"), ("bun", "run", "-")):
            with self.subTest(argv=argv):
                self.assertTrue(_live(argv))

    def test_an_ordinary_deno_or_bun_server_says_nothing(self):
        self.assertEqual(_live(("deno", "run", "-A", "--config", "deno.json", "./main.ts"),
                               ("bun", "run", "dev"), ("bun", "--cwd", "./app", "./server.ts"),
                               ("deno", "serve", "--port", "8000", "./server.ts")), [])


if __name__ == "__main__":
    unittest.main()

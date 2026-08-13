#!/usr/bin/env python3
"""The running-process snapshot must return the kernel's argv, or say it could not.

Both halves are load-bearing. A re-split command string makes every downstream consumer — which is
specified over an argv VECTOR — answer confidently about the wrong command; and a refused process
rendered as an empty command line makes a beacon owned by another user look like an absence of
beacons.
"""
from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
import unittest

from stayawake.utils import procsnap


@contextlib.contextmanager
def _fixture(argv):
    """Run `argv` in its OWN SESSION and tear down the whole group.

    A shell fixture spawns a `sleep` child; killing only the shell reparents that child to init,
    where it lingers — which is how a verification run once left a looping process on the host for
    nineteen hours."""
    with subprocess.Popen(argv, start_new_session=True) as proc:
        try:
            time.sleep(0.4)
            yield proc.pid
        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.kill()


def _argv_of(pid):
    return next((p.argv for p in procsnap.snapshot().processes if p.pid == pid), None)


class TestArgvIsTheKernelsVector(unittest.TestCase):
    """`; :` keeps the shell resident — with a single command it exec-replaces itself, and the
    process under test is then `sleep`, which looks like a parser defect and is not one.

    Every fixture runs in its own session and is torn down by PROCESS GROUP. Killing the shell alone
    orphans its `sleep` child, and a test suite that leaves reparented sleepers behind is both untidy
    and a false positive for the very detector this data feeds."""

    def _roundtrip(self, argv):
        with _fixture(argv) as pid:
            return _argv_of(pid)

    @unittest.skipUnless(sys.platform in ("darwin",) or sys.platform.startswith("linux"),
                         "no argv source on this platform")
    def test_argv_round_trips_exactly(self):
        # Quotes, embedded spaces, a $0 slot and a newline all survive, because none of them is
        # recovered by splitting — they are read as the vector the process was executed with.
        for argv in ([("/bin/sh"), "-c", "sleep 20; :", "arg with spaces", "quo'te", "ZZ"],
                     ["/bin/sh", "-c", "sleep 20; :\nexec /tmp/.x/p &"],
                     ["/bin/sleep", "20"]):
            with self.subTest(argv=argv):
                self.assertEqual(list(self._roundtrip(argv) or ()), argv)

    @unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "no argv source")
    def test_a_long_argument_is_not_truncated(self):
        # A payload's whole code argument has to arrive intact — the incident's was 5,930 characters,
        # and a collector that quietly clipped it would hand the fingerprints a partial payload.
        #
        # 64 KB, not more, because the ceiling here is the PLATFORM's and not the collector's: Linux
        # caps a single argument at MAX_ARG_STRLEN (128 KiB), so a 200,000-character fixture cannot be
        # spawned at all and fails with "Argument list too long" before anything is measured. macOS
        # has no equivalent per-argument cap — 400,000 round-trips there — which is exactly why this
        # was green locally and failed in CI.
        argv = ["/bin/sh", "-c", "sleep 20; : " + "A" * 64_000]
        got = self._roundtrip(argv)
        self.assertEqual(list(got or ()), argv)

    @unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "no argv source")
    def test_splitting_a_ps_command_string_would_lose_arguments(self):
        # The reason this module exists, asserted rather than described: the same process read two
        # ways disagrees, and the string is the one that is wrong.
        argv = ["/bin/sh", "-c", "sleep 20; :", "arg with spaces", "quo'te", "ZZ"]
        with _fixture(argv) as pid:
            joined = subprocess.run(["ps", "-o", "command=", "-p", str(pid)],
                                    capture_output=True, text=True).stdout.strip()
            self.assertEqual(list(_argv_of(pid) or ()), argv)
            self.assertNotEqual(len(joined.split()), len(argv))


class TestARefusalIsReportedNotRenderedAsEmpty(unittest.TestCase):
    def test_an_unreadable_process_is_flagged_not_silently_empty(self):
        snap = procsnap.snapshot()
        if not snap.supported:
            self.skipTest("no argv source on this platform")
        refused = [p for p in snap.processes if p.argv_unreadable]
        if not refused:
            self.skipTest("every process on this host yielded its arguments")
        # The distinction a caller checking truthiness would lose.
        self.assertTrue(all(p.argv == () for p in refused))
        self.assertEqual(snap.unreadable, len(refused))
        self.assertIn("did not yield their arguments", snap.scope_note())

    def test_an_empty_argv_is_never_silently_a_readable_process(self):
        # This one must not be skippable: every readable process has at least argv[0], so
        # `argv == () and not argv_unreadable` is unreachable unless a refusal was rendered as an
        # absence. The refusal-list test above skips itself on a host with nothing refused, which
        # made it pass against exactly that defect.
        snap = procsnap.snapshot()
        if not snap.supported:
            self.skipTest("no argv source on this platform")
        silent = [p.pid for p in snap.processes if not p.argv and not p.argv_unreadable]
        self.assertEqual(silent, [], f"processes with no argv and no refusal flag: {silent[:5]}")

    def test_the_scope_note_counts_the_processes_it_actually_saw(self):
        snap = procsnap.snapshot()
        if not snap.supported or not snap.unreadable:
            self.skipTest("nothing refused on this host")
        # Refused processes are already IN `processes`; adding them again reported 740 of 543.
        self.assertIn(f"{snap.unreadable} of {len(snap.processes)} ", snap.scope_note())
        self.assertLessEqual(snap.unreadable, len(snap.processes))

    def test_an_unsupported_platform_says_so_rather_than_returning_nothing(self):
        snap = procsnap.Snapshot(supported=False)
        self.assertEqual(snap.processes, [])
        self.assertIn("cannot be read", snap.scope_note())

    def test_a_clean_snapshot_has_no_scope_note(self):
        self.assertEqual(procsnap.Snapshot(processes=[procsnap.Process(pid=1, argv=("x",))]).scope_note(), "")


if __name__ == "__main__":
    unittest.main()

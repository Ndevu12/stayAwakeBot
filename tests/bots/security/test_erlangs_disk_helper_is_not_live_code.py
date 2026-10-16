#!/usr/bin/env python3
"""The shell the Erlang VM runs to measure its disks is not reported as code handed to a process on standard input, and
nothing is ended for it; every other shell fed on standard input still is, however close it comes."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import erlang_port, livecode
from stayawake.bots.security.harden import live
from stayawake.bots.security.hygiene import process as audit
from stayawake.bots.security.hygiene.models import ROTATION_UNSAFE_IDS
from stayawake.utils import procstop
from stayawake.utils.procsnap import Identity, Process, Snapshot

_VM = ("/usr/lib/erlang/erts-14.2/bin/beam.smp", "--", "-root", "/usr/lib/erlang", "-progname", "erl")
_HELPER = ("erl_child_setup", "1048576")
_SPAWN = ("sh", "-c", "sh -s disksup 2>&1")
_DISK_HELPER = ("sh", "-s", "disksup")
_STDIN = "a program handed to it on standard input"


def _process(pid, ppid, argv, start, *, unreadable=False, identity=True):
    who = Identity(pid=pid, ppid=ppid, uid=os.getuid(), start_time=start) if identity else None
    return Process(pid=pid, argv=() if unreadable else tuple(argv), argv_unreadable=unreadable, identity=who)


def _chain(*argvs, port=_DISK_HELPER, **last):
    """Each argv started by the one before it, the port program last."""
    processes = [_process(10 + n, 9 + n, argv, n + 1) for n, argv in enumerate(argvs)]
    processes.append(_process(10 + len(argvs), 9 + len(argvs), port, len(argvs) + 1, **last))
    return processes


def _reported(processes, *, gone=False):
    with mock.patch.object(livecode, "program_is_gone", return_value=gone):
        return [(found.process.pid, found.reason) for found in livecode.live_code_processes(Snapshot(processes))]


def _port_pid(processes):
    return processes[-1].pid


class TestTheVmsDiskHelperIsNotReported(unittest.TestCase):
    def test_the_disk_helper_the_vms_helper_starts_is_not_reported(self):
        self.assertEqual(_reported(_chain(_VM, _HELPER)), [])

    def test_the_disk_helper_run_through_the_shell_the_vms_helper_starts_is_not_reported(self):
        self.assertEqual(_reported(_chain(_VM, _HELPER, _SPAWN)), [])

    def test_the_vm_started_by_its_short_name_is_the_vm(self):
        self.assertEqual(_reported(_chain(("beam",), _HELPER)), [])

    def test_a_disk_helper_whose_program_is_gone_is_still_reported(self):
        processes = _chain(_VM, _HELPER)
        self.assertIn((_port_pid(processes), "a program that is no longer on this disk"),
                      _reported(processes, gone=True))


class TestAuditAndTheKillPathBothLeaveItAlone(unittest.TestCase):
    def _audit(self, processes):
        with mock.patch.object(audit, "_snapshot", return_value=Snapshot(processes)), \
                mock.patch.object(livecode, "program_is_gone", return_value=False):
            return audit.check_live_processes()

    def _frozen(self, processes):
        frozen = []
        with mock.patch.object(livecode, "snapshot", return_value=Snapshot(processes)), \
                mock.patch.object(livecode, "program_is_gone", return_value=False):
            live.end_live_code(freeze=lambda who: frozen.append(who.pid) or procstop.SIGNALLED,
                               end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                               capture=lambda held, where: None, protected=set,
                               person=lambda: os.getuid(), rounds=2)
        return frozen

    def test_audit_reports_nothing_for_it(self):
        self.assertEqual(self._audit(_chain(_VM, _HELPER)), [])

    def test_audit_still_reports_one_a_node_program_feeds_and_rotation_is_unsafe(self):
        issues = self._audit(_chain(("node", "/opt/app/server.js"), port=_DISK_HELPER))
        self.assertEqual([issue.id for issue in issues], ["live-obfuscated-process"])
        self.assertIn("live-obfuscated-process", ROTATION_UNSAFE_IDS)

    def test_nothing_is_ended_for_it(self):
        self.assertEqual(self._frozen(_chain(_VM, _HELPER, _SPAWN)), [])

    def test_one_a_node_program_feeds_is_still_ended(self):
        processes = _chain(("node", "/opt/app/server.js"))
        self.assertEqual(self._frozen(processes), [_port_pid(processes)])


class TestEveryOtherShellFedOnStandardInputIsStillReported(unittest.TestCase):
    def assertReported(self, processes):
        self.assertIn((_port_pid(processes), _STDIN), _reported(processes))

    def test_the_disk_helper_under_any_other_parent(self):
        for label, chain in (
            ("a node program", (("node", "/opt/app/server.js"),)),
            ("bash", (("bash",),)),
            ("the vm itself, with no helper between", (_VM,)),
            ("the vm's shell, with no helper between", (_VM, _SPAWN)),
            ("a helper the vm did not start", (("node", "x.js"), _HELPER)),
            ("a helper bash started", (("bash",), _HELPER)),
            ("a helper with no parent", (_HELPER,)),
            ("a program the vm started that is not its helper", (_VM, ("bash",))),
            ("a program the vm started that is not its helper, through the vm's shell", (_VM, ("node", "x.js"), _SPAWN)),
            ("the vm's helper, through a shell running anything else",
             (_VM, _HELPER, ("sh", "-c", "sh -s disksup; id"))),
            ("the vm's helper, through two shells", (_VM, _HELPER, _SPAWN, _SPAWN)),
        ):
            with self.subTest(label=label):
                self.assertReported(_chain(*chain))

    def test_any_other_shell_fed_on_standard_input_under_the_vms_helper(self):
        for port in (("sh", "-s"), ("sh", "-s", "cpu_sup"), ("sh", "-s", "disksup", "extra"),
                     ("sh", "-s", "--", "--yes"), ("bash", "-s", "disksup"), ("/usr/bin/sh", "-s", "disksup"),
                     ("dash", "-s", "disksup")):
            with self.subTest(port=port):
                self.assertReported(_chain(_VM, _HELPER, port=port))

    def test_a_link_that_cannot_be_read(self):
        vm, helper, port = _chain(_VM, _HELPER)
        for label, processes in (
            ("the helper's arguments", [vm, _process(11, 10, (), 2, unreadable=True), port]),
            ("the vm's arguments", [_process(10, 9, (), 1, unreadable=True), helper, port]),
            ("who the helper is", [vm, _process(11, 10, _HELPER, 2, identity=False), port]),
            ("who the port program is", [vm, helper, _process(12, 11, _DISK_HELPER, 3, identity=False)]),
            ("the helper is not in the table", [vm, port]),
            ("the vm is not in the table", [helper, port]),
        ):
            with self.subTest(label=label):
                self.assertReported(processes)

    def test_a_parent_that_started_after_the_process_it_would_have_started(self):
        vm, helper, _port = _chain(_VM, _HELPER)
        for label, processes in (
            ("the helper", [vm, _process(11, 10, _HELPER, 9), _process(12, 11, _DISK_HELPER, 3)]),
            ("the vm", [_process(10, 9, _VM, 9), helper, _process(12, 11, _DISK_HELPER, 3)]),
        ):
            with self.subTest(label=label):
                self.assertReported(processes)


class TestAListThatCannotBeReadIsSaidSo(unittest.TestCase):
    def test_a_list_missing_a_part_is_refused(self):
        shipped = erlang_port.PROGRAMS_FILE.read_text(encoding="utf-8")
        for part in ("helpers:", "vms:", "shells:", "spawned_as:"):
            with self.subTest(part=part), tempfile.TemporaryDirectory() as work:
                broken = Path(work) / "programs.yml"
                broken.write_text("\n".join(line for line in shipped.splitlines() if part not in line),
                                  encoding="utf-8")
                with self.assertRaises(ValueError):
                    erlang_port.port_programs(broken)


if __name__ == "__main__":
    unittest.main()

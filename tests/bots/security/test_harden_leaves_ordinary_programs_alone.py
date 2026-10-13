#!/usr/bin/env python3
"""`saw harden` stops code running with no file behind it, and leaves ordinary programs running."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import harden, hook
from stayawake.bots.security.harden import approvals as agentapprovals
from stayawake.bots.security.harden import denial, live
from stayawake.bots.security.harden import settings as editorsettings
from stayawake.bots.security.hygiene.models import HygieneIssue
from stayawake.bots.security import livecode
from stayawake.bots.security.livecode import LiveCode
from stayawake.utils import elevate, operator, procsnap, procstop, streaming
from stayawake.utils.procsnap import Identity, Process, Snapshot

_NEEDS_POSIX_NONROOT = (os.name == "posix"
                        and not (hasattr(os, "geteuid") and os.geteuid() == 0))
_SYSTEM_FOLDER = "/usr/bin"
_ON_LINUX = sys.platform.startswith("linux")
_SYSTEM_LINKS = ("/bin", "/sbin", "/lib", "/var", "/etc")


_MINE = os.getuid() if hasattr(os, "getuid") else 501
_THEIRS = _MINE + 1


def _code(pid, *, confirmed, uid=_MINE, argv=("node", "-e", "payload")):
    """One graded process as the finder hands it over."""
    return LiveCode(Process(pid=pid, argv=argv,
                            identity=Identity(pid=pid, ppid=1, uid=uid, start_time=7)),
                    "payload", "dynamic-exec sink", confirmed)


def _operator(uid):
    """The account saw acts for, as the operator lookup answers it."""
    return operator.Operator(name="someone", uid=uid, home=Path("/home/someone"), via="raised")


def _not_ours(who):
    """A process this account may not signal."""
    return procstop.NEEDS_PRIVILEGE


def _status(*, owner=0, mode=0o755, device=0, inode=0):
    """A file status as the kernel reports it."""
    return os.stat_result((stat.S_IFREG | mode, inode, device, 1, owner, 0, 0, 0, 0, 0))


_REPLACEMENT = _status(inode=9)
_ON_DISK, _IN_MEMORY, _LAYERED = 0xEF53, 0x01021994, 0x794C7630


_ROOT_FOLDER = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 2, 0, 0, 0, 0, 0, 0))


def _gone(where, *, running=None, readable=True, now=None, filesystem=_ON_DISK, view="",
          view_is_roots=False, runs_as=0, root=False):
    """Grade a process executing `where` as account `runs_as`: the file it runs has status
    `running` and lives on `filesystem` (None when that cannot be read), the path holds a file with
    status `now` when given, and the process sees its files through `view`, whose folders are
    root's when `view_is_roots`."""
    running = running or _status()
    target = where[:-len(" (deleted)")] if where.endswith(" (deleted)") else where
    real_stat = os.stat

    def read(pid):
        if not readable:
            raise PermissionError(13, "denied")
        return running

    def kind(pid):
        if filesystem is None:
            raise PermissionError(13, "denied")
        return filesystem

    def look(name, *args, **kwargs):
        if now is not None and name == view + target:
            return now
        return real_stat(name, *args, **kwargs)

    real_lstat = os.lstat

    def look_at_folder(name, *args, **kwargs):
        if view_is_roots and view and name.startswith(view):
            return _ROOT_FOLDER
        return real_lstat(name, *args, **kwargs)

    with mock.patch.object(procsnap, "_view_of", return_value=view), \
            mock.patch.object(procsnap.os, "stat", side_effect=look), \
            mock.patch.object(procsnap.os, "lstat", side_effect=look_at_folder):
        return procsnap.program_is_gone(os.getpid(), path=lambda pid: where, running=read,
                                        filesystem=kind, account=lambda pid: runs_as,
                                        as_root=lambda: root)


class TestAProgramWhoseFileIsGoneIsFound(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="gone-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.real = self.home / "server"
        self.real.write_text("")

    def test_code_running_from_memory_is_found(self):
        self.assertTrue(_gone("/memfd:x (deleted)"))

    def test_a_removed_program_with_nothing_in_its_place_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/saw-no-such-program (deleted)"))

    def test_a_removed_program_run_by_an_unreadable_account_needs_its_update(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/saw-no-such-program (deleted)", runs_as=None))
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/saw-no-such-program (deleted)", runs_as=-1))

    def test_an_accounts_own_removed_program_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", running=_status(owner=_MINE),
                              runs_as=_MINE))

    def test_an_administrators_program_removed_from_an_accounts_folder_is_found(self):
        self.assertTrue(_gone(f"{self.home}/agent (deleted)", runs_as=_MINE))

    def test_a_removed_program_an_account_owns_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", running=_status(owner=1000)))

    def test_a_removed_program_other_accounts_could_change_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", running=_status(mode=0o775)))

    def test_a_removed_program_that_cannot_be_read_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", readable=False))

    def test_a_removed_program_replaced_by_an_accounts_file_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", now=_status(owner=1000, inode=9)))

    def test_a_removed_program_replaced_by_a_file_others_could_change_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", now=_status(mode=0o777, inode=9)))

    def test_a_removed_program_whose_path_holds_the_same_file_is_found(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", now=_status()))

    def test_a_removed_program_in_a_folder_the_account_can_write_is_found(self):
        self.assertTrue(_gone(f"{self.home}/agent (deleted)", now=_REPLACEMENT))

    def test_a_removed_program_in_a_folder_every_account_can_write_is_found(self):
        self.assertTrue(_gone(f"{os.path.realpath('/tmp')}/agent (deleted)", now=_REPLACEMENT))

    def test_a_removed_program_reached_through_a_link_is_found(self):
        links = [link for link in _SYSTEM_LINKS if os.path.islink(link)
                 and not _gone(f"{os.path.realpath(link)}/a (deleted)", now=_REPLACEMENT)]
        if not links:
            self.skipTest("no link here leads to a folder only an administrator can change")
        self.assertTrue(_gone(f"{links[0]}/agent (deleted)", now=_REPLACEMENT))

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "needs a POSIX account that permissions apply to")
    def test_a_removed_program_in_a_folder_an_account_owns_is_found(self):
        self.assertTrue(_gone(f"{Path.home()}/agent (deleted)", now=_REPLACEMENT))

    def test_a_removed_program_in_a_folder_that_is_not_there_is_found(self):
        self.assertTrue(_gone(f"{self.home}/missing/agent (deleted)", now=_REPLACEMENT))

    def test_a_removed_program_where_it_runs_is_not_excused_by_this_machines_files(self):
        self.assertTrue(_gone(f"{_SYSTEM_FOLDER}/env (deleted)", view=str(self.home)))

    def test_a_program_whose_path_holds_another_file_and_lives_in_memory_is_found(self):
        self.assertTrue(_gone(str(self.real), filesystem=_IN_MEMORY))

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "needs a POSIX account that permissions apply to")
    def test_a_program_in_a_folder_this_account_cannot_open_is_found(self):
        shut = self.home / "shut"
        shut.mkdir()
        self.addCleanup(os.chmod, shut, 0o700)
        os.chmod(shut, 0)
        self.assertTrue(_gone(f"{shut}/agent"))

    @unittest.skipUnless(_NEEDS_POSIX_NONROOT, "needs a POSIX account that permissions apply to")
    def test_a_program_root_is_refused_is_judged_by_the_file_it_runs(self):
        shut = self.home / "shut"
        shut.mkdir()
        self.addCleanup(os.chmod, shut, 0o700)
        os.chmod(shut, 0)
        self.assertFalse(_gone(f"{shut}/wm", root=True, filesystem=_ON_DISK))
        self.assertTrue(_gone(f"{shut}/wm", root=True, filesystem=_IN_MEMORY))

    def test_a_program_behind_a_looping_link_is_found(self):
        (self.home / "a").symlink_to(self.home / "b")
        (self.home / "b").symlink_to(self.home / "a")
        self.assertTrue(_gone(f"{self.home}/a/agent"))

    def test_a_process_that_ended_between_reads_is_judged_by_its_path(self):
        def ended(pid):
            raise FileNotFoundError(2, "No such process")
        for root in (False, True):
            self.assertTrue(procsnap.program_is_gone(
                os.getpid(), path=lambda pid: f"{_SYSTEM_FOLDER}/env (deleted)", running=ended,
                as_root=lambda: root))
            self.assertFalse(procsnap.program_is_gone(
                os.getpid(), path=lambda pid: str(self.real), running=ended,
                as_root=lambda: root))

    def test_a_running_file_root_is_refused_is_not_called_missing_by_root(self):
        self.assertFalse(_gone(str(self.home / "app"), readable=False, root=True))
        self.assertTrue(_gone(str(self.home / "app"), readable=False, root=False))

    def test_a_program_that_cannot_be_read_and_is_not_there_is_found(self):
        self.assertTrue(_gone(str(self.home / "agent"), readable=False))

    def test_a_program_out_of_reach_here_living_in_memory_is_found(self):
        self.assertTrue(_gone("/saw-out-of-reach/payload", filesystem=_IN_MEMORY))

    def test_a_program_out_of_reach_here_whose_filesystem_cannot_be_read_is_found(self):
        self.assertTrue(_gone("/saw-out-of-reach/payload", filesystem=None))

    @unittest.skipUnless(_ON_LINUX, "macOS ends a copied system program before it runs")
    def test_a_real_process_whose_file_was_removed_is_found(self):
        copy = self.home / "sleeper"
        shutil.copyfile(shutil.which("sleep") or "/bin/sleep", copy)
        copy.chmod(0o700)
        proc = subprocess.Popen([str(copy), "30"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 5
        while procsnap.program_path(proc.pid) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        copy.unlink()
        self.assertTrue(procsnap.program_is_gone(proc.pid))


class TestAnOrdinaryProgramIsNotMissing(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="kept-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        self.real = self.home / "server"
        self.real.write_text("")

    def test_a_system_program_replaced_by_an_update_is_not_missing(self):
        self.assertFalse(_gone(f"{_SYSTEM_FOLDER}/env (deleted)"))

    def test_an_administrators_program_an_update_removed_is_not_missing_for_an_account(self):
        self.assertFalse(_gone(f"{_SYSTEM_FOLDER}/saw-no-such-program (deleted)", runs_as=_MINE))

    def test_a_program_out_of_reach_here_on_disk_is_not_missing(self):
        self.assertFalse(_gone("/saw-out-of-reach/server", filesystem=_ON_DISK))

    def test_a_program_on_a_detached_layered_mount_is_not_missing(self):
        self.assertFalse(_gone("/libexec/saw-session", filesystem=_LAYERED))

    def test_a_program_reachable_here_in_memory_is_not_missing(self):
        self.assertFalse(_gone(str(self.real), running=os.stat(self.real), filesystem=_IN_MEMORY))

    def test_a_program_an_update_replaced_where_it_runs_is_not_missing(self):
        self.assertFalse(_gone("/usr/bin/saw-only-there (deleted)", now=_REPLACEMENT,
                               view=str(self.home), view_is_roots=True))

    def test_a_program_whose_path_a_newer_mount_covers_is_not_missing(self):
        self.assertFalse(_gone(str(self.real)))

    def test_a_program_that_cannot_be_read_but_is_there_is_not_missing(self):
        self.assertFalse(_gone(str(self.real), readable=False))

    def test_a_real_running_program_is_not_missing(self):
        proc = subprocess.Popen([shutil.which("sleep") or "/bin/sleep", "30"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        deadline = time.monotonic() + 5
        while procsnap.program_path(proc.pid) is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(procsnap.program_is_gone(proc.pid))

    @unittest.skipUnless(_ON_LINUX, "only Linux describes a process's mounts")
    def test_a_process_sharing_this_runs_mounts_is_read_in_this_runs_view(self):
        self.assertEqual(procsnap._view_of(os.getpid()), "")

    @unittest.skipUnless(_ON_LINUX, "only Linux describes a running file's filesystem")
    def test_the_filesystem_a_running_program_lives_on_is_read(self):
        self.assertIsInstance(procsnap._filesystem_of(os.getpid()), int)
        self.assertFalse(procsnap._on_memory(os.getpid(), procsnap._filesystem_of))


class TestAnotherAccountsProcessIsStoppedOnlyWhenIdentified(unittest.TestCase):
    def _end(self, item, *, freeze=_not_ours, person=lambda: _MINE):
        asked = []
        out = live.end_live_code(find=lambda: [item], freeze=freeze,
                                 end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                                 capture=lambda held, where: None, protected=lambda: {1},
                                 elevated=lambda pids, signatures: (asked.extend(pids)
                                                                    or (elevate.GRANTED, pids)),
                                 person=person, rounds=3)
        return out, asked

    def _frozen(self, item, *, person):
        frozen = []
        out, _asked = self._end(item, person=person,
                                freeze=lambda who: frozen.append(who.pid) or procstop.SIGNALLED)
        return out, frozen

    def test_code_saw_could_not_identify_is_named_and_never_asked_about(self):
        out, asked = self._end(_code(404, confirmed=False, uid=_THEIRS))
        self.assertEqual(asked, [], "it asked for root to stop a guess")
        self.assertEqual(out.left_unidentified, [404])
        self.assertFalse(out.finished)

    def test_code_left_running_is_never_called_finished(self):
        seen = []
        def find():
            seen.append(1)
            return [_code(404, confirmed=False, uid=_THEIRS)] if len(seen) < 3 else []
        out = live.end_live_code(find=find, freeze=_not_ours,
                                 end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                                 capture=lambda held, where: None, protected=lambda: {1},
                                 elevated=lambda pids, signatures: (elevate.GRANTED, pids),
                                 person=lambda: _MINE, rounds=3)
        self.assertEqual(out.still_holding, 0)
        self.assertFalse(out.finished, "it called a pass finished that left code running")

    def test_where_saw_cannot_see_the_machines_root_it_never_asks_for_a_password(self):
        with mock.patch.object(live, "maps_the_hosts_root", return_value=False):
            out, asked = self._end(_code(412, confirmed=True, uid=_THEIRS))
        self.assertEqual(asked, [], "it asked for a root that cannot reach the machine")
        self.assertTrue(out.cannot_reach_the_machines_root)
        self.assertEqual(out.refused, [412])

    def test_code_saw_identified_is_asked_about(self):
        out, asked = self._end(_code(405, confirmed=True, uid=_THEIRS))
        self.assertEqual(asked, [405])
        self.assertEqual(out.left_unidentified, [])

    def test_another_accounts_guess_is_left_running_even_where_it_could_be_stopped(self):
        out, frozen = self._frozen(_code(407, confirmed=False, uid=_THEIRS), person=lambda: _MINE)
        self.assertEqual(frozen, [], "it stopped another account's process on a guess")
        self.assertEqual(out.left_unidentified, [407])

    def test_a_system_process_is_never_stopped_on_a_guess_when_saw_runs_as_root(self):
        out, frozen = self._frozen(_code(408, confirmed=False, uid=0), person=lambda: None)
        self.assertEqual(frozen, [], "it stopped a system process on a guess")
        self.assertEqual(out.left_unidentified, [408])

    def test_this_accounts_guess_that_needs_root_is_never_asked_about(self):
        out, asked = self._end(_code(411, confirmed=False))
        self.assertEqual(asked, [], "it asked for root to stop a guess")
        self.assertEqual(out.left_unidentified, [411])

    def test_this_accounts_guess_is_still_stopped(self):
        out, frozen = self._frozen(_code(409, confirmed=False), person=lambda: _MINE)
        self.assertEqual(frozen, [409])
        self.assertEqual(out.left_unidentified, [])

    def test_root_is_never_the_account_a_guess_is_stopped_for(self):
        for who, expected in ((None, None), (_operator(0), None), (_operator(_MINE), _MINE)):
            with mock.patch.object(live.os, "geteuid", return_value=0), \
                    mock.patch.object(live.operator, "resolve", return_value=who):
                self.assertEqual(live._person_running_it(), expected)

    def test_a_run_that_cannot_see_the_machines_root_acts_on_no_guess(self):
        with mock.patch.object(live, "maps_the_hosts_root", return_value=False):
            self.assertIsNone(live._person_running_it())

    def test_a_run_sees_the_machines_root_only_through_an_identity_map(self):
        self.assertTrue(procsnap.maps_the_hosts_root(read=lambda: "0 0 4294967295\n"))
        for table in ("0 1000 1\n1 100000 65536\n", "0 1 1000\n1000 0 1\n1001 1001 64536\n", ""):
            self.assertFalse(procsnap.maps_the_hosts_root(read=lambda: table), table)

    def test_a_machine_without_account_maps_is_seen_as_it_is(self):
        def absent():
            raise FileNotFoundError(2, "absent")
        self.assertTrue(procsnap.maps_the_hosts_root(read=absent))

    def test_a_run_whose_account_map_cannot_be_read_sees_no_root(self):
        def refused():
            raise PermissionError(13, "denied")
        self.assertFalse(procsnap.maps_the_hosts_root(read=refused))

    def test_a_run_without_root_acts_for_its_own_account(self):
        with mock.patch.object(live.os, "geteuid", return_value=_MINE), \
                mock.patch.object(live.os, "getuid", return_value=_MINE), \
                mock.patch.object(live.operator, "resolve", return_value=None):
            self.assertEqual(live._person_running_it(), _MINE)

    def test_a_process_holding_root_beside_this_account_is_never_stopped_on_a_guess(self):
        item = _code(414, confirmed=False)
        raised = item.process.identity.__class__(pid=414, ppid=1, uid=_MINE, start_time=7,
                                                 held_uids=(_MINE, 0, 0, 0))
        item = LiveCode(Process(pid=414, argv=item.process.argv, identity=raised), "payload",
                        "a program handed to it on standard input", False)
        out, frozen = self._frozen(item, person=lambda: _MINE)
        self.assertEqual(frozen, [], "it stopped a process holding root's rights on a guess")
        self.assertEqual(out.left_unidentified, [414])

    def test_identified_code_is_stopped_in_any_account(self):
        out, frozen = self._frozen(_code(410, confirmed=True, uid=0), person=lambda: None)
        self.assertEqual(frozen, [410])

    def test_nothing_of_this_account_stays_frozen_while_a_password_is_asked_for(self):
        events = []
        mine, theirs = _code(10, confirmed=True), _code(405, confirmed=True, uid=_THEIRS)
        live.end_live_code(find=lambda: [] if events else [mine, theirs],
                           freeze=lambda who: (procstop.SIGNALLED if who.pid == 10
                                               else procstop.NEEDS_PRIVILEGE),
                           end=lambda who: events.append(f"end {who.pid}") or procstop.SIGNALLED,
                           ended=lambda who: True, capture=lambda held, where: None,
                           protected=lambda: {1}, person=lambda: _MINE,
                           elevated=lambda pids, signatures: (events.append("ask")
                                                              or (elevate.GRANTED, pids)))
        self.assertEqual(events, ["end 10", "ask"], "a process stayed frozen through the prompt")

    def test_a_finder_that_hands_back_plain_tuples_is_never_trusted_with_root(self):
        process = _code(406, confirmed=True, uid=_THEIRS).process
        out, asked = self._end((process, "payload", "dynamic-exec sink"))
        self.assertEqual(asked, [])
        self.assertEqual(out.left_unidentified, [406])


class TestTheRecordNamesWhatWasFrozen(unittest.TestCase):
    def test_each_frozen_process_is_named(self):
        held = {}
        live.end_live_code(find=lambda: [] if held else [_code(10, confirmed=False,
                                                               argv=("/opt/x/agent", "-e", "p"))],
                           freeze=lambda who: procstop.SIGNALLED,
                           end=lambda who: procstop.SIGNALLED, ended=lambda who: True,
                           capture=lambda h, where: held.update(h) or None,
                           protected=lambda: {1}, person=lambda: _MINE)
        where = Path(tempfile.mkdtemp(prefix="capture-"))
        self.addCleanup(shutil.rmtree, where, True)
        record = json.loads(Path(live._capture(held, where)).read_text())
        self.assertEqual([p["program"] for p in record["processes"]], ["/opt/x/agent"])


class TestItAsksOnlyAnAdministratorAndNeverUnderASpinner(unittest.TestCase):
    class _Done:
        def __init__(self, code):
            self.returncode = code

    def _run(self, *, admin, terminal=True):
        calls, held = [], []

        @contextlib.contextmanager
        def quiet():
            held.append("on")
            yield
            held.append("off")

        def run(argv, **kw):
            calls.append((list(argv), list(held)))
            return self._Done(1 if "-n" in argv else 0)

        outcome, _detail = elevate.run_as_root(["/bin/kill", "-KILL", "9"],
                                               sudo=lambda: "/usr/bin/sudo", ask=lambda: terminal,
                                               admin=lambda: admin, run=run,
                                               quiet_spinners=quiet)
        return outcome, calls

    def test_an_account_that_does_not_administer_the_machine_is_never_prompted(self):
        outcome, calls = self._run(admin=False)
        self.assertEqual(outcome, elevate.NOT_AN_ADMINISTRATOR)
        self.assertEqual(len(calls), 1, "it prompted an account that cannot use sudo")

    def test_an_account_that_does_not_administer_the_machine_is_told_so_without_a_terminal(self):
        outcome, _calls = self._run(admin=False, terminal=False)
        self.assertEqual(outcome, elevate.NOT_AN_ADMINISTRATOR)

    def test_the_systems_own_prompt_asks_with_every_spinner_held_still(self):
        outcome, calls = self._run(admin=True)
        self.assertEqual(outcome, elevate.GRANTED)
        prompt, held_then = calls[-1]
        self.assertNotIn("-p", prompt, "saw put its own words on the system's prompt")
        self.assertEqual(held_then, ["on"], "the prompt ran while a spinner could draw over it")

    def test_an_administrator_belongs_to_a_group_sudo_grants(self):
        self.assertTrue(elevate.may_use_sudo(groups={"users", "wheel"}))
        self.assertTrue(elevate.may_use_sudo(groups={"staff", "admin"}))
        self.assertFalse(elevate.may_use_sudo(groups={"users", "docker"}))


class TestASpinnerStaysOffTheTerminalWhileHeld(unittest.TestCase):
    def test_nothing_is_drawn_while_it_is_held(self):
        out = io.StringIO()
        with streaming.status("working", out=out, enabled=True, interval=0.01):
            time.sleep(0.05)
            with streaming.spinners_held(settle=0.1):
                before = out.getvalue()
                time.sleep(0.1)
                during = out.getvalue()
        self.assertEqual(during, before, "the spinner drew while a prompt held the terminal")
        self.assertTrue(before.endswith("\r\033[K"), "the spinner's line was not cleared")


def _the_known_implant():
    """Code the signature corpus identifies, assembled from split tokens so this file holds no
    contiguous indicator."""
    return "glo" + "bal['_V']='0';var t=1;"


class TestTheKnownImplantIsAlwaysStopped(unittest.TestCase):
    def _stop(self, *, uid, person, reaches):
        snap = Snapshot(processes=[Process(pid=900, argv=("node", "-e", _the_known_implant()),
                                           identity=Identity(pid=900, ppid=1, uid=uid,
                                                             start_time=3))],
                        unreadable=0, supported=True)
        ended, asked = [], []
        out = live.end_live_code(
            find=lambda: [] if ended or asked else livecode.live_code_processes(snap),
            freeze=lambda who: procstop.SIGNALLED if reaches else procstop.NEEDS_PRIVILEGE,
            end=lambda who: ended.append(who.pid) or procstop.SIGNALLED,
            ended=lambda who: True, capture=lambda held, where: None, protected=lambda: {1},
            elevated=lambda pids, signatures: asked.extend(pids) or (elevate.GRANTED, pids),
            person=lambda: person)
        self.assertEqual(ended + asked, [900], "the known implant was left running")
        self.assertEqual(out.left_unidentified, [])
        self.assertTrue(out.finished)

    def test_the_grader_identifies_it(self):
        snap = Snapshot(processes=[Process(pid=900, argv=("node", "-e", _the_known_implant()))],
                        unreadable=0, supported=True)
        self.assertTrue(livecode.live_code_processes(snap)[0].confirmed)

    def test_it_is_stopped_in_this_account(self):
        self._stop(uid=_MINE, person=_MINE, reaches=True)

    def test_it_is_stopped_in_another_account_through_root(self):
        self._stop(uid=_THEIRS, person=_MINE, reaches=False)

    def test_it_is_stopped_in_another_account_under_sudo(self):
        self._stop(uid=_THEIRS, person=_MINE, reaches=True)

    def test_it_is_stopped_as_a_system_process_when_root_runs_saw(self):
        self._stop(uid=0, person=None, reaches=True)

    def test_it_is_stopped_where_saw_cannot_see_the_machines_root(self):
        self._stop(uid=_MINE, person=None, reaches=True)


def _issue(id_):
    return HygieneIssue(id=id_, severity="unknown", title=id_, detail=id_, remediation="x")


def _harden(ending):
    """Run harden over a stand-in for every collaborator that would act on this machine."""
    class _InPlace:
        state = hook.IN_PLACE
    return harden.run(live=lambda: [_issue("live-obfuscated-process")], stop=lambda: ending,
                      folders=lambda: [Path("/mine")], supported=lambda: True,
                      apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                      settle_hooks=lambda: hook.Settling(actions=[_InPlace()], target="/t"),
                      schedule_pass=lambda: None, editor_pass=editorsettings.Correcting,
                      agent_pass=agentapprovals.Correcting, altered=lambda: [],
                      saw_runs=lambda: True)


class TestWhatHardenSaysAboutAnotherAccount(unittest.TestCase):
    def test_unidentified_code_elsewhere_is_named_and_nothing_claims_it_was_stopped(self):
        code, text = _harden(live.Ending(left_unidentified=[404], quiet=True, still_holding=1))
        self.assertEqual(code, 1)
        self.assertIn("Suspicious code was left running", text)
        self.assertNotIn("another account", text)
        self.assertNotIn("It has been stopped", text)
        self.assertNotIn("sudo", text)

    def test_an_account_that_cannot_use_sudo_is_not_told_to(self):
        ending = live.Ending(matched=1, refused=[405], asked_for=[405],
                             asking=elevate.NOT_AN_ADMINISTRATOR, quiet=True, still_holding=1)
        _code_, text = _harden(ending)
        self.assertIn("An administrator can stop it with `sudo saw harden`", text)
        self.assertNotIn("Run `sudo saw harden`", text)

    def test_a_machine_without_sudo_is_not_told_to_use_it(self):
        ending = live.Ending(matched=1, refused=[405], asked_for=[405],
                             asking=elevate.NOT_AVAILABLE, quiet=True, still_holding=1)
        _code_, text = _harden(ending)
        self.assertIn("as root", text)
        self.assertNotIn("sudo", text)

    def test_code_still_running_here_is_said_beside_another_accounts(self):
        ending = live.Ending(left_unidentified=[404], quiet=True, still_holding=2)
        _code_, text = _harden(ending)
        self.assertIn("still running on this machine", text)
        self.assertIn("Suspicious code was left running", text)


class TestWhatHardenSaysInAContainer(unittest.TestCase):
    def test_it_says_to_run_outside_the_container_instead_of_as_root(self):
        ending = live.Ending(matched=1, refused=[412], asked_for=[412], quiet=True,
                             still_holding=1, cannot_reach_the_machines_root=True)
        code, text = _harden(ending)
        self.assertEqual(code, 1)
        self.assertIn("outside this container", text)
        self.assertNotIn("sudo", text)
        self.assertNotIn("as root", text)

    def test_unidentified_code_left_in_a_container_says_the_same(self):
        ending = live.Ending(left_unidentified=[413], quiet=True, still_holding=1,
                             cannot_reach_the_machines_root=True)
        _code_, text = _harden(ending)
        self.assertIn("outside this container", text)


class TestWhatHardenSaysWhenCodeCouldNotBeStopped(unittest.TestCase):
    def test_code_that_survived_ending_names_the_command(self):
        code, text = _harden(live.Ending(matched=1, frozen=1, survived=[10], quiet=True,
                                         still_holding=1))
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith("Code with no file behind it is still running"))
        self.assertIn("Run `saw harden` again", text)

    def test_a_stop_that_failed_names_the_command(self):
        def broken():
            raise OSError("the process table could not be read")
        class _InPlace:
            state = hook.IN_PLACE
        code, text = harden.run(live=lambda: [_issue("live-obfuscated-process")], stop=broken,
                                folders=lambda: [Path("/mine")], supported=lambda: True,
                                apply=lambda p: denial.PathOutcome(p, denial.ENFORCING, "held"),
                                settle_hooks=lambda: hook.Settling(actions=[_InPlace()],
                                                                   target="/t"),
                                schedule_pass=lambda: None, editor_pass=editorsettings.Correcting,
                                agent_pass=agentapprovals.Correcting, altered=lambda: [],
                                saw_runs=lambda: True)
        self.assertEqual(code, 1)
        self.assertIn("Run `saw harden` again", text)
        self.assertEqual(text.count("still running"), 1, "the same fact was said twice")


class TestEachProcessesAccountsAreRead(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin",
                         "only Linux and macOS describe a process's accounts")
    def test_an_ordinary_process_holds_only_its_own_account(self):
        identity, _state = procsnap.identify(os.getpid())
        self.assertEqual(len(identity.held_uids), 4 if _ON_LINUX else 3)
        self.assertEqual(set(identity.held_uids), {os.getuid()})


class TestWhatHardenSaysWhenNothingWasLeftToStop(unittest.TestCase):
    def test_code_that_ended_by_itself_is_not_claimed_as_stopped(self):
        code, text = _harden(live.Ending(quiet=True))
        self.assertEqual(code, 0)
        self.assertIn("no longer running", text)
        self.assertNotIn("It has been stopped", text)


if __name__ == "__main__":
    unittest.main()

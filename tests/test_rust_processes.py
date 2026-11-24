"""saw-platform lists, identifies and stops processes exactly as main does."""
import itertools
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.utils import elevate, procsnap, procstop

REPO_ROOT = Path(__file__).resolve().parents[1]


def identity(who):
    return None if who is None else [who.pid, who.ppid, who.uid, who.start_time, who.zombie, list(who.held_uids)]


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class ProcessesMatchMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "processes_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "processes_probe"

    def ask(self, cases):
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        return [json.loads(line) for line in printed]

    def sleeper(self):
        child = subprocess.Popen(["sleep", "60"])
        self.addCleanup(lambda: (child.kill(), child.wait()))
        return child.pid

    def sample(self):
        listed = procsnap._live_pids()[:40]
        return sorted({1, os.getpid(), self.sleeper(), 999999, *listed})

    def test_each_process_reads_the_same(self):
        pids = self.sample()
        questions = ("identify", "started", "path", "signature", "gone_live")
        pairs = list(itertools.product(pids, questions))
        before = [self.main_answer(pid, question) for pid, question in pairs]
        rust = self.ask([{"ask_about": q, "pid": p} for p, q in pairs])
        after = [self.main_answer(pid, question) for pid, question in pairs]
        steady = [(pair, answer, main) for pair, answer, main, again in zip(pairs, rust, before, after) if main == again]
        self.assertGreater(len(steady), len(pairs) // 2)
        for (pid, question), answer, main in steady:
            with self.subTest(pid=pid, question=question):
                self.assertEqual(answer, main)

    @staticmethod
    def main_answer(pid, question):
        """Return main's answer to one question about one process."""
        if question == "identify":
            who, state = procsnap.identify(pid)
            return [identity(who), state]
        if question == "started":
            start = procsnap.started(pid)
            return None if start is None else [str(start.at_ns), start.name, start.ppid]
        if question == "path":
            return procsnap.program_path(pid)
        if question == "signature":
            return procsnap.ps_signature(pid)
        return procsnap.program_is_gone(pid)

    def test_parents_and_snapshot(self):
        pids = self.sample()
        parents, snap = self.ask([{"ask_about": "parents"}, {"ask_about": "snapshot"}])
        main_parents = procsnap.parent_map()
        main_snap = procsnap.snapshot()
        for pid in pids:
            with self.subTest(pid=pid):
                self.assertEqual(parents.get(str(pid)), main_parents.get(pid))
        rows = {row[0]: row for row in snap["processes"]}
        for process in main_snap.processes:
            if process.pid in pids and process.pid in rows:
                with self.subTest(pid=process.pid):
                    self.assertEqual(rows[process.pid], [process.pid, list(process.argv), process.argv_unreadable,
                                                         identity(process.identity)])
        self.assertTrue(set(pids) - {999999} <= set(rows))
        same_counts = procsnap.Snapshot(processes=[None] * len(snap["processes"]), unreadable=snap["unreadable"],
                                        supported=snap["supported"])
        self.assertEqual(snap["note"], same_counts.scope_note())

    def test_a_program_no_longer_on_disk(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        mine = os.path.join(folder, "tool")
        Path(mine).write_text("x")
        system = "/bin/sh"
        paths = [None, "/memfd:x (deleted)", f"{system} (deleted)", f"{mine} (deleted)", system, mine, "/no/such",
                 "/no/such (deleted)", f"{folder}/gone (deleted)", "/usr/bin/true (deleted)"]
        runnings = [system, mine, "/usr/bin/true", {"error": "perm"}, {"error": "other"}, {"error": "missing"}]
        cases = [{"ask_about": "gone", "pid": 7, "path": p, "running": r, "filesystem": f, "account": a, "as_root": root}
                 for p, r, f, a, root in itertools.product(paths, runnings, [None, 0x01021994, 5], [None, 0, 501], [False, True])]
        for case, answer in zip(cases, self.ask(cases)):
            def running(_pid, given=case["running"]):
                if isinstance(given, str):
                    return os.stat(given)
                raise {"perm": PermissionError, "missing": FileNotFoundError}.get(given["error"], OSError)()

            def filesystem(_pid, given=case["filesystem"]):
                if given is None:
                    raise OSError()
                return given

            main = procsnap.program_is_gone(7, path=lambda _p: case["path"], running=running, filesystem=filesystem,
                                            account=lambda _p: case["account"], as_root=lambda: case["as_root"])
            with self.subTest(case=case):
                self.assertEqual(answer, main)
        folders = ["/bin", "/usr/bin", "/tmp", folder, "", "rel", "/usr//bin/", "/usr/bin/../lib", "/no/such", "/", "//"]
        rust = self.ask([{"ask_about": "root_changes", "folder": f} for f in folders[:-1]])
        self.assertEqual(rust, [procsnap._only_root_changes(f) for f in folders[:-1]])

    def test_windows_process_rows(self):
        texts = ["", "x", "[]", "{}", '{"ProcessId": 4}', '[{"ProcessId": 4, "ParentProcessId": 0, "CommandLine": "a b  c",'
                 ' "ExecutablePath": "C:\\\\x.exe", "CreationDate": "/Date(1700000000123)/", "User": "me"}]',
                 '[{"ProcessId": 5, "CreationDate": 17.9, "User": ""}, {"ProcessId": "6"}, 3, {"ProcessId": 7, "CommandLine": "",'
                 ' "CreationDate": "/Date(12+0100)/", "ParentProcessId": "x", "User": 4}]',
                 '{"ProcessId": 8, "CreationDate": "/Date(-5)/"}', '{"ProcessId": 9, "CreationDate": true}',
                 '{"ProcessId": 10, "CreationDate": "/Date(x)/", "User": "SYSTEM"}']
        rust = self.ask([{"ask_about": "cim", "text": t} for t in texts])
        main = [procsnap.rows_from_cim(t, split=lambda line: line.split()) for t in texts]
        self.assertEqual(rust, main)

    def test_whether_a_process_is_still_the_one_known(self):
        known = procsnap.Identity(pid=9, ppid=1, uid=501, start_time=100)
        nows = [(None, procsnap.GONE), (None, procsnap.NOT_OURS), (None, procsnap.UNSUPPORTED), (None, procsnap.RUNNING),
                (known, procsnap.RUNNING), (known, procsnap.NOT_OURS),
                (procsnap.Identity(pid=9, ppid=1, uid=501, start_time=100, zombie=True), procsnap.RUNNING),
                (procsnap.Identity(pid=9, ppid=2, uid=501, start_time=101), procsnap.RUNNING),
                (procsnap.Identity(pid=9, ppid=2, uid=0, start_time=100), procsnap.RUNNING)]
        rust = self.ask([{"ask_about": "still", "known": identity(known), "now": identity(w), "reading": s} for w, s in nows])
        for (who, state), answer in zip(nows, rust):
            with self.subTest(now=who, state=state), mock.patch.object(procstop, "identify", lambda _pid: (who, state)):
                verdict, _ = procstop._still(known)
                self.assertEqual(answer, verdict)

    def test_stopping_a_real_process(self):
        rust_child, main_child = self.sleeper(), self.sleeper()
        main_known = procsnap.identify(main_child)[0]
        steps = ["freeze", "resume", "end"]
        rust = self.ask([{"ask_about": "stop", "pid": rust_child, "action": a} for a in steps])
        main = [[procstop.freeze(main_known), False], [procstop.resume(main_known), False],
                [procstop.end(main_known), procstop.has_ended(main_known)]]
        self.assertEqual(rust, main)
        other = self.sleeper()
        recycled = self.ask([{"ask_about": "stop", "pid": other, "action": "end", "start_time": 1}])[0]
        known = procsnap.identify(other)[0]
        fake = procsnap.Identity(pid=known.pid, ppid=known.ppid, uid=known.uid, start_time=1)
        self.assertEqual(recycled, [procstop.end(fake), False])
        if os.geteuid() != 0 and procsnap.identify(1)[0] is not None:
            self.assertEqual(self.ask([{"ask_about": "stop", "pid": 1, "action": "freeze"}])[0],
                             [procstop.freeze(procsnap.identify(1)[0]), False])

    def test_ending_processes_as_root(self):
        tables = [{"10": "a", "11": "b"}, {"10": "a"}, {}, {"10": "z", "11": "b"}]
        cases = [{"ask_about": "as_root", "pids": [10, 11, 12], "signatures": {"10": "a", "11": "b"}, "before": before,
                  "after": after, "outcome": outcome}
                 for before, after, outcome in itertools.product(tables, tables, ["granted", "declined", "not-available"])]
        for case, answer in zip(cases, self.ask(cases)):
            asked = []

            def run(argv, given=case["outcome"]):
                asked.append(argv)
                return given, ""

            def signature(pid):
                return (case["after"] if len(asked) >= 2 else case["before"]).get(str(pid))

            outcome, ended = procstop.end_as_root([10, 11, 12], signatures={10: "a", 11: "b"}, run_as_root=run,
                                                  signature=signature)
            with self.subTest(case=case):
                self.assertEqual(answer, [outcome, ended, asked])


if __name__ == "__main__":
    unittest.main()

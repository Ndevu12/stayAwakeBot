"""saw-platform drives the service manager, reaches the session bus and locks Windows folders
exactly as main does."""
import itertools
import ntpath
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import schedule
from stayawake.utils import sessionbus, winlock

REPO_ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("cargo") and os.name == "posix", "needs cargo on Unix")
class ServicesMatchMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "services_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "services_probe"

    def ask(self, cases):
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        return [json.loads(line) for line in printed]

    def folder(self):
        made = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, made)
        return made

    def test_the_service_managers(self):
        with mock.patch.object(schedule.os, "path", ntpath):
            windows = list(schedule.every_manager_candidate())
        self.assertEqual(self.ask([{"ask_about": "candidates"}])[0], [list(schedule.manager_candidates()), windows])

    def test_starting_stopping_and_asking_about_a_job(self):
        folder = self.folder()
        items = {"text": "<Task>é</Task>\n".encode(), "not-utf8": b"\xff\xfe<", "missing": None}
        for name, raw in items.items():
            if raw is not None:
                Path(folder, name).write_bytes(raw)
        scripts = [[0, 0], [1], [0, 1], ["raise"], [0, "raise"]]
        cases = [{"ask_about": "manage", "platform": p, "action": a, "account": acc, "env": env, "codes": codes,
                  "item": os.path.join(folder, item)}
                 for p, a, acc, env, codes, item in itertools.product(
                     ["darwin", "linux", "windows"], ["activate", "running", "deactivate"], [501, None],
                     [None, {"XDG_RUNTIME_DIR": "/run/user/501"}], scripts, items)]
        for case, answer in zip(cases, self.ask(cases)):
            seen = []

            def run(argv, *, capture_output, timeout, env, codes=case["codes"]):
                copy = argv[argv.index("/XML") + 1] if "/XML" in argv else None
                copied = Path(copy).read_bytes().hex() if copy and os.path.exists(copy) else None
                seen.append([argv, env, copied])
                code = codes[len(seen) - 1] if len(seen) <= len(codes) else 0
                if code == "raise":
                    raise OSError("could not run")
                return subprocess.CompletedProcess(argv, code)

            item = Path(case["item"])
            with mock.patch.object(schedule, "_windows", lambda: case["platform"] == "windows"), \
                    mock.patch.object(schedule, "_linux", lambda: case["platform"] == "linux"), \
                    mock.patch.object(schedule, "_account", lambda: case["account"]), \
                    mock.patch.object(schedule, "_service_env", lambda: case["env"]), \
                    mock.patch.object(schedule, "LABEL", "com.example.job"), mock.patch.object(schedule, "UNIT", "example.service"), \
                    mock.patch.object(schedule, "_TASK", "example"):
                if case["action"] == "activate":
                    result = schedule._activate(item, run=run, binary="/sys/manager")
                elif case["action"] == "running":
                    result = schedule._running(run=run, binary="/sys/manager")
                else:
                    result = schedule._deactivate(item, run=run, binary="/sys/manager")
            with self.subTest(case=case):
                self.assertEqual(answer, [result, seen, os.path.exists(f"{item}.utf16")])

    def test_reaching_the_session_bus(self):
        uid = os.getuid()
        mine, with_bus, file_bus = self.folder(), self.folder(), self.folder()
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(os.path.join(with_bus, "bus"))
        self.addCleanup(listener.close)
        Path(file_bus, "bus").write_text("")
        link = os.path.join(self.folder(), "link")
        os.symlink(with_bus, link)
        runtimes = [None, mine, with_bus, file_bus, link, "/no/such", ""]
        cases = []
        for runtime, given, who in itertools.product(runtimes, runtimes, [uid, uid + 1]):
            cases.append({"ask_about": "user_manager", "uid": who, "runtime": runtime, "given": given})
        cases += [{"ask_about": "bus", "uid": who, "runtime": r} for r in runtimes for who in (uid, uid + 1)]
        for case, answer in zip(cases, self.ask(cases)):
            if case["ask_about"] == "bus":
                main = sessionbus.session_bus_env(uid=lambda: case["uid"], runtime_dir=case["runtime"])
            else:
                environ = {} if case["given"] is None else {"XDG_RUNTIME_DIR": case["given"]}
                main = sessionbus.user_manager_env(uid=lambda: case["uid"], runtime_dir=case["runtime"], environ=environ)
            with self.subTest(case=case):
                self.assertEqual(answer, main)

    def test_windows_folder_locks(self):
        names = [None, "", "S-1-5-18", "s-1-5-32-544", "S-1-5-21-1", "s-1-5-21-1"]
        cases = [{"ask_about": "grade", "owner": o, "acting": a} for o, a in itertools.product(names, names)]
        self.assertEqual(self.ask(cases), [winlock.grade(c["owner"], c["acting"]) for c in cases])
        locks = [{"ask_about": "lock", "action": a, "path": r"C:\Users\me\x", "sid": sid, "codes": codes}
                 for a, sid, codes in itertools.product(["deny", "allow", "give"], ["S-1-5-21-1", ""], [[0], [1], ["raise"]])]
        for case, answer in zip(locks, self.ask(locks)):
            seen = []

            def run(argv, *, capture_output, timeout, code=case["codes"][0]):
                seen.append(argv)
                if code == "raise":
                    raise OSError("could not run")
                return subprocess.CompletedProcess(argv, code)

            act = {"deny": lambda: winlock.deny_writes(Path(case["path"]), case["sid"], run=run, binary=r"C:\icacls.exe"),
                   "allow": lambda: winlock.allow_writes(Path(case["path"]), case["sid"], run=run, binary=r"C:\icacls.exe"),
                   "give": lambda: winlock.give_to_administrators(Path(case["path"]), run=run, binary=r"C:\icacls.exe")}
            result = act[case["action"]]()
            with self.subTest(case=case):
                self.assertEqual(answer, [result, seen])


if __name__ == "__main__":
    unittest.main()

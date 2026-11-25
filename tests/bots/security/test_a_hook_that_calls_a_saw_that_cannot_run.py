#!/usr/bin/env python3
"""`saw hook status` names saw's hooks that call a saw that cannot run, in the repository it runs in
and in every hooks folder saw keeps current, judged as git runs them, with the command that puts them
back. `saw hook repair` rewrites them wherever status sends the operator to it."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import hook, hookscript
from tests.bots.security.test_hook import _Isolated, _repo, _run, _set_aside

_CANNOT_RUN = "hook-copy-cannot-run"
_LEFT = "hooks-saw-does-not-rewrite"


def _split(fn, **kwargs) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(**kwargs)
    return code, out.getvalue(), err.getvalue()


class TestAHookThatCallsASawThatCannotRun(_Isolated):
    def setUp(self):
        super().setUp()
        self.repo = _repo({"a.txt": "x\n"})
        self.addCleanup(shutil.rmtree, self.repo, True)
        self.hooks = self.repo / ".git" / "hooks"
        self.saw = self.home / "bin" / "saw"
        self.saw.parent.mkdir()
        self.saw.write_text("#!/bin/sh\n")
        os.chmod(self.saw, 0o755)
        self.module = self.home / "site-packages" / "stayawake" / "__main__.py"
        self.module.parent.mkdir(parents=True)
        self.module.write_text("")
        os.chmod(self.module, 0o644)
        with mock.patch.object(hook, "_saw_executable", return_value=str(self.saw)):
            code, out, err = _split(hook.install, no_stream=True)
        self.assertEqual(code, 0, out + err)

    def _copies_calling(self, saw, folder: Path | None = None) -> None:
        for event in hookscript.HOOKS:
            path = (folder or self.hooks) / event
            path.write_text(hookscript.render(event, str(saw), None))
            os.chmod(path, 0o755)

    def _all_put_back(self, folder: Path) -> None:
        for event in hookscript.HOOKS:
            self.assertEqual(hookscript.verdict(folder / event, hookscript.installed()), hookscript.PRISTINE,
                             event)

    def _program(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
        os.chmod(path, 0o755)
        return path

    def _problems(self, **kwargs) -> dict:
        code, out, err = _split(hook.status, as_json=True, no_stream=True, **kwargs)
        self.assertEqual(code, 0, err)
        problems = {item["code"]: item for item in json.loads(out)["problems"]}
        for item in problems.values():
            self.assertIn(item["message"], err)
        return problems

    def _seed(self) -> None:
        cache = hookscript.cache_path()
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({str(self.repo): "abc"}))

    def _seeded_with_hooks_in(self, folder) -> None:
        _run(self.repo, "config", "core.hooksPath", str(folder))
        self._seed()

    def test_status_in_the_repository_names_its_hooks_that_call_a_module_file(self):
        self._copies_calling(self.module)
        self._in_repo(self.repo)
        found = self._problems(standing_in=True)[_CANNOT_RUN]
        self.assertEqual(found["repair"], "saw hook repair")
        self.assertIn(f"{len(hookscript.HOOKS)} of saw's hook file(s)", found["message"])
        self.assertNotIn(str(self.module), found["message"])
        self.assertNotIn(_CANNOT_RUN, self._problems())

    def test_repair_in_the_repository_rewrites_them_and_keeps_its_own_hooks(self):
        self._copies_calling(self.module)
        own = self.hooks / "pre-commit"
        own.write_text("#!/bin/sh\nnpx lint-staged\n")
        os.chmod(own, 0o755)
        chained = self.hooks / "post-merge.local"
        chained.write_text("#!/bin/sh\necho after\n")
        os.chmod(chained, 0o755)
        self._in_repo(self.repo)
        code, out, err = _split(hook.repair, no_stream=True, standing_in=True)
        self.assertEqual(code, 0, out + err)
        for event in hookscript.HOOKS:
            self.assertEqual(hookscript.verdict(self.hooks / event, hookscript.installed()), hookscript.PRISTINE,
                             event)
            self.assertNotIn(str(self.module), (self.hooks / event).read_text())
        self.assertEqual(len(_set_aside(self.home)), len(hookscript.HOOKS))
        self.assertEqual(own.read_text(), "#!/bin/sh\nnpx lint-staged\n")
        self.assertEqual(chained.read_text(), "#!/bin/sh\necho after\n")
        self.assertNotIn(_CANNOT_RUN, self._problems(standing_in=True))

    def test_hooks_that_call_a_saw_that_runs_are_no_problem_and_stay(self):
        self._copies_calling(self.saw)
        before = {event: (self.hooks / event).read_text() for event in hookscript.HOOKS}
        self._in_repo(self.repo)
        self.assertNotIn(_CANNOT_RUN, self._problems(standing_in=True))
        code, out, err = _split(hook.repair, no_stream=True, standing_in=True)
        self.assertEqual(code, 0, out + err)
        self.assertEqual({event: (self.hooks / event).read_text() for event in hookscript.HOOKS}, before)
        self.assertEqual(_set_aside(self.home), [])

    def test_a_repository_saw_keeps_current_is_named_wherever_status_runs(self):
        self._copies_calling(self.module)
        self._seed()
        self.assertIn(_CANNOT_RUN, self._problems())
        code, out, err = _split(hook.repair, no_stream=True)
        self.assertEqual(code, 0, out + err)
        self.assertNotIn(_CANNOT_RUN, self._problems())


    def test_status_walks_the_hooks_folders_once(self):
        self._copies_calling(self.module)
        self._seed()
        with mock.patch.object(hookscript, "hook_folders", wraps=hookscript.hook_folders) as walked:
            self.assertIn(_CANNOT_RUN, self._problems())
        self.assertEqual(walked.call_count, 1)

    def test_a_seeded_repository_whose_hooks_run_from_a_folder_of_the_persons_is_repaired(self):
        mine = self.home / "my-hooks"
        mine.mkdir()
        self._copies_calling(self.module, mine)
        self._seeded_with_hooks_in(mine)
        self.assertEqual(self._problems()[_CANNOT_RUN]["repair"], "saw hook repair")
        code, out, err = _split(hook.repair, no_stream=True)
        self.assertEqual(code, 0, out + err)
        self._all_put_back(mine)
        self.assertEqual(self._problems().keys() & {_CANNOT_RUN, _LEFT}, set())

    def test_a_seeded_repository_whose_hooks_path_names_its_own_hooks_folder_is_repaired(self):
        self._copies_calling(self.module)
        self._seeded_with_hooks_in(self.hooks)
        self.assertEqual(self._problems()[_CANNOT_RUN]["repair"], "saw hook repair")
        code, out, err = _split(hook.repair, no_stream=True)
        self.assertEqual(code, 0, out + err)
        self._all_put_back(self.hooks)
        self.assertNotIn(_CANNOT_RUN, self._problems())

    def test_a_folder_repair_does_not_write_is_named_with_why_and_left_as_it_is(self):
        husky = self.repo / ".husky"
        husky.mkdir()
        self._copies_calling(self.module, husky)
        changed = husky / "post-merge"
        changed.write_text(changed.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        self._seeded_with_hooks_in(".husky")
        found = self._problems()
        self.assertEqual(found.keys() & {_CANNOT_RUN, "altered-hooks"}, set())
        self.assertEqual(found[_LEFT]["repair"], "")
        self.assertIn(f"{len(hookscript.HOOKS)} of saw's hook file(s)", found[_LEFT]["message"])
        self.assertIn("see `saw audit`", found[_LEFT]["message"])
        self.assertIn("it lies inside a git working tree. Correct that, then run `saw hook repair`.",
                      found[_LEFT]["message"])
        before = {path.name: path.read_text() for path in husky.iterdir()}
        code, out, err = _split(hook.repair, no_stream=True)
        self.assertEqual(code, 3, out + err)
        self.assertIn("were not rewritten: it lies inside a git working tree", out + err)
        self.assertEqual({path.name: path.read_text() for path in husky.iterdir()}, before)

    def test_a_recorded_hooks_folder_repair_refuses_is_rewritten_once_corrected(self):
        folder = self.home / "every-repository-hooks"
        folder.mkdir()
        self._copies_calling(self.module, folder)
        saw, config = hookscript.installed()
        self.assertTrue(hookscript.declare(saw, config, hookscript.installed_into(), [folder]))
        os.chmod(folder, 0o775)
        found = self._problems()
        self.assertNotIn(_CANNOT_RUN, found)
        self.assertIn("it can be written by others", found[_LEFT]["message"])
        os.chmod(folder, 0o755)
        found = self._problems()
        self.assertNotIn(_LEFT, found)
        self.assertEqual(found[_CANNOT_RUN]["repair"], "saw hook repair")
        code, out, err = _split(hook.repair, no_stream=True)
        self.assertEqual(code, 0, out + err)
        self._all_put_back(folder)
        self.assertNotIn(_CANNOT_RUN, self._problems())

    def test_a_recorded_saw_that_cannot_run_is_named_once(self):
        self._copies_calling(self.saw)
        os.chmod(self.saw, 0o644)
        self._in_repo(self.repo)
        found = self._problems(standing_in=True)
        self.assertIn("stale-binary-path", found)
        self.assertNotIn(_CANNOT_RUN, found)
        other = self.hooks / "post-merge"
        other.write_text(hookscript.render("post-merge", str(self.module), None))
        self.assertIn("1 of saw's hook file(s)", self._problems(standing_in=True)[_CANNOT_RUN]["message"])

    def test_without_a_record_they_are_named_with_the_commands_that_put_them_back(self):
        self._copies_calling(self.module)
        hookscript.declaration_path().unlink()
        self._in_repo(self.repo)
        found = self._problems(standing_in=True)[_CANNOT_RUN]
        self.assertEqual(found["repair"], "saw hook install && saw hook repair")
        self.assertIn("Run `saw hook install`, then `saw hook repair`.", found["message"])
        with mock.patch.object(hook, "_saw_executable", return_value=str(self.saw)):
            for command in (hook.install, hook.repair):
                code, out, err = _split(command, no_stream=True, standing_in=True)
                self.assertEqual(code, 0, out + err)
        self._all_put_back(self.hooks)
        self.assertNotIn(_CANNOT_RUN, self._problems(standing_in=True))

    def test_a_bare_saw_is_looked_for_on_the_path(self):
        self._copies_calling("saw-on-the-path")
        self._seed()
        self.assertIsNone(shutil.which("saw-on-the-path"))
        self.assertIn(_CANNOT_RUN, self._problems())
        found_at = self._program(self.home / "on-the-path" / "saw-on-the-path").parent
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join([str(found_at), os.environ["PATH"]])}):
            self.assertNotIn(_CANNOT_RUN, self._problems())

    def test_a_relative_saw_is_taken_from_the_repository_its_hooks_run_in(self):
        self._copies_calling("bin/saw")
        self._seed()
        self.assertIn(_CANNOT_RUN, self._problems())
        self._program(self.repo / "bin" / "saw")
        self.assertNotEqual(os.path.realpath(os.getcwd()), os.path.realpath(self.repo))
        self.assertNotIn(_CANNOT_RUN, self._problems())


if __name__ == "__main__":
    unittest.main()

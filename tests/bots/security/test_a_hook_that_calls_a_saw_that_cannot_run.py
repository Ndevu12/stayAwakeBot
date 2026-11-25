#!/usr/bin/env python3
"""`saw hook status` names saw's hooks that call a saw that cannot run, in the repository it runs in
and in every repository saw keeps current, and `saw hook repair` rewrites them to call one that runs."""
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
from tests.bots.security.test_hook import _Isolated, _repo, _set_aside

_CANNOT_RUN = "hook-copy-cannot-run"


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

    def _copies_calling(self, saw: Path) -> None:
        for event in hookscript.HOOKS:
            path = self.hooks / event
            path.write_text(hookscript.render(event, str(saw), None))
            os.chmod(path, 0o755)

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


if __name__ == "__main__":
    unittest.main()

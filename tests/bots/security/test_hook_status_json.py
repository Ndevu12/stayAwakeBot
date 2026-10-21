#!/usr/bin/env python3
"""`saw hook status --json` is the same account as the report, and install and repair print it after
they run."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import unittest
from unittest import mock

from stayawake.bots.security import hook, hookscript
from stayawake.cli.commands.hook import run_install, run_repair, run_status
from stayawake.utils.json_documents import SCHEMA_VERSION_OF_EACH_DOCUMENT
from tests.bots.security.test_hook import _Isolated


def _split(fn, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args, **kwargs)
    return code, out.getvalue(), err.getvalue()


def _document(out: str) -> dict:
    return json.loads(out)


class TestHookStatusJson(_Isolated):
    def _places(self) -> list[str]:
        return [str(hook._hooks_dir()), str(hook.template_dir()), str(hookscript.set_aside_dir()),
                str(hookscript.cache_path()), str(hookscript.declaration_path())]

    def test_a_caller_that_omits_json_gets_the_report(self):
        code, out, err = _split(hook.status)
        self.assertEqual(code, 0)
        self.assertIn("scan-on-clone:", out)
        self.assertNotIn("schema_version", out + err)
        code, out, err = _split(run_status, argparse.Namespace(no_stream=True))
        self.assertEqual(code, 0)
        self.assertIn("scan-on-clone:", out)
        self.assertNotIn("{", out)

    def test_the_document_says_what_the_report_says(self):
        self.assertEqual(hook.install(no_stream=True), 0)
        code, out, err = _split(hook.status, as_json=True, no_stream=True)
        doc = _document(out)
        self.assertEqual(code, 0)
        self.assertEqual(next(iter(doc)), "schema_version")
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT["hook-status"])
        self.assertIs(doc["installed"], True)
        self.assertNotIn("changed", doc)
        listed = err.split("(", 1)[1].split(")", 1)[0]
        self.assertEqual(doc["events"], [event.strip() for event in listed.split(",") if event.strip()])
        self.assertIn("template", doc["via"])
        self.assertIs(doc["disabled_by_env"], False)
        codes = [item["code"] for item in doc["problems"]]
        self.assertIn("older-git", codes)
        for item in doc["problems"]:
            self.assertIn(item["message"], err)
            self.assertIsInstance(item["repair"], str)
        for place in self._places():
            self.assertNotIn(place, out)

    def test_a_git_that_runs_settings_hooks_is_not_called_old(self):
        self.assertEqual(hook.install(no_stream=True), 0)
        with mock.patch.object(hook, "git_runs_settings_hooks", return_value=True):
            code, out, err = _split(hook.status, as_json=True, no_stream=True)
        self.assertEqual(code, 0)
        self.assertNotIn("older-git", [item["code"] for item in _document(out)["problems"]])
        self.assertNotIn("update git to 2.54", err)

    def test_each_warning_keeps_its_code(self):
        self.assertEqual(hook.install(no_stream=True), 0)
        hookscript.declaration_path().unlink()
        _code, out, err = _split(hook.status, as_json=True, no_stream=True)
        missing = next(item for item in _document(out)["problems"] if item["code"] == "no-record")
        self.assertEqual(missing["repair"], "saw hook install")
        self.assertIn(missing["message"], err)
        gone = self.home / "gone" / "saw"
        hookscript.declaration_path().write_text(json.dumps({"saw": str(gone), "config": None}))
        hook_file = hook._hooks_dir() / "post-checkout"
        hook_file.write_text(hook_file.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        os.environ["SAW_HOOK_DISABLED"] = "1"
        self.addCleanup(os.environ.pop, "SAW_HOOK_DISABLED", None)
        with mock.patch.object(hook, "_hookspath_git_uses", return_value=(False, None)):
            code, out, err = _split(hook.status, as_json=True, no_stream=True)
        doc = _document(out)
        self.assertEqual(code, 0)
        by_code = {item["code"]: item for item in doc["problems"]}
        self.assertEqual(by_code["stale-binary-path"]["repair"], "saw hook repair")
        self.assertEqual(by_code["altered-hooks"]["repair"], "saw hook repair")
        self.assertIn("file(s)", by_code["altered-hooks"]["message"])
        self.assertIn("SAW_HOOK_DISABLED", by_code["disabled-by-env"]["message"])
        self.assertIs(doc["disabled_by_env"], True)
        self.assertEqual(by_code["hooks-path-unread"]["repair"],
                         "git config --global --get core.hooksPath")
        for item in doc["problems"]:
            self.assertIn(item["message"], err)
        self.assertNotIn(str(gone), out)

    def test_a_missing_config_is_named(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist:\n  - {signature: some-rule, path_glob: 'docs/**'}\n")
        self.assertEqual(hook.install(str(cfg), no_stream=True), 0)
        cfg.unlink()
        _code, out, err = _split(hook.status, as_json=True, no_stream=True)
        item = next(p for p in _document(out)["problems"] if p["code"] == "config-gone")
        self.assertEqual(item["repair"], "saw hook install -c <your config>")
        self.assertIn(item["message"], err)
        self.assertNotIn(str(cfg), out)

    def test_a_failed_install_still_prints_the_document(self):
        cfg = self.home / "security.yml"
        cfg.write_text("allowlist: [\n  - {\n")
        code, out, err = _split(hook.install, str(cfg), no_stream=True, as_json=True)
        self.assertEqual(code, 2)
        doc = _document(out)
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION_OF_EACH_DOCUMENT["hook-status"])
        self.assertEqual(doc["changed"], [])
        self.assertIn("cannot be read", err)
        self.assertNotIn("schema_version", err)

    def test_install_and_repair_print_the_document_and_what_changed(self):
        code, out, err = _split(hook.install, no_stream=True, as_json=True)
        doc = _document(out)
        self.assertEqual(code, 0, err)
        self.assertIs(doc["installed"], True)
        self.assertTrue(any("scan-on-clone installed" in line for line in doc["changed"]))
        self.assertIn("scan-on-clone installed", err)
        self.assertNotIn("schema_version", err)
        for place in self._places():
            self.assertNotIn(place, out)
        hook_file = hook._hooks_dir() / "post-merge"
        hook_file.write_text(hook_file.read_text().replace("exit 0\n", "/tmp/.x/stage\nexit 0\n"))
        code, out, err = _split(hook.repair, no_stream=True, as_json=True)
        doc = _document(out)
        self.assertEqual(code, 0, err)
        self.assertTrue(any("had been changed" in line for line in doc["changed"]), doc["changed"])
        self.assertIn("had been changed", err)
        cwd = os.getcwd()
        os.chdir(self.home)
        self.addCleanup(os.chdir, cwd)
        plain = argparse.Namespace(config=None, paths=[], no_stream=True)
        code, out, err = _split(run_install, plain)
        self.assertNotIn("schema_version", out)
        self.assertIn("scan-on-clone", out + err)
        code, out, _err = _split(run_repair, argparse.Namespace(no_stream=True))
        self.assertNotIn("schema_version", out)

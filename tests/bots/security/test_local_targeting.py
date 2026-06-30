#!/usr/bin/env python3
"""Local-path targeting: explicit paths / CWD default for `saw scan`.

Targets (what to scan) are orthogonal to auth (how to access): local scanning needs
no token. These tests pin the target-resolution precedence and the config/CWD
fallbacks without running a real (slow, self-flagging) scan — discover_local_repos
and _resolve_remote are stubbed to capture what they're asked to scan.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stayawake.bots.security import service as svc


class TestTargetResolution(unittest.TestCase):
    def _capture(self, **scan_kwargs) -> dict:
        cap: dict = {}

        def fake_discover(patterns, opts):
            cap["patterns"] = patterns
            return []

        def fake_remote(cfg, opts, **kw):
            cap["remote_called"] = True
            cap["remote_kw"] = kw   # users/orgs/slugs selectors (the #1075 ladder inputs)
            return [], None, None   # mirror _resolve_remote's (slugs, token, source) 3-tuple

        with mock.patch.object(svc, "discover_local_repos", side_effect=fake_discover), \
             mock.patch.object(svc, "_resolve_remote", side_effect=fake_remote):
            out = Path(tempfile.mkdtemp())
            svc.scan(reports_dir=str(out), **scan_kwargs)
        return cap

    def _cfg(self, body: str) -> str:
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text(body, encoding="utf-8")
        return str(cfg)

    def test_explicit_paths_scan_local(self):
        cap = self._capture(config_path=None, paths=["/tmp/a", "/tmp/b"])
        self.assertEqual(cap["patterns"], ["/tmp/a", "/tmp/b"])
        self.assertNotIn("remote_called", cap)  # explicit paths ⇒ local, no token

    def test_config_local_globs_used(self):
        cap = self._capture(config_path=self._cfg('settings: {}\ntargets: { local: ["~/dev/**"] }\n'))
        self.assertEqual(cap["patterns"], ["~/dev/**"])

    def test_cwd_default_when_nothing_configured(self):
        cap = self._capture(config_path=self._cfg("settings: {}\ntargets: { local: [] }\n"))
        self.assertEqual(cap["patterns"], [str(svc._enclosing_repo_root())])

    def test_default_scope_is_local_even_with_github_configured(self):
        # #1069: scope is LOCAL by default — a configured GitHub target is NOT scanned
        # unless `--remote` (remote=True) is given.
        cfg = self._cfg("settings: {}\ntargets:\n  local: []\n  github: { users: [octocat] }\n")
        cap = self._capture(config_path=cfg)                      # no remote=True
        self.assertNotIn("remote_called", cap)                   # GitHub NOT enumerated
        self.assertEqual(cap["patterns"], [str(svc._enclosing_repo_root())])  # cwd fallback

    def test_remote_scope_scans_github_not_local(self):
        cfg = self._cfg("settings: {}\ntargets:\n  github: { users: [octocat] }\n")
        cap = self._capture(config_path=cfg, remote=True)
        self.assertTrue(cap.get("remote_called"))                # remote enumerated
        self.assertNotIn("patterns", cap)                       # local discovery NOT run


class TestHelpers(unittest.TestCase):
    def test_enclosing_repo_root_finds_root_from_subdir(self):
        repo = Path(tempfile.mkdtemp())
        (repo / ".git").mkdir()
        sub = repo / "src" / "deep"
        sub.mkdir(parents=True)
        self.assertEqual(svc._enclosing_repo_root(sub), repo.resolve())

    def test_enclosing_repo_root_falls_back_to_start(self):
        plain = Path(tempfile.mkdtemp())  # no .git anywhere under tmp
        self.assertEqual(svc._enclosing_repo_root(plain), plain.resolve())

    def test_read_config_default_missing_is_empty_but_explicit_missing_raises(self):
        # explicit but missing path → hard error (don't silently scan nothing)
        with self.assertRaises(FileNotFoundError):
            svc._read_config("/no/such/security.yml")
        # default (None) with no config file present → empty config, no error
        cwd = os.getcwd()
        tmp = tempfile.mkdtemp()
        try:
            os.chdir(tmp)
            self.assertEqual(svc._read_config(None), {})
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()

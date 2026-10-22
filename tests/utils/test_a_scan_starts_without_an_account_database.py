#!/usr/bin/env python3
"""`saw scan` starts where this system has no account database."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


_PROGRAM = textwrap.dedent("""\
    import builtins
    import os
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    folder = tempfile.mkdtemp(prefix="saw-scan-")
    Path(folder, "readme.txt").write_text("hello\\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", folder], check=True)
    os.environ["HOME"] = folder
    os.environ["USERPROFILE"] = folder
    os.environ["SAW_AUTORUN_BASELINE"] = str(Path(folder) / "baseline.json")

    real = builtins.__import__

    def block(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "pwd":
            raise ImportError("No module named 'pwd'")
        return real(name, globals, locals, fromlist, level)

    builtins.__import__ = block
    for missing in ("getuid", "geteuid"):
        if hasattr(os, missing):
            delattr(os, missing)

    import stayawake.cli
    from stayawake.cli.dispatch import main
    sys.argv = ["saw", "scan", folder, "--json", "--no-stream", "--no-advisories"]
    raise SystemExit(main())
""")


class TestAScanStartsWithoutAnAccountDatabase(unittest.TestCase):
    def test_a_folder_scan_prints_a_report(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(sys.path)
        with tempfile.TemporaryDirectory(prefix="saw-scan-out-") as out:
            completed = subprocess.run(
                [sys.executable, "-c", _PROGRAM],
                cwd=out, env=env, capture_output=True, text=True, timeout=180)
        self.assertNotIn("Traceback", completed.stderr)
        self.assertNotIn("ModuleNotFoundError", completed.stderr)
        self.assertNotIn("AttributeError", completed.stderr)
        report = json.loads(completed.stdout)
        self.assertIn("schema_version", report)
        self.assertFalse(report["any_error"])
        self.assertIn(completed.returncode, (0, 1))


if __name__ == "__main__":
    unittest.main()

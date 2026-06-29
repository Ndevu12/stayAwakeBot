#!/usr/bin/env python3
"""Output sinks + redaction + the exit-code verdict.

Asserts the core promises of the terminal-first redesign:
  * TerminalSink / JsonSink show FULL evidence (ephemeral surfaces); stdout stays clean.
  * FileSink (and SARIF, covered in test_sarif) REDACT evidence in persisted artifacts.
  * a bare scan persists NOTHING; files appear only when a file sink is asked for.
  * the verdict is the exit code (1 infected / 0 clean), unconditionally.
"""
from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from stayawake.bots.security import redaction, service as sec_service
from stayawake.bots.security.models import Finding, ScanResult, ScanReport, Severity
from stayawake.bots.security.sinks import TerminalSink, JsonSink, FileSink
from stayawake.bots.security.sinks.render import render_terminal

PAYLOAD = "String.fromCharCode(127)_EVIL_" + ("Z" * 80) + "_TAIL"


def _report():
    f = Finding(signature_id="loader-fromcharcode", category="code-loader",
                severity=Severity.CRITICAL, path="postcss.config.mjs",
                description="obfuscated loader", line=1, evidence=PAYLOAD,
                confidence="confirmed")
    return ScanReport(generated_at="t",
                      results=[ScanResult(target="myrepo", source="local", findings=[f])])


class TestRedaction(unittest.TestCase):
    def test_empty_is_none(self):
        self.assertIsNone(redaction.redact(None))
        self.assertIsNone(redaction.redact(""))

    def test_fingerprint_shape(self):
        r = redaction.redact("abc")
        self.assertEqual(len(r["sha256"]), 64)
        self.assertEqual(r["preview"], "abc")
        self.assertEqual(r["len"], 3)

    def test_preview_truncates(self):
        r = redaction.redact(PAYLOAD)
        self.assertEqual(len(r["preview"]), redaction.PREVIEW_LEN)
        self.assertNotIn("_TAIL", r["preview"])         # never the full payload

    def test_redact_payload_keeps_other_fields(self):
        out = redaction.redact_payload(_report().to_payload())
        f = out["results"][0]["findings"][0]
        self.assertEqual(f["signature_id"], "loader-fromcharcode")
        self.assertIsInstance(f["evidence"], dict)      # replaced by a fingerprint
        self.assertIn("sha256", f["evidence"])


class TestTerminalSink(unittest.TestCase):
    def test_full_evidence_to_stdout(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            TerminalSink(enabled=False).emit(_report())
        out = buf.getvalue()
        self.assertIn("Security scan", out)
        self.assertIn(PAYLOAD, out)                     # terminal shows full evidence
        self.assertNotIn("|---", out)                   # aligned table, not raw markdown pipes

    def test_table_lists_all_targets_and_details_findings(self):
        clean = ScanResult(target="~/clean-repo", source="local", findings=[])
        susp = ScanResult(target="~/susp-repo", source="local", findings=[
            Finding(signature_id="oversized-config-line", category="code-loader",
                    severity=Severity.MEDIUM, path="x.js", description="big line",
                    line=1, evidence="A" * 50, confidence="heuristic")])
        report = ScanReport(generated_at="t",
                            results=[_report().results[0], susp, clean])
        buf = io.StringIO()
        with redirect_stdout(buf):
            TerminalSink(enabled=False).emit(report)
        out = buf.getvalue()
        # EVERY scanned target appears in the table, clean included.
        self.assertIn("~/clean-repo", out)
        self.assertIn("clean", out)
        self.assertIn("INFECTED", out)
        # findings are enumerated for both infected and suspect repos.
        self.assertIn("loader-fromcharcode", out)
        self.assertIn("oversized-config-line", out)

    def test_color_only_when_requested(self):
        payload = _report().to_payload()
        self.assertIn("\033[1;31m", render_terminal(payload, color=True))   # INFECTED red
        self.assertNotIn("\033[", render_terminal(payload, color=False))    # plain by default


class TestJsonSink(unittest.TestCase):
    def test_pure_json_full_evidence(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            JsonSink().emit(_report())
        out = buf.getvalue()
        self.assertTrue(out.lstrip().startswith("{"))   # stdout is ONLY the JSON
        data = json.loads(out)                          # …and it parses
        self.assertEqual(data["results"][0]["findings"][0]["evidence"], PAYLOAD)


class TestFileSink(unittest.TestCase):
    def test_persisted_bundle_is_redacted(self):
        d = Path(tempfile.mkdtemp())
        with redirect_stderr(io.StringIO()):
            FileSink(d).emit(_report())
        text = (d / "latest.json").read_text(encoding="utf-8")
        self.assertNotIn(PAYLOAD, text)                 # never persist the raw payload
        self.assertIn("sha256", text)
        self.assertIn("sha256:", (d / "latest.md").read_text(encoding="utf-8"))


class TestExitCodeVerdict(unittest.TestCase):
    """Integration: the scan's exit code is the verdict, with no --fail flag."""

    def _git_repo(self, seed: Path | None = None) -> Path:
        repo = Path(tempfile.mkdtemp())
        if seed:
            for p in seed.iterdir():
                dest = repo / p.name
                if p.is_dir():
                    __import__("shutil").copytree(p, dest)
                else:
                    dest.write_bytes(p.read_bytes())
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        # Discovery only needs a .git dir; commit only when there is something to commit.
        if seed:
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t",
                            "-c", "user.name=t", "commit", "-qm", "x"], check=True)
        return repo

    def _scan(self, repo: Path) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return sec_service.scan(None, paths=[str(repo)], no_stream=True)

    def test_infected_exits_1(self):
        seed = Path(__file__).parent / "fixtures" / "infected"
        self.assertEqual(self._scan(self._git_repo(seed)), 1)

    def test_clean_exits_0(self):
        self.assertEqual(self._scan(self._git_repo()), 0)


if __name__ == "__main__":
    unittest.main()

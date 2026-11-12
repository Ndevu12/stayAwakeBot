#!/usr/bin/env python3
"""The worm's `.gitignore` tampering: a `config.bat` marker it adds, and an environment-variable
section it leaves without a `.env` ignore so committed secrets slip through."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions

SIGS = load_signatures()


def _ids(files: dict) -> set:
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        (d / rel).write_bytes(content)
    return {f.signature_id for f in scan_target(LocalRepoTarget(d, "t", ScanOptions()), SIGS, []).findings}


class TestGitignoreWormTampering(unittest.TestCase):
    def test_the_config_bat_marker_is_flagged(self):
        self.assertIn("gitignore-autopush-markers", _ids({".gitignore": b"# notes\nconfig.bat\n"}))

    def test_an_env_section_without_dot_env_is_flagged_lf_and_crlf(self):
        lf = b"# dependencies\n/node_modules\n\n# environmental variables\n\nconfig.bat\n"
        crlf = b"# dependencies\r\n/node_modules\r\n\r\n# environment variables\r\n\r\nother\r\n"
        self.assertIn("gitignore-unignored-env", _ids({".gitignore": lf}))
        self.assertIn("gitignore-unignored-env", _ids({".gitignore": crlf}))

    def test_a_normal_gitignore_that_ignores_dot_env_is_clean(self):
        for ok in (b"# environment variables\n.env\n.env.local\n",
                   b"# environment variables\r\n.env\r\n.env.*.local\r\n",
                   b"# dependencies\n/node_modules\n/build\n"):
            ids = _ids({".gitignore": ok})
            self.assertNotIn("gitignore-unignored-env", ids, ok)
            self.assertNotIn("gitignore-autopush-markers", ids, ok)


if __name__ == "__main__":
    unittest.main()

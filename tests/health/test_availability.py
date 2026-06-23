#!/usr/bin/env python3
"""Availability unit tests (config merge, badge, uptime) — no network."""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from health.config import merge_settings          # noqa: E402
from health.reporter import compute_uptime        # noqa: E402
from shared.adapters.badge import update_readme_badge          # noqa: E402


class TestConfig(unittest.TestCase):
    def test_url_overrides_global(self):
        cfg = merge_settings({"timeout_seconds": 10, "retries": 2},
                             {"name": "x", "url": "https://x", "timeout_seconds": 5})
        self.assertEqual(cfg.timeout_seconds, 5)   # per-URL override
        self.assertEqual(cfg.retries, 2)           # inherited global


class TestUptime(unittest.TestCase):
    def test_uptime_percent(self):
        now = datetime.now(timezone.utc)
        history = [
            {"generated_at": now.isoformat(), "urls": [{"name": "a", "healthy": True}]},
            {"generated_at": now.isoformat(), "urls": [{"name": "a", "healthy": False}]},
        ]
        self.assertEqual(compute_uptime("a", history, now - timedelta(days=30)), 50.0)


class TestBadge(unittest.TestCase):
    def test_badge_inserted_and_colored(self):
        p = Path(tempfile.mkdtemp()) / "README.md"
        p.write_text("# Title\n")
        update_readme_badge(p, 2, 2)
        txt = p.read_text()
        self.assertIn("STAYAWAKEBOT_BADGE", txt)
        self.assertIn("brightgreen", txt)
        update_readme_badge(p, 1, 2)
        self.assertIn("-red", p.read_text())


if __name__ == "__main__":
    unittest.main()

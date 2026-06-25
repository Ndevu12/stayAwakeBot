#!/usr/bin/env python3
"""Availability unit tests (config merge, uptime) — no network."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta


from stayawake.bots.health.config import merge_settings          # noqa: E402
from stayawake.bots.health.reporter import compute_uptime        # noqa: E402


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


if __name__ == "__main__":
    unittest.main()

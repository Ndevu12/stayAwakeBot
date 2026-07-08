#!/usr/bin/env python3
"""Availability config unit test — no network. (Reporting/uptime deleted in #1149; status lives in
the single dashboard issue, exercised by test_alerter.)"""
from __future__ import annotations

import unittest

from stayawake.bots.health.config import merge_settings


class TestConfig(unittest.TestCase):
    def test_url_overrides_global(self):
        cfg = merge_settings({"timeout_seconds": 10, "retries": 2},
                             {"name": "x", "url": "https://x", "timeout_seconds": 5})
        self.assertEqual(cfg.timeout_seconds, 5)   # per-URL override
        self.assertEqual(cfg.retries, 2)           # inherited global


if __name__ == "__main__":
    unittest.main()

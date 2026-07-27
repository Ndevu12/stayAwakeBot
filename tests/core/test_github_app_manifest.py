#!/usr/bin/env python3
"""StayAwakeBot App manifest branding + install URL helpers."""
from __future__ import annotations

import unittest

from stayawake.lib import github_app_manifest as manifest


class TestManifestBranding(unittest.TestCase):
    def test_default_name_is_stayawakebot(self):
        m = manifest.build_manifest(
            redirect_url="http://127.0.0.1:9/callback",
            setup_url="http://127.0.0.1:9/setup",
        )
        self.assertEqual(m["name"], "StayAwakeBot")
        self.assertIn("setup_url", m)
        self.assertEqual(m["setup_url"], "http://127.0.0.1:9/setup")
        self.assertIn("operator-managed", m["description"].lower())
        self.assertNotIn("deferred", m["description"].lower())
        self.assertNotIn("1277", m["description"])

    def test_icon_ships_with_package(self):
        path = manifest.app_icon_path()
        self.assertIsNotNone(path)
        self.assertTrue(path.is_file())
        self.assertGreater(path.stat().st_size, 1000)

    def test_install_and_settings_urls(self):
        self.assertEqual(manifest.install_url("stayawakebot"),
                         "https://github.com/apps/stayawakebot/installations/new")
        self.assertEqual(manifest.settings_url("stayawakebot"),
                         "https://github.com/settings/apps/stayawakebot")


class TestAppExtraHint(unittest.TestCase):
    def test_hint_uses_distribution_name(self):
        from stayawake.lib import github_app
        self.assertIn("stayawakebot[app]", github_app.APP_EXTRA_HINT)
        self.assertNotIn("stayawake[app]", github_app.APP_EXTRA_HINT)


if __name__ == "__main__":
    unittest.main()

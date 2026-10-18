#!/usr/bin/env python3
"""GitHub's list of an account's SSH signing keys is read as the keys it holds."""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.lib.adapters import github_api


class TestTheAccountsSigningKeysAreListed(unittest.TestCase):
    def test_each_key_github_returns_is_listed(self):
        answer = [{"id": 1, "key": "ssh-ed25519 AAAA", "title": "laptop"}, {"id": 2}]
        with mock.patch.object(github_api, "request", return_value=answer) as asked:
            self.assertEqual(github_api.list_ssh_signing_keys("your user", "t"), ["ssh-ed25519 AAAA"])
        self.assertIn("/users/your%20user/ssh_signing_keys", asked.call_args.args[0])

    def test_an_unanswered_request_lists_nothing(self):
        with mock.patch.object(github_api, "request", return_value=None):
            self.assertIsNone(github_api.list_ssh_signing_keys("your-user", "t"))


if __name__ == "__main__":
    unittest.main()

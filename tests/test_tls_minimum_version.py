#!/usr/bin/env python3
"""Every TLS context saw builds refuses the retired TLS 1.0/1.1 protocols (CodeQL py/insecure-protocol)."""
from __future__ import annotations

import ssl
import unittest
from unittest import mock

from stayawake.bots.security.dependencies import db
from stayawake.lib.adapters import github_api, http_client


class TlsContextsRequireTls12(unittest.TestCase):
    def test_the_verified_api_and_corpus_contexts_pin_tls12(self):
        self.assertEqual(db._SSL_CTX.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(github_api._SSL_CTX.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_the_certificate_probe_context_pins_tls12(self):
        ctx = ssl.create_default_context()
        with mock.patch.object(http_client.ssl, "create_default_context", return_value=ctx), \
             mock.patch.object(http_client.socket, "create_connection", side_effect=OSError("no net")):
            http_client.get_cert_info_blocking("example.test", 443, 1)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()

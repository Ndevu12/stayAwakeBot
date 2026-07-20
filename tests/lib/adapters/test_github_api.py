#!/usr/bin/env python3
"""github_api typed read outcomes (#1243) — read_dir/read_file surface the failure CAUSE
(not_found/unauthorized/forbidden/rate_limited/network), instead of a bare None that conflates
'the repo has no CI' (404) with a real auth failure."""
from __future__ import annotations

import base64
import io
import time
import unittest
import urllib.error
from unittest import mock

from stayawake.lib.adapters import github_api as g


def _http(code, headers=None):
    return urllib.error.HTTPError("https://api.github.com/x", code, "err",
                                  headers or {}, io.BytesIO(b"{}"))


class _Resp:                                   # a urlopen() context manager returning `body`
    def __init__(self, body): self._b = body
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self): return self._b


class TestReadDirClassification(unittest.TestCase):
    def _dir(self, side_effect):
        with mock.patch("urllib.request.urlopen", side_effect=side_effect):
            return g.read_dir("o", "r", ".github/workflows", "tok")

    def test_success_returns_the_list(self):
        with mock.patch("urllib.request.urlopen",
                        return_value=_Resp(b'[{"name":"w.yml","type":"file","path":"x"}]')):
            r = g.read_dir("o", "r", ".github/workflows", "tok")
        self.assertIsNone(r.cause)
        self.assertEqual(r.value[0]["name"], "w.yml")

    def test_404_is_not_found(self):
        self.assertEqual(self._dir(_http(404)).cause, "not_found")

    def test_401_is_unauthorized(self):
        self.assertEqual(self._dir(_http(401)).cause, "unauthorized")

    def test_403_without_ratelimit_is_forbidden(self):
        self.assertEqual(self._dir(_http(403, {"x-ratelimit-remaining": "37"})).cause, "forbidden")

    def test_403_exhausted_is_rate_limited_with_retry(self):
        reset = int(time.time()) + 25
        r = self._dir(_http(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset)}))
        self.assertEqual(r.cause, "rate_limited")
        self.assertIsNotNone(r.retry_after)
        self.assertLessEqual(r.retry_after, 25)

    def test_network_error_is_network(self):
        self.assertEqual(self._dir(OSError("dns fail")).cause, "network")

    def test_a_file_at_a_dir_path_is_not_found(self):
        with mock.patch("urllib.request.urlopen", return_value=_Resp(b'{"type":"file"}')):
            self.assertEqual(g.read_dir("o", "r", "somefile", "tok").cause, "not_found")


class TestReadFile(unittest.TestCase):
    def test_decodes_base64_on_success(self):
        content = base64.b64encode(b"hello").decode()
        body = ('{"encoding":"base64","content":"%s"}' % content).encode()
        with mock.patch("urllib.request.urlopen", return_value=_Resp(body)):
            r = g.read_file("o", "r", "f", "tok")
        self.assertIsNone(r.cause)
        self.assertEqual(r.value, "hello")

    def test_surfaces_cause_on_failure(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http(401)):
            self.assertEqual(g.read_file("o", "r", "f", "tok").cause, "unauthorized")


class TestValueWrappersUnchanged(unittest.TestCase):
    def test_list_dir_still_value_or_none(self):
        with mock.patch("urllib.request.urlopen", side_effect=_http(404)):
            self.assertIsNone(g.list_dir("o", "r", "x", "tok"))
        with mock.patch("urllib.request.urlopen", return_value=_Resp(b'[]')):
            self.assertEqual(g.list_dir("o", "r", "x", "tok"), [])


if __name__ == "__main__":
    unittest.main()

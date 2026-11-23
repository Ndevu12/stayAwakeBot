"""saw-platform chooses a proxy exactly as main does and sends requests through the system's curl
without putting anything from them on a command line."""
import itertools
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
CURL = "/usr/bin/curl"


def main_proxy(host, pairs):
    """Run urllib's own proxy handler for an https request to `host` under `pairs`."""
    with mock.patch.object(os, "environ", dict(pairs)):
        proxies = urllib.request.getproxies_environment()
        if "https" not in proxies:
            return None
        request = urllib.request.Request(f"https://{host}/x")
        try:
            urllib.request.ProxyHandler(proxies).proxy_open(request, proxies["https"], "https")
        except ValueError:
            return {"error": True}
    if request._tunnel_host is None:
        return None
    return [request.host, request.headers.get("Proxy-authorization")]


class Recorder:
    """A proxy on this machine that records the first request it is sent and refuses it."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.port = self.server.getsockname()[1]
        self.seen = b""
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            self.server.settimeout(10)
            connection, _ = self.server.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(5)
            while b"\r\n\r\n" not in self.seen:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                self.seen += chunk
            connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    def close(self):
        self.server.close()


def closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@unittest.skipUnless(shutil.which("cargo") and os.path.exists(CURL), "needs cargo and the system curl")
class NetworkMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "network_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "network_probe"

    def ask(self, cases):
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True, timeout=120).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        return [json.loads(line) for line in printed]

    def test_the_proxy_chosen_for_each_environment(self):
        p = "http://proxy.test:3128"
        envs = [[], [["https_proxy", p]], [["HTTPS_PROXY", "proxy.test:1"]], [["HTTPS_PROXY", "a.test:1"], ["https_proxy", "b.test:2"]],
                [["https_proxy", "b.test:2"], ["HTTPS_PROXY", "a.test:1"]], [["https_proxy", ""], ["HTTPS_PROXY", "a.test:1"]],
                [["HTTPS_PROXY", "a.test:1"], ["https_proxy", ""]], [["ALL_PROXY", p]], [["all_proxy", p]], [["http_proxy", p]],
                [["HTTPS_PROXY", "http://user:pa%3Ass@proxy.test:8080/"]], [["HTTPS_PROXY", "http://user@proxy.test:8080"]],
                [["HTTPS_PROXY", "http://:pw@proxy.test"]], [["HTTPS_PROXY", "http:/bad"]], [["HTTPS_PROXY", "socks5://proxy.test:1080"]],
                [["HTTPS_PROXY", "https://u:p@[::1]:8443/x"]], [["HTTPS_PROXY", "proxy%41.test:1"]], [["HTTPS_PROXY", "u:p@h@proxy.test:1"]],
                [["HTTPS_PROXY", p], ["REQUEST_METHOD", "GET"]], [["Https_Proxy", p]], [["x_PROXY", "1"]], [["HTTPS_PROXY", "ü:ö@proxy.test:1"]]]
        no_proxies = ["*", "example.com", ".example.com", "EXAMPLE.com:443", " other , example.com", "ample.com", "example.com:8443", ",", ""]
        envs += [[["HTTPS_PROXY", p], [name, value]] for value in no_proxies for name in ("NO_PROXY", "no_proxy")]
        hosts = ["example.com", "api.example.com", "EXAMPLE.COM:443", "example.com:8443", "notexample.com", "127.0.0.1:9", ""]
        cases = [{"ask_about": "proxy", "host": h, "env": e} for e, h in itertools.product(envs, hosts)]
        for case, answer in zip(cases, self.ask(cases)):
            with self.subTest(case=case):
                self.assertEqual(answer, main_proxy(case["host"], case["env"]))

    def test_requests_through_the_system_curl(self):
        refused = closed_port()
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        key, cert = os.path.join(folder, "key.pem"), os.path.join(folder, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1",
                        "-subj", "/CN=127.0.0.1"], check=True, capture_output=True)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        def serve_tls():
            try:
                server.settimeout(10)
                connection, _ = server.accept()
                with context.wrap_socket(connection, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

        threading.Thread(target=serve_tls, daemon=True).start()
        recorder, bypassed = Recorder(), Recorder()
        self.addCleanup(recorder.close)
        self.addCleanup(bypassed.close)
        secret = [["Authorization", "Bearer secret-token-value"]]
        through = [["HTTPS_PROXY", f"http://u:p@127.0.0.1:{recorder.port}"]]
        around = [["HTTPS_PROXY", f"http://127.0.0.1:{bypassed.port}"], ["NO_PROXY", "127.0.0.1"]]
        cases = [{"ask_about": "fetch", "url": f"https://127.0.0.1:{refused}/", "env": []},
                 {"ask_about": "fetch", "url": f"https://127.0.0.1:{server.getsockname()[1]}/", "env": []},
                 {"ask_about": "fetch", "url": "https://example.test/x", "env": through, "headers": secret},
                 {"ask_about": "fetch", "url": f"https://127.0.0.1:{refused}/", "env": around},
                 {"ask_about": "fetch", "url": "http://example.test/", "env": []}]
        answers = self.ask(cases)
        self.assertEqual(answers[0], {"error": "failed", "code": 7})
        self.assertEqual(answers[1], {"error": "failed", "code": 60})
        self.assertEqual(answers[2]["error"], "failed")
        first, *headers = recorder.seen.decode("latin-1").split("\r\n")
        self.assertEqual(first, "CONNECT example.test:443 HTTP/1.1")
        sent = dict(line.split(": ", 1) for line in headers if ": " in line)
        self.assertEqual(sent.get("Proxy-Authorization"), main_proxy("example.test", through)[1])
        self.assertNotIn(b"secret-token-value", recorder.seen)
        self.assertEqual(answers[3], {"error": "failed", "code": 7})
        self.assertEqual(bypassed.seen, b"")
        self.assertEqual(answers[4], {"error": "NotHttps"})


if __name__ == "__main__":
    unittest.main()

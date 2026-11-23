"""saw-platform matches shell patterns and reads the macOS and Windows proxy settings exactly as
main does."""
import fnmatch
import itertools
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import textwrap
import types
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]


def scutil_text(settings):
    """Print settings the way `scutil --proxy` prints them."""
    lines = ["<dictionary> {"]
    for name, value in settings.items():
        if isinstance(value, list):
            lines.append(f"  {name} : <array> {{")
            lines += [f"    {i} : {item}" for i, item in enumerate(value)]
            lines.append("  }")
        else:
            lines.append(f"  {name} : {value}")
    lines += ["  __SCOPED__ : <dictionary> {", "    en0 : <dictionary> {", "      HTTPSEnable : 1",
              "      HTTPSProxy : scoped.test", "      ExceptionsList : <array> {", "        0 : scoped", "      }",
              "    }", "  }", "}"]
    return "\n".join(lines)


def scproxy(settings):
    """State what `_scproxy` returns for settings, from its C source."""
    proxies = {}
    for scheme, prefix in (("http", "HTTP"), ("https", "HTTPS"), ("ftp", "FTP"), ("gopher", "Gopher")):
        if settings.get(f"{prefix}Enable") and f"{prefix}Proxy" in settings:
            port = settings.get(f"{prefix}Port")
            host = settings[f"{prefix}Proxy"]
            proxies[scheme] = f"http://{host}:{port}" if port is not None else f"http://{host}"
    found = {"exclude_simple": bool(settings.get("ExcludeSimpleHostnames", 0))}
    if "ExceptionsList" in settings:
        found["exceptions"] = tuple(settings["ExceptionsList"])
    return proxies, found


def windows_functions(values):
    """Run main's own registry proxy functions against `values` in place of the registry."""
    source = open(urllib.request.__file__).read()
    start = source.index("    def getproxies_registry")
    end = source.index("    def proxy_bypass(host):", source.index("    def proxy_bypass_registry"))
    fake = types.ModuleType("winreg")
    fake.HKEY_CURRENT_USER = object()

    class Key:
        def Close(self):
            pass

    def query(_key, name):
        for key, value in values.items():
            if key.lower() == name.lower():
                return (value[1] if value[0] != "none" else None), 1
        raise FileNotFoundError(name)

    fake.OpenKey = lambda *_: Key()
    fake.QueryValueEx = query
    namespace = {"re": re, "_proxy_bypass_winreg_override": urllib.request._proxy_bypass_winreg_override,
                 "getproxies_environment": dict}
    exec(textwrap.dedent(source[start:end]), namespace)
    return namespace, fake


@unittest.skipUnless(shutil.which("cargo"), "needs cargo")
class SystemProxyMatchesMain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        subprocess.run(["cargo", "build", "-q", "-p", "saw-platform", "--example", "system_proxy_probe"], cwd=REPO_ROOT, check=True)
        cls.tool = REPO_ROOT / "target" / "debug" / "examples" / "system_proxy_probe"

    def ask(self, cases):
        printed = subprocess.run([str(self.tool)], input="\n".join(json.dumps(c) for c in cases), capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        self.assertEqual(len(printed), len(cases))
        return [json.loads(line) for line in printed]

    def test_shell_patterns(self):
        patterns = ["", "*", "**", "?", "*.local", "a*b*c", "*a", "a?c", "[abc]", "[!abc]", "[a-c]", "[!a-c]", "[]]", "[!]]",
                    "[]-a]", "[z-a]", "[!z-a]", "[a-]", "[-a]", "[a-c-e]", "[a-xy-z]", "[\\]", "[\\-z]", "[", "[!", "[a",
                    "a[", "[^a]", "[&&a]", "[a&&b]", "[~|]", "*.Example.COM", "x*y?z[0-9]", "[!-]", "[!a-]", "[--z]",
                    "[a--]", "*[!.]*", "\\*", "a\\b", "*/x", "A/B*", "[[]", "[!!]", "[é-ü]", "*ß*"]
        names = ["", "a", "b", "abc", "aXbYc", "x.local", "X.LOCAL", "local", "]", "-", "z", "!", "^", "&", "|", "~",
                 "[", "\\", "a\\b", "*", "ab\nc", "host.example.com", "x9yAz5", "a/b", "A\\b", "a/bc", "é", "straße", "."]
        cases = [{"ask_about": "pattern", "name": n, "pattern": p} for p, n in itertools.product(patterns, names)]
        for case, answer in zip(cases, self.ask(cases)):
            name, pattern = case["name"], case["pattern"]
            main = [fnmatch.fnmatchcase(name, pattern), fnmatch.fnmatchcase(ntpath.normcase(name), ntpath.normcase(pattern))]
            with self.subTest(case=case):
                self.assertEqual(answer, main)

    def test_the_macos_bypass(self):
        exception_lists = [[], ["*.local", "169.254/16"], ["10.0/16"], ["10"], ["127.0.0.1"], ["10.1.2.3/40"], ["0.256"],
                           ["1.2.3.4.5"], ["192.168.1.0/24", "*.corp.test"], ["", "host"], ["10.0/x"], ["99999999999.1"],
                           ["1.2/0"], ["*.example.com"], ["example.com:8443"]]
        hosts = ["example.com", "api.example.com", "host", "host:80", "x.local", "169.254.3.4", "169.255.0.1", "10.0.9.9",
                 "10.1.0.1", "127.0.0.1", "127.0.0.1:9", "192.168.1.77", "1.0.0.5", "010.0.0.1", "10.0.0.256", "a.corp.test",
                 "example.com:8443", "1.2.3.4"]
        cases = [{"ask_about": "macos_bypass", "host": h, "exclude_simple": simple, "exceptions": e}
                 for e, h, simple in itertools.product(exception_lists, hosts, [False, True])]
        for case, answer in zip(cases, self.ask(cases)):
            settings = {"exclude_simple": case["exclude_simple"], "exceptions": case["exceptions"]}
            with self.subTest(case=case):
                self.assertEqual(answer, urllib.request._proxy_bypass_macosx_sysconf(case["host"], settings))

    def test_reading_the_macos_settings(self):
        fixtures = [{}, {"HTTPSEnable": 1, "HTTPSProxy": "proxy.test", "HTTPSPort": 3128},
                    {"HTTPSEnable": 0, "HTTPSProxy": "proxy.test"}, {"HTTPSEnable": 1, "HTTPSProxy": "proxy.test"},
                    {"HTTPEnable": 1, "HTTPProxy": "h.test", "HTTPPort": 80, "FTPEnable": 1, "FTPProxy": "f.test",
                     "GopherEnable": 1, "GopherProxy": "g.test", "GopherPort": 70},
                    {"ExcludeSimpleHostnames": 1, "ExceptionsList": ["*.local", "169.254/16"]}, {"HTTPSEnable": 1}]
        rust = self.ask([{"ask_about": "scutil", "text": scutil_text(f)} for f in fixtures])
        for fixture, answer in zip(fixtures, rust):
            proxies, found = scproxy(fixture)
            with self.subTest(fixture=fixture):
                self.assertEqual(answer, [proxies, {"exclude_simple": found["exclude_simple"],
                                                    "exceptions": list(found.get("exceptions", ()))}])

    @unittest.skipUnless(sys.platform == "darwin", "needs macOS")
    def test_this_macs_own_settings(self):
        import _scproxy
        settings = _scproxy._get_proxy_settings()
        self.assertEqual(self.ask([{"ask_about": "live"}])[0],
                         [_scproxy._get_proxies(), {"exclude_simple": settings["exclude_simple"],
                                                    "exceptions": list(settings.get("exceptions", ()))}])

    def test_the_windows_registry_settings(self):
        hosts = ["example.com", "host", "host:80", "host:", "www.example.com", "a.example.net", "192.168.0.1", "WWW.EXAMPLE.COM",
                 "x.internal"]
        override = ["sz", "www.example.com;*.example.net; 192.168.0.1;<local>"]
        registries = [{}, {"ProxyEnable": ["dword", 0], "ProxyServer": ["sz", "p.test:8080"]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "p.test:8080"]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "http=h.test:1;https=s.test:2"], "ProxyOverride": override},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "socks=k.test:1080"], "ProxyOverride": ["sz", "*.internal"]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "https=s.test:2;broken"]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "https=https://s.test:2;socks=socks://k.test"]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "https=;socks=k.test"]},
                      {"ProxyEnable": ["sz", "0"], "ProxyServer": ["sz", "p.test"], "ProxyOverride": ["sz", ""]},
                      {"ProxyEnable": ["dword", 1]}, {"ProxyEnable": ["dword", 1], "ProxyServer": ["dword", 5]},
                      {"ProxyEnable": ["dword", 1], "ProxyServer": ["sz", "p.test"], "ProxyOverride": ["none", None]},
                      {"proxyenable": ["dword", 1], "PROXYSERVER": ["sz", "p.test"], "ProxyOverride": override}]
        rust = self.ask([{"ask_about": "windows", "values": r, "hosts": hosts} for r in registries])
        for registry, answer in zip(registries, rust):
            namespace, fake = windows_functions(registry)
            with mock.patch.dict(sys.modules, {"winreg": fake}), mock.patch.object(fnmatch.os, "path", ntpath):
                main = [namespace["getproxies_registry"](), [namespace["proxy_bypass_registry"](h) for h in hosts]]
            with self.subTest(registry=registry):
                self.assertEqual(answer, main)

    @unittest.skipUnless(sys.platform == "darwin", "needs macOS")
    def test_the_proxy_chosen_with_system_settings(self):
        system = {"HTTPSEnable": 1, "HTTPSProxy": "sys.test", "HTTPSPort": 8080, "ExcludeSimpleHostnames": 1,
                  "ExceptionsList": ["*.local", "10.0/16"]}
        envs = [[], [["HTTPS_PROXY", "env.test:1"]], [["no_proxy", "x"]], [["http_proxy", "h.test:1"]]]
        hosts = ["example.com", "host", "a.local", "10.0.3.4", "10.1.3.4", ""]
        cases = [{"ask_about": "choose", "host": h, "env": e, "scutil": scutil_text(system)} for e, h in itertools.product(envs, hosts)]
        proxies, found = scproxy(system)
        for case, answer in zip(cases, self.ask(cases)):
            with mock.patch.object(os, "environ", dict(case["env"])), \
                    mock.patch.object(urllib.request, "_get_proxies", lambda: dict(proxies)), \
                    mock.patch.object(urllib.request, "_get_proxy_settings", lambda: dict(found)):
                chosen = urllib.request.getproxies()
                main = None
                if "https" in chosen:
                    request = urllib.request.Request(f"https://{case['host'] or 'x'}/x")
                    if not case["host"]:
                        request.host = ""
                    urllib.request.ProxyHandler(chosen).proxy_open(request, chosen["https"], "https")
                    if request._tunnel_host is not None:
                        main = [request.host, request.headers.get("Proxy-authorization")]
            with self.subTest(case=case):
                self.assertEqual(answer, main)


if __name__ == "__main__":
    unittest.main()

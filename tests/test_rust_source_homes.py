"""Each confined capability of the Rust workspace is used only in its home: external programs run
only through the platform's one chokepoint, the network is reached only from the platform's network
home, and regular expressions are built only where patterns are bounded. This carries over the
ratchets that hold the same shape for the Python code. Each check also runs on a crate that breaks
it, so a check that stops catching its violation fails here."""

import re
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# What using each capability looks like in Rust source.
CAPABILITY_USES = {
    "external_programs": re.compile(
        r"\bstd\s*::\s*process\b|\bprocess\s*::|\buse\s+(?:::)?std\s*::\s*\{[^;]*\bprocess\b"
        r"|\bCommand\s*::\s*new\b|\bposix_spawn|\bfork\s*\(|\bvfork\s*\("
        r"|\bexec(?:v|vp|ve|vpe|l|lp|le)\s*\(|\bCreateProcess|\bShellExecute|\bWinExec\b|\bsystem\s*\("),
    "network": re.compile(
        r"\bstd\s*::\s*net\b|\bnet\s*::|\buse\s+(?:::)?std\s*::\s*\{[^;]*\bnet\b"
        r"|\bTcpStream\b|\bTcpListener\b|\bUdpSocket\b|\bsocket\s*\("),
    "regex": re.compile(r"\bregex\s*::|\bRegex(?:Builder|Set|SetBuilder)?\s*::\s*new\b"),
}
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _homes(root: Path) -> dict[str, Path]:
    with (root / "crates" / "layers.toml").open("rb") as handle:
        return {capability: root / folder for capability, folder in tomllib.load(handle)["home"].items()}


def _code(path: Path) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub("", path.read_text(encoding="utf-8")))


def home_problems(root: Path) -> list[str]:
    """Each use of a confined capability outside its home, as `capability: file:line`."""
    homes = _homes(root)
    problems = [f"{capability} has no pattern to look for" for capability in homes if capability not in CAPABILITY_USES]
    for source in sorted((root / "crates").rglob("*.rs")):
        code = _code(source)
        for capability, pattern in CAPABILITY_USES.items():
            home = homes.get(capability)
            if home is not None and source.is_relative_to(home):
                continue
            for match in pattern.finditer(code):
                line = code.count("\n", 0, match.start()) + 1
                problems.append(f"{capability}: {source.relative_to(root)}:{line} uses {match.group(0).strip()!r} "
                                f"outside {home.relative_to(root) if home else 'any home'}")
    return problems


class EachCapabilityStaysInItsHome(unittest.TestCase):

    def test_the_workspace_keeps_each_capability_in_its_home(self):
        self.assertEqual(home_problems(REPO_ROOT), [])


class EachHomeCatchesItsViolation(unittest.TestCase):

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        (self.root / "crates").mkdir()
        shutil.copyfile(REPO_ROOT / "crates" / "layers.toml", self.root / "crates" / "layers.toml")

    def _write(self, relative: str, code: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)

    def _caught(self, code: str) -> list[str]:
        self._write("crates/saw-engine/src/lib.rs", code)
        return home_problems(self.root)

    def test_each_way_of_running_a_program_is_caught(self):
        for code in ("use std::process::Command;",
                     "use std::{fs, process};",
                     "use std::{fs, os::unix::fs::symlink, process::Command};",
                     "use std::process as run;",
                     "use ::std::process;",
                     "fn f() { std::process::Command::new(\"git\"); }",
                     "fn f() { Command::new(\"curl\"); }",
                     "fn f() { unsafe { libc::execvp(p, a) }; }",
                     "fn f() { unsafe { libc::fork() }; }",
                     "fn f() { unsafe { libc::posix_spawnp(a, b, c, d, e, f) }; }",
                     "fn f() { unsafe { libc::system(c) }; }",
                     "fn f() { unsafe { CreateProcessW(a) }; }",
                     "fn f() { unsafe { ShellExecuteW(a) }; }"):
            with self.subTest(code=code):
                self.assertTrue(self._caught(code), code)

    def test_each_way_of_reaching_the_network_is_caught(self):
        for code in ("use std::net::TcpStream;", "use std::{io, net};", "use std::net as wire;", "fn f() { TcpListener::bind(a); }", "fn f() { UdpSocket::bind(a); }",
                     "fn f() { unsafe { libc::socket(a, b, c) }; }"):
            with self.subTest(code=code):
                self.assertTrue(self._caught(code), code)

    def test_each_way_of_building_a_regex_is_caught(self):
        for code in ("use regex::Regex;", "fn f() { Regex::new(p); }", "fn f() { RegexBuilder::new(p); }"):
            with self.subTest(code=code):
                self.assertTrue(self._caught(code), code)

    def test_the_report_names_the_file_and_line(self):
        self.assertEqual(self._caught("//! doc\n\nuse std::process::Command;\n"),
                         ["external_programs: crates/saw-engine/src/lib.rs:3 uses 'std::process' "
                          "outside crates/saw-platform/src/programs"])

    def test_a_capability_inside_its_home_is_allowed(self):
        self._write("crates/saw-platform/src/programs/mod.rs", "use std::process::Command;\n")
        self._write("crates/saw-platform/src/network/mod.rs", "use std::net::TcpListener;\n")
        self._write("crates/saw-detect/src/patterns/mod.rs", "use regex::Regex;\n")
        self.assertEqual(home_problems(self.root), [])

    def test_a_capability_in_another_home_is_caught(self):
        self._write("crates/saw-platform/src/network/mod.rs", "use std::process::Command;\n")
        self.assertEqual(len(home_problems(self.root)), 1)

    def test_comments_and_names_that_only_look_alike_are_not_caught(self):
        self.assertEqual(self._caught("// std::process::Command is run by the platform crate\n"
                                      "/* regex::Regex */\nfn file_system(x: u8) -> u8 { x }\n"
                                      "fn process_name() {}\nfn subnet_mask() {}\n"), [])


if __name__ == "__main__":
    unittest.main()

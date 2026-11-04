"""Build hook: compile saw's Rust binaries and ship them in the wheel.

`saw-mcp` (the MCP server) and `saw-git-standin` (the git/gh stand-in used by `saw govern install`)
are needed for governed git. When `cargo` is present the hook builds them in release mode and bundles
them in the wheel, which makes the wheel platform-specific. When `cargo` is absent, or the build
fails, it falls back to a pure-Python wheel without them, so installing never fails; governed git is
simply unavailable there, exactly as before.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# saw-mcp builds everywhere; saw-git-standin is Unix-only (it uses std::os::unix), so it is left
# out on Windows, where the editor extension supplies the terminal stand-in instead.
_BINARIES = ("saw-mcp", "saw-git-standin")


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict) -> None:
        if self.target_name != "wheel":
            return
        if shutil.which("cargo") is None:
            self._note("cargo not found; building a pure-Python wheel. Governed git will be "
                       "unavailable until saw is installed where its binaries can be built.")
            return
        manifest = Path(self.root) / "src" / "stayawake" / "bots" / "mcp" / "session" / "Cargo.toml"
        wanted = [b for b in _BINARIES if b != "saw-git-standin" or sys.platform != "win32"]
        build = ["cargo", "build", "--release", "--manifest-path", str(manifest)]
        for name in wanted:
            build += ["--bin", name]
        try:
            subprocess.run(build, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            self._note(f"the Rust build did not finish ({exc}); building a pure-Python wheel.")
            return
        release = manifest.parent / "target" / "release"
        suffix = ".exe" if sys.platform == "win32" else ""
        include = build_data.setdefault("force_include", {})
        for name in wanted:
            built = release / f"{name}{suffix}"
            if built.is_file():
                include[str(built)] = f"stayawake/bots/mcp/bin/{name}{suffix}"
        if any(f"stayawake/bots/mcp/bin/{n}" in v for n in wanted for v in include.values()):
            import sysconfig
            # The bundled binaries are standalone (no Python ABI), so the wheel is platform-specific
            # but works on any Python 3: py3-none-<platform>, not a CPython-ABI tag.
            platform = sysconfig.get_platform().replace("-", "_").replace(".", "_")
            build_data["pure_python"] = False
            build_data["tag"] = f"py3-none-{platform}"

    def _note(self, message: str) -> None:
        print(f"stayawake build: {message}", file=sys.stderr)

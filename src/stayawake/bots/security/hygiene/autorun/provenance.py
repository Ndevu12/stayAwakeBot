#!/usr/bin/env python3
"""Autorun PROVENANCE (#1333) — approximate "who put this here" without process-level visibility.

`saw` is an unprivileged static scanner; it cannot see which process wrote a file (that is the #1338
question). But it CAN read what the entry is statically attributable to, and that is most of the way
there: is the referenced executable owned by a package, shipped inside an app bundle, code-signed, or
sitting in a system/package path — versus unowned, unsigned, and running out of a scratch / cache /
`node_modules` / `~/.claude` directory a worm writes to. Fused with content-shape, novelty and
correlation (see `grade`), this separates a legitimately-installed autorun entry from a foothold far
better than any single leg.

FAIL-CLOSED: every subprocess (`dpkg`/`rpm`/`codesign`) is bounded and, on any error/timeout/absence,
yields UNKNOWN — never a spurious "attributed". An entry we could not attribute is surfaced, not
blessed. The subprocess legs are what the caller fans out over the shared THREAD parallel seam.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_PROBE_TIMEOUT = 5          # a hung dpkg/codesign must never stall the audit

# Executables here are shipped by the OS / a package manager / a signed app → a strong "attributed".
_TRUSTED_PREFIXES = (
    "/usr/", "/bin/", "/sbin/", "/opt/homebrew/", "/usr/local/", "/System/", "/Library/Apple/",
    "/nix/store/", "/opt/local/",
)
# Directories a user-level worm plants and runs payloads from — an ExecStart here is a strong signal.
_UNTRUSTED_ROOTS = ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/")
_UNTRUSTED_COMPONENTS = ("node_modules", ".npm", ".cache", ".claude", ".npm-global", ".cursor")


@dataclass
class Attribution:
    """What the entry's referenced executable is statically attributable to."""
    exec_class: str                 # "trusted" | "untrusted" | "unknown"
    owner: str | None = None        # package / formula / app-bundle name, or None
    signed: bool | None = None      # macOS code-signature valid? None = N/A or could-not-check

    @property
    def attributed(self) -> bool:
        """Attributed = owned by a package/app, OR running from a trusted path and not proven-unsigned.
        Anything unowned that runs from a scratch/cache path, or that fails signature verification, is
        NOT attributed — the conservative default a foothold cannot escape by simply being unknown."""
        if self.owner:
            return True
        return self.exec_class == "trusted" and self.signed is not False


def _run(argv: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(argv, capture_output=True, text=True, errors="replace",
                              timeout=_PROBE_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def _norm(exec_path: str) -> str:
    return os.path.normpath(os.path.expanduser(exec_path))


def _classify_path(exec_path: str) -> str:
    p = _norm(exec_path)
    if p.startswith(_TRUSTED_PREFIXES):
        return "trusted"
    # inside an app bundle anywhere → trusted (a signed .app ships its own agents)
    if ".app/" in p:
        return "trusted"
    low = p.lower()
    if low.startswith(_UNTRUSTED_ROOTS) or any(f"/{c}/" in low or low.endswith(f"/{c}")
                                               for c in _UNTRUSTED_COMPONENTS):
        return "untrusted"
    return "unknown"


def _package_owner(exec_path: str) -> str | None:
    """The distro package that owns the executable (Linux), or None. dpkg (Debian/Ubuntu) then rpm
    (Fedora/RHEL/SUSE). A path owned by no package is user-/manually-installed (or planted)."""
    r = _run(["dpkg", "-S", exec_path])
    if r and r.returncode == 0 and r.stdout.strip():
        return r.stdout.split(":", 1)[0].strip() or None
    r = _run(["rpm", "-qf", exec_path])
    if r and r.returncode == 0 and "not owned" not in r.stdout.lower() and r.stdout.strip():
        return r.stdout.strip().splitlines()[0]
    return None


def _homebrew_owner(entry_path: Path, exec_path: str) -> str | None:
    """Homebrew's agents are named `homebrew.mxcl.<formula>` and run out of the Cellar/opt — a strong,
    check-free attribution on macOS."""
    name = entry_path.name.lower()
    if name.startswith("homebrew.mxcl."):
        return name[len("homebrew.mxcl."):].removesuffix(".plist") or "homebrew"
    p = _norm(exec_path)
    if "/cellar/" in p.lower() or p.startswith("/opt/homebrew/"):
        return "homebrew"
    return None


def _codesigned(exec_path: str) -> bool | None:
    """macOS only: True if the executable is signed by an identity Apple vouched for, False if it is
    unsigned OR signed only ad-hoc, None if not-applicable / could-not-check. A False is a real signal
    (nobody accountable stands behind this binary); None never asserts anything."""
    if sys.platform != "darwin":
        return None
    p = _norm(exec_path)
    if not os.path.isfile(p):
        return None
    # `--verify` alone answers "is this signature intact", which an ad-hoc signature satisfies for
    # free (`codesign -s -`, no certificate) — and on Apple Silicon the linker ad-hoc signs by
    # DEFAULT (`ld(1)`), so a bare verify is near-inert there. `-R` adds the identity question.
    # `--strict` is dropped: it fails legitimately signed Developer ID software on "resource fork,
    # Finder information, or similar detritus" — measured on a shipping notarized browser, whose
    # authority chain is valid. Both errors were live: ad-hoc read as signed, real vendors as unsigned.
    r = _run(["codesign", "--verify", "-R=anchor apple generic", p])
    if r is None:
        return None
    return r.returncode == 0


def attribute(entry) -> Attribution:
    """Statically attribute one entry's referenced executable. Pure-ish + up to two bounded
    subprocesses; fail-closed to UNKNOWN. This is the unit the caller maps over the THREAD seam."""
    exec_path = entry.exec_path
    if not exec_path:                       # a config that references no executable — nothing to run
        return Attribution(exec_class="unknown")
    exec_class = _classify_path(exec_path)
    owner = _homebrew_owner(entry.path, exec_path) or _package_owner(exec_path)
    signed = _codesigned(exec_path)
    return Attribution(exec_class=exec_class, owner=owner, signed=signed)

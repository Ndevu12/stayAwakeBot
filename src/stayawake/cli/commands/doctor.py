#!/usr/bin/env python3
"""`saw doctor` — self-check the install and credentials (delegates AuthZ to core.identity)."""
from __future__ import annotations

import argparse
import json
import shutil

from stayawake.cli._meta import __version__
from stayawake.cli.helptext import add_command
from stayawake.core.identity import Intent, require, resolve_session
from stayawake.lib import github_app
from stayawake.utils import exitcodes
from stayawake.utils.streaming import busy, say
from stayawake.cli.argtypes import no_stream_requested


def register(sub) -> None:
    p = add_command(
        sub, "doctor", aliases=["d", "doc"],
        help="self-check install + credentials",
        description=(
            "Check this install: that `saw` runs this copy, which GitHub credential it uses and "
            "whether that credential can open fix and guard pull requests, whether a saw GitHub "
            "App is set up, and that saw's CI health tools are installed. `saw auth status` shows "
            "everything the credential can do."),
        examples=[
            ("saw doctor", "the full self-check"),
            ("saw doctor -q", "print only the problems"),
            ("saw doctor --json", "machine-readable"),
        ])
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="print only problems")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
    no_stream = no_stream_requested(a)
    with busy("checking install and credentials…", no_stream=no_stream):
        saw_path = shutil.which("saw") or shutil.which("stayawake")
        sess = resolve_session()
        health = shutil.which("stayawake-health-check")
        guard = require(Intent.OPEN_GUARD_PR, session=sess)
        fix = require(Intent.OPEN_FIX_PR, session=sess)

    if a.json:
        print(json.dumps({
            "saw_on_path": saw_path,
            "credential": sess.source,
            "actor": sess.actor,
            "live": sess.live,
            "scopes": sorted(sess.scopes) if sess.scopes is not None else None,
            "capabilities": (sorted(c.value for c in sess.capabilities)
                             if sess.capabilities is not None else None),
            "app_configured": github_app.is_configured(),
            "open_fix_pr": fix.allowed,
            "open_guard_pr": guard.allowed,
            "health_scripts_installed": bool(health),
            "version": __version__,
        }, indent=2))
        return exitcodes.CLEAN
    def mark(ok: bool) -> str:
        return "✓" if ok else "✗"

    lines = [
        f"{mark(bool(saw_path))} saw resolves to: {saw_path or 'NOT FOUND on PATH'}",
    ]
    if not sess.token:
        lines.append("• No GitHub credential. Scans of public repositories and `saw audit` work "
                     "without one; private repositories and fix or guard pull requests need one.")
        lines.append("  Run `gh auth login`, or `saw auth app register` to use a saw GitHub App.")
    else:
        who = sess.actor or "?"
        lines.append(f"{mark(sess.live)} GitHub credential: {sess.source} as {who}")
        if sess.scopes is not None:
            lines.append(f"  scopes: {', '.join(sorted(sess.scopes)) or '(none)'}")
        lines.append(f"{mark(fix.allowed)} can open fix pull requests")
        if not fix.allowed:
            lines.append("  It needs write access to repository contents and pull requests.")
        lines.append(f"{mark(guard.allowed)} can open guard pull requests")
        if not guard.allowed:
            lines.append("  It also needs permission to change workflow files.")
            for u in guard.upgrades:
                if u.command:
                    lines.append(f"  → {u.command}")
        if github_app.is_configured():
            lines.append(f"✓ a saw GitHub App is set up ({github_app.config_path()})")
    lines += [
        f"{mark(bool(health))} saw's CI health tools are installed" if health
        else f"{mark(False)} saw's CI health tools are not installed. Reinstall saw.",
        f"• version: {__version__}",
        "• `saw auth status` shows everything the credential can do",
    ]
    if a.quiet:
        problems = [ln for ln in lines if ln.startswith("✗")]
        say("\n".join(problems) if problems else "ok", no_stream=no_stream)
    else:
        say("\n".join(lines), no_stream=no_stream)
    return exitcodes.CLEAN
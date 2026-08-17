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


def register(sub) -> None:
    p = add_command(
        sub, "doctor", aliases=["d", "doc"],
        help="self-check install + credentials",
        description=(
            "Self-check the installation: confirm `saw` resolves to this install, report the "
            "active GitHub credential and whether it can open fix and guard PRs, note whether a "
            "StayAwakeBot App is configured, and confirm the health entry points are present. "
            "`saw auth status` carries the full intent/capability matrix."),
        examples=[
            ("saw doctor", "the full self-check"),
            ("saw doctor -q", "print only the problems"),
            ("saw doctor --json", "machine-readable"),
        ])
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("-q", "--quiet", action="store_true", help="print only problems")
    p.set_defaults(func=run)


def run(a: argparse.Namespace) -> int:
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
        return 0

    def mark(ok: bool) -> str:
        return "✓" if ok else "✗"

    lines = [
        f"{mark(bool(saw_path))} saw resolves to: {saw_path or 'NOT FOUND on PATH'}",
    ]
    if not sess.token:
        lines.append("• no GitHub credential (public scans + local audit still work; needed "
                     "for private repos and remote fix/guard PRs)")
        lines.append("  → `gh auth login`  or  `saw auth app register`")
    else:
        who = sess.actor or "?"
        lines.append(f"{mark(sess.live)} GitHub credential: {sess.source} as {who}")
        if sess.scopes is not None:
            lines.append(f"  scopes: {', '.join(sorted(sess.scopes)) or '(none)'}")
        lines.append(f"{mark(fix.allowed)} can open fix PRs (Contents + Pull requests)")
        lines.append(f"{mark(guard.allowed)} can open guard/workflow PRs (+ Workflows / `workflow` scope)")
        if not guard.allowed:
            for u in guard.upgrades:
                if u.command:
                    lines.append(f"  → {u.command}")
        if github_app.is_configured():
            lines.append(f"✓ Saw App config present ({github_app.config_path()})")
    lines += [
        f"{mark(bool(health))} health entry points installed (remote-only, not saw "
        f"subcommands): {'yes' if health else 'no'}",
        f"• version: {__version__}",
        "• `saw auth status` for the full intent/capability matrix",
    ]
    if a.quiet:
        problems = [ln for ln in lines if ln.startswith("✗")]
        print("\n".join(problems) if problems else "ok")
    else:
        print("\n".join(lines))
    return 0

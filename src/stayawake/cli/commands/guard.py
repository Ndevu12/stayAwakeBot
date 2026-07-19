#!/usr/bin/env python3
"""`saw guard` — install & verify the Strix CI gate on a repo (#1229).

This slice ships `saw guard check` (read-only). `saw guard setup` (writing/updating the workflow)
builds on the same detection and follows.
"""
from __future__ import annotations

import argparse
import sys

from stayawake.core import auth
from stayawake.core.render import SEVERITY, paint
from stayawake.core.streaming import Streamer, stream_enabled
from stayawake.core.terminal import supports_color


def register(sub) -> None:
    p = sub.add_parser("guard", aliases=["gd"],
                       help="install & verify the Strix security-scan CI gate on a repo")
    p.set_defaults(func=lambda a: (p.print_help() or 0))
    gsub = p.add_subparsers(dest="guard_command", metavar="<subcommand>")

    ck = gsub.add_parser(
        "check", help="check the Strix gate: present, SHA-pinned, fresh, and required",
        description="Detect the Strix gate by its `uses: Ndevu12/strix@…` action reference (not by "
                    "filename), grade the pin (a commit SHA is best), report whether it is behind the "
                    "latest Strix release, and — for a remote repo — whether branch protection "
                    "requires it. Read-only; never runs the repo's code.")
    ck.add_argument("--repo", metavar="OWNER/NAME", default=None,
                    help="check a remote GitHub repo instead of the local working tree")
    ck.add_argument("-b", "--branch", default="main",
                    help="branch whose protection must require the gate (default: main)")
    ck.add_argument("-f", "--fail", action="store_true", dest="fail",
                    help="exit non-zero when the gate is absent, unpinned, stale, or not required")
    ck.add_argument("--no-stream", action="store_true", dest="no_stream",
                    help="disable the typewriter output (plain, instant)")
    ck.set_defaults(func=run_check)


def run_check(a: argparse.Namespace) -> int:
    from stayawake import guard   # lazy: pull yaml/API in only when the command runs

    token = None
    if a.repo:
        token, _ = auth.resolve_token()
        if not token:
            print(auth.no_credential_hint("checking a remote repo's gate") +
                  " (branch-protection + freshness checks need it)\n", file=sys.stderr)

    status = guard.check(slug=a.repo, branch=a.branch, token=token)
    report = _render(status, color=supports_color(sys.stdout), remote=bool(a.repo))
    Streamer(enabled=stream_enabled(sys.stdout, force_off=a.no_stream)).line(report)
    return 1 if (a.fail and not _is_ok(status)) else 0


def _is_ok(s) -> bool:
    """Gate is healthy: present, SHA-pinned, not stale, and (when we could check) required."""
    if not s.present or s.ref is None or s.ref.pin != "sha":
        return False
    if s.fresh is not None and s.fresh.state == "behind":
        return False
    return s.required is not False


def _render(s, *, color: bool, remote: bool) -> str:
    ok, warn, dim = SEVERITY["ok"], SEVERITY["warning"], SEVERITY["info"]
    lines: list[str] = []

    if not s.present:
        if s.error:
            return paint(f"⚠️  {s.error}", warn, on=color)
        lines.append(paint("✗ No Strix gate found", warn, on=color) +
                     " — no workflow uses `Ndevu12/strix`.")
        lines.append(paint("     Run `saw guard setup` to add one.", dim, on=color))
        return "\n".join(lines)

    r = s.ref
    lines.append(paint("✓ Strix gate found", ok, on=color) + f" — {r.workflow} (job “{r.job}”)")

    if r.pin == "sha":
        lines.append("  " + paint("✓ pinned to a commit SHA", ok, on=color) + f"  (@{r.ref[:12]}…)")
    elif r.pin == "tag":
        lines.append("  " + paint("• pinned to a release tag", dim, on=color) +
                     f"  (@{r.ref}) — a SHA is immutable; `saw guard setup` can rewrite it")
    else:
        lines.append("  " + paint("⚠ floating ref", warn, on=color) +
                     f"  (@{r.ref}) — the action's code can change under you; pin a SHA")

    if s.fresh is not None:
        f = s.fresh
        if f.state == "fresh":
            lines.append("  " + paint("✓ up to date", ok, on=color) + f"  (latest {f.latest_tag})")
        elif f.state == "behind":
            lines.append("  " + paint("⚠ behind latest", warn, on=color) + f"  — {f.detail}")
        elif f.state == "floating":
            lines.append("  " + paint("• moving alias", dim, on=color) + f"  — {f.detail}")
        else:
            lines.append("  " + paint("• freshness unknown", dim, on=color) + f"  — {f.detail}")

    if remote:
        if s.required is True:
            lines.append("  " + paint("✓ required", ok, on=color) +
                         f"  — branch protection on {s.branch} requires “{r.job}”")
        elif s.required is False:
            lines.append("  " + paint("⚠ not a required check", warn, on=color) +
                         f"  — {s.branch} protection does NOT require “{r.job}”; an infected PR can still merge")
        # s.required is None → no token, couldn't check → stay quiet
    return "\n".join(lines)

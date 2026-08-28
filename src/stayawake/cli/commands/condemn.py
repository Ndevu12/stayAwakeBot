#!/usr/bin/env python3
"""`saw condemn` — remove an installed dependency tree a lockfile can reconstruct.

Separate from `saw fix` on purpose: `fix` prepares a branch and never edits your working tree, and
this does the opposite. A command that deletes is asked for by name."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from stayawake.bots.security.dependencies.resolvers.npm import NpmResolver
from stayawake.bots.security.remediation.changes import quarantine_path
from stayawake.bots.security.remediation.condemn import (INSTALLED_DIR, carry_out,
                                                         next_quarantine, plan_condemnation)
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.targets import LocalRepoTarget, ScanOptions
from stayawake.cli.helptext import add_command


def register(sub) -> None:
    p = add_command(
        sub, "condemn",
        help="remove an installed dependency tree the lockfile can rebuild",
        description=(
            "Remove the installed dependency tree of a CONFIRMED-infected repository. Anything the "
            "lockfile does not account for is copied aside first — a tree that has drifted from the "
            "lockfile is the only record of what actually ran, and it is kept. Nothing is "
            "reinstalled: installing re-runs the lifecycle scripts. Refuses on any other verdict."),
        examples=[("saw condemn .", "remove what the lockfile proves, keep the rest"),
                  ("saw condemn . --dry-run", "show what each part would be, change nothing")])
    p.add_argument("path", nargs="?", default=".", help="the repository (default: this one)")
    p.add_argument("-n", "--dry-run", action="store_true",
                   help="report the split and exit without removing anything")
    p.set_defaults(func=run)


_LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}


def _declared(root: Path) -> tuple[set[tuple[str, str]], list[Path]]:
    """What the LOCKFILES say should be installed, and which files said it.

    A manifest is excluded even where it pins an exact version. It records what someone asked for,
    not what an install produced — a dependency added and never installed, or a peer dependency that
    is never written into a tree at all, would otherwise prove a package removable that nothing
    would put back."""
    target = LocalRepoTarget(root, str(root), ScanOptions())
    declared, lockfiles = set(), []
    for dependency in NpmResolver().resolve(target):
        path = root / dependency.source_path
        if path.name not in _LOCKFILES:
            continue
        declared.add((dependency.purl.name, dependency.purl.version))
        if path not in lockfiles:
            lockfiles.append(path)
    return declared, lockfiles


def run(a: argparse.Namespace) -> int:
    root = Path(a.path).resolve()
    if not (root / INSTALLED_DIR).is_dir():
        print(f"No installed tree at {root / INSTALLED_DIR} — nothing to condemn.")
        return 0

    result = scan_target(LocalRepoTarget(root, str(root), ScanOptions()), load_signatures(), [])
    if not result.infected:
        print(f"Refusing: {root} is '{result.verdict}', not confirmed infected. "
              "Removing an installed tree on anything less turns a false positive into data loss.")
        return 2

    declared, lockfiles = _declared(root)
    plan = plan_condemnation(root, declared, lockfiles)
    if not plan.safe_to_remove:
        print(f"Refusing: {plan.reason}.")
        return 2

    if a.dry_run:
        print(f"{len(plan.derivable)} packages the lockfile can rebuild would be removed; "
              f"{len(plan.preserve)} it does not account for would be kept.")
        return 0

    quarantine = next_quarantine(root, quarantine_path(root))
    preserved, removed = carry_out(plan, quarantine)
    print(f"Removed {removed} packages. Kept {preserved} the lockfile does not account for, in "
          f"{quarantine.relative_to(root)}. Reinstall when you are ready — it re-runs "
          "install scripts.")
    return 0

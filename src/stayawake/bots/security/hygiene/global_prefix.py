#!/usr/bin/env python3
"""The tree `npm install -g` writes into.

It sits outside every repository and, on most installs, outside the home directory, so a repository
scan never walks it and a home wipe does not remove it. Grading rationale and limits: `Ndevu12/saw#134`.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from stayawake.utils import hostdenial

from stayawake.bots.security.dependencies.installed import NpmInstalledTree

from .models import HygieneIssue, _WIPER_NOTE
from .host_artifacts import _npm_prefix_roots, _usable_prefix

GLOBAL_INSTALL_FINDING_ID = "global-install-tree"

_PREFIX_LINE = re.compile(r"^\s*prefix\s*=\s*(.+?)\s*$", re.MULTILINE)

# Node version managers keep a prefix per installed version. `*` is the version.
_MANAGED_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("NVM_DIR", (".nvm", "versions", "node", "*")),
    ("VOLTA_HOME", (".volta", "tools", "image", "node", "*")),
    ("FNM_DIR", (".fnm", "node-versions", "*", "installation")),
)


def _prefix_from_npmrc(path: Path) -> Path | None:
    """The `prefix=` a config file sets, or None."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found = _PREFIX_LINE.search(text)
    return _usable_prefix(os.path.expandvars(found.group(1))) if found else None


def _declared_prefixes() -> list[Path]:
    """Prefixes npm's own configuration names, in the precedence npm documents: the environment
    first, then the per-user file, then the global one."""
    out: list[Path] = []
    named = _usable_prefix(os.environ.get("npm_config_prefix"))
    if named is not None:
        out.append(named)
    user = os.environ.get("NPM_CONFIG_USERCONFIG")
    for rc in (Path(user) if user else Path.home() / ".npmrc",):
        from_file = _prefix_from_npmrc(rc)
        if from_file is not None:
            out.append(from_file)
    return out


def _managed_prefixes() -> list[Path]:
    """Prefixes a Node version manager owns — one per installed version, so a payload does not
    become invisible by living under the version that is not current."""
    home = Path.home()
    out: list[Path] = []
    for var, parts in _MANAGED_PREFIXES:
        base = Path(os.environ[var]) if os.environ.get(var) else home / parts[0]
        try:
            out += sorted(p for p in base.glob(str(Path(*parts[1:]))) if p.is_dir())
        except OSError:
            continue
    return out


def global_module_roots() -> list[Path]:
    """Every directory a global install writes packages into, on this host.

    Unix keeps them at `<prefix>/lib/node_modules`; Windows keeps them at `<prefix>/node_modules`,
    with no `lib`. Both layouts are asked of every prefix, because the platform a path was written
    for is not always the platform reading it.
    """
    leaves = (("node_modules",), ("lib", "node_modules"))
    seen: dict[Path, None] = {}
    for prefix in _declared_prefixes() + _managed_prefixes() + _npm_prefix_roots():
        for leaf in leaves:
            root = prefix.joinpath(*leaf)
            if root in seen:
                continue
            try:
                if root.is_dir() and not hostdenial.held_by_us(root):
                    seen[root] = None
            except OSError:
                continue
    return list(seen)


class GlobalNpmInstalledTree(NpmInstalledTree):
    """The globally installed packages under one prefix.

    `ghost_reconcilable` is False: no lockfile governs a global tree, so "installed but not in the
    lockfile" would describe every package here, including npm's own.
    """

    ghost_reconcilable = False


def _target_for(root: Path):
    """The package audit's own reader, aimed at the prefix holding `root`."""
    from stayawake.bots.security.targets.base import ScanOptions, Target
    return Target(root.parent, str(root), ScanOptions(exclude_dirs=set()))


def _issue(finding, root: Path) -> HygieneIssue:
    return HygieneIssue(
        id=GLOBAL_INSTALL_FINDING_ID,
        severity="warning",
        title="A globally installed package was reported",
        detail=f"{finding.description} It is installed for every project on this host, under "
               f"{root}.",
        remediation=f"Remove or reinstall it from a source you trust, and rotate credentials "
                    f"LAST — {_WIPER_NOTE}.",
    )


def check_global_install_tree() -> list[HygieneIssue]:
    """Report what the globally installed packages carry.

    Nothing is reported for a location this tool controls, and nothing is reported for being absent
    from a lockfile, which does not govern this tree.
    """
    roots = global_module_roots()
    if not roots:
        return []
    from stayawake.bots.security.matchers.installed_package_audit import InstalledPackageAuditMatcher
    from stayawake.bots.security.signatures import load_signatures

    by_matcher = load_signatures()
    sigs = by_matcher.get(InstalledPackageAuditMatcher.handles, [])
    every = [s for group in by_matcher.values() for s in group]
    matcher = InstalledPackageAuditMatcher(trees=(GlobalNpmInstalledTree(),), resolvers=())
    issues: list[HygieneIssue] = []
    for root in roots:
        for finding in matcher.scan(_target_for(root), sigs, all_signatures=every):
            issues.append(_issue(finding, root))
    return issues

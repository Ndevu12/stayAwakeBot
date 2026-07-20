#!/usr/bin/env python3
"""Target resolution — turn CLI/config selectors into the repositories a command acts on.

One shared model for every repo-sweeping verb (`saw scan`, `saw fix`, `saw guard`): discover LOCAL
repos under given paths/globs (or the enclosing repo), and resolve REMOTE `owner/name` slugs via the
#1075 ladder (ad-hoc `--user`/`--org`/`owner/repo` selectors → configured `targets.github` → your own
repos). Pure target math — no scanning, no output, no git writes — so each command layers its own
per-repo action on top without re-implementing discovery.

Extracted from `service.py` when `saw guard` became the third consumer (after scan and fix), so the
resolution logic lives in exactly one place instead of being copied per verb.
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from stayawake.lib import auth
from stayawake.lib import git as gitutil
from stayawake.lib.adapters import github_api
from stayawake.bots.security.targets import ScanOptions

DEFAULT_CONFIG = "config/security.yml"

# Shared actionable message when a `--remote` run resolves zero repositories.
REMOTE_EMPTY_HINT = (
    "No GitHub repositories resolved. Name targets with `--user U` / `--org O` / `owner/repo`, "
    "set `targets.github` in the config, or authenticate (`gh auth login` or GH_SECURITY_TOKEN) "
    "to act on your own repos.")

_SLUG_RE = re.compile(r"^[^/\s]+/[^/\s]+$")


def enclosing_repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor of `start` (default: CWD) that contains a .git, else `start`.
    Lets a bare invocation default to 'act on the repo I'm standing in', even from a
    subdirectory."""
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if (d / ".git").exists():
            return d
    return start


def discover_local_repos(patterns: list[str], opts: ScanOptions) -> list[Path]:
    """Every git repository under the given path/glob `patterns` (deduped, deterministic order).
    Descends until it hits a `.git` (that dir is a repo — it is not descended further), pruning
    `opts.exclude_dirs` so a huge `node_modules` never dominates the walk."""
    repos: list[Path] = []
    seen: set[str] = set()
    for pat in patterns or []:
        root = Path(os.path.expanduser(pat).split("*", 1)[0] or "/")
        if not root.exists():
            root = root.parent
        if not root.exists():
            continue
        for dirpath, dirnames, _ in os.walk(root):
            if (Path(dirpath) / ".git").exists():
                rp = Path(dirpath).resolve()
                if str(rp) not in seen:
                    seen.add(str(rp))
                    repos.append(rp)
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in opts.exclude_dirs]
    return repos


def remote_scope(cfg: dict, users, orgs, slugs) -> str:
    """A short label for the per-run line, describing WHICH remote repos a `--remote` run
    resolved (mirrors the ladder in `resolve_remote`). Pure — no API calls."""
    if users or orgs or slugs:
        bits = []
        if users:
            bits.append("user " + ", ".join(users))
        if orgs:
            bits.append("org " + ", ".join(orgs))
        if slugs:
            bits.append(f"{len(slugs)} named repo(s)")
        return "; ".join(bits)
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    if gconf.get("users") or gconf.get("orgs"):
        return "configured targets"
    return "your own repos"


def resolve_remote(cfg: dict, opts: ScanOptions, *, users=None, orgs=None, slugs=None):
    """Resolve `--remote` targets to ('owner/name', ...). Ladder, first match wins (#1075):
      1. ad-hoc CLI selectors — `slugs` (named repos), `--user`/`--org` enumerations — which
         OVERRIDE config so you can target anything without editing a file;
      2. configured `targets.github.users/orgs`;
      3. infer "my repos" — the authenticated user's OWNED repos (private-inclusive via
         /user/repos), or a GitHub App installation's repos.
    Returns (sorted unique slugs, token, source)."""
    gconf = cfg.get("targets", {}).get("github", {}) or {}
    inc_forks = gconf.get("include_forks", False)
    inc_arch = gconf.get("include_archived", False)
    token, source = auth.resolve_token()
    resolved: list[str] = []

    if users or orgs or slugs:                       # 1. ad-hoc selectors override everything
        resolved += list(slugs or [])
        for u in users or []:
            resolved += github_api.list_repos(u, "users", token, inc_forks, inc_arch)
        for o in orgs or []:
            resolved += github_api.list_repos(o, "orgs", token, inc_forks, inc_arch)
    else:
        for kind in ("users", "orgs"):               # 2. configured targets
            for acct in gconf.get(kind, []) or []:
                resolved += github_api.list_repos(acct, kind, token, inc_forks, inc_arch)
        if not resolved and token:                   # 3. infer "my repos"
            resolved += (github_api.list_installation_repos(token, inc_arch)
                         if source == "github-app"
                         else github_api.list_my_repos(token, inc_forks, inc_arch))
    return sorted(set(resolved)), token, source


def invalid_slugs(slugs) -> list[str]:
    """The entries that aren't a valid `owner/name` — so `--remote` positionals (which are
    slugs, not local paths) fail loudly instead of silently resolving to nothing."""
    return [s for s in (slugs or []) if not _SLUG_RE.match(s)]


@contextlib.contextmanager
def cloned_repo(slug: str, token: str | None, *, depth: int = 50):
    """Shallow-clone a remote `owner/name` into a throwaway directory (authenticated HTTPS — the
    token goes via the git-askpass env, never in the URL/argv), yield the clone `Path`, and remove
    it on exit. Yields `None` if the clone fails. The one shared way a command (`saw fix`,
    `saw guard setup`) acts on a remote repo it hasn't got checked out."""
    tmp = Path(tempfile.mkdtemp(prefix="sab-clone-"))
    clone = tmp / "repo"
    try:
        with gitutil.github_https_auth(token) as (prefix, env):
            r = subprocess.run(["git", "clone", "--quiet", "--depth", str(depth),
                                f"{prefix}{slug}.git", str(clone)],
                               capture_output=True, text=True, check=False, env=env)
        yield clone if r.returncode == 0 else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

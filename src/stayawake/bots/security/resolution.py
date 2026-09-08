#!/usr/bin/env python3
"""Target resolution — turn CLI/config selectors into the repositories a command acts on."""
from __future__ import annotations

import contextlib
import glob
import os
from dataclasses import dataclass, replace
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from stayawake.bots.security.write_sinks import sink_label
from stayawake.lib import auth
from stayawake.lib import git as gitutil
from stayawake.lib.adapters import github_api
from stayawake.bots.security.targets import ScanOptions

DEFAULT_CONFIG = "config/security.yml"

REMOTE_EMPTY_HINT = (
    "No GitHub repositories resolved. Name targets with `--user U` / `--org O` / `owner/repo`, "
    "set `targets.github` in the config, or authenticate (`gh auth login` or GH_SECURITY_TOKEN) "
    "to act on your own repos.")

_SLUG_RE = re.compile(r"^[^/\s]+/[^/\s]+$")


def _holds_git(p: Path) -> bool:
    """Whether `p` contains a `.git`, False when that cannot be determined.

    `Path.exists()` raises on a path inside an unreadable directory on Linux and returns False on
    macOS, so an unguarded check crashed the whole run on one platform and not the other.
    """
    try:
        return (p / ".git").exists()
    except OSError:
        return False


def _shape_of(named: Path) -> tuple[bool, bool, bool]:
    """(is_symlink, is_dir, is_file) for `named`, all False when the path cannot be examined."""
    try:
        return named.is_symlink(), named.is_dir(), named.is_file()
    except OSError:
        return False, False, False


def enclosing_repo_root(start: Path | None = None) -> Path:
    """Nearest ancestor of `start` (default: CWD) that contains a .git, else `start`.
    Lets a bare invocation default to 'act on the repo I'm standing in', even from a
    subdirectory."""
    start = (start or Path.cwd()).resolve()
    for d in (start, *start.parents):
        if _holds_git(d):
            return d
    return start


def discover_local_repos(patterns: list[str], opts: ScanOptions,
                        *, unreadable: list[Path] | None = None) -> list[Path]:
    """Every git repository under the given path/glob `patterns` (deduped, deterministic order).
    Descends until it hits a `.git` (that dir is a repo — it is not descended further), pruning
    `opts.exclude_dirs` so a huge `node_modules` never dominates the walk.

    Directories the walk cannot enter are appended to `unreadable`, because one it skips may be the
    repository the pattern was written for — dropping it silently answers `clean` about a target
    nobody looked at.
    """
    repos: list[Path] = []
    seen: set[str] = set()

    def _unwalkable(err: OSError) -> None:
        if unreadable is not None:
            where = getattr(err, "filename", None)
            if where:
                unreadable.append(Path(where))

    for pat in patterns or []:
        root = Path(os.path.expanduser(pat).split("*", 1)[0] or "/")
        if not os.path.lexists(root):
            root = root.parent
        if not os.path.lexists(root):
            continue
        for dirpath, dirnames, _ in os.walk(root, onerror=_unwalkable):
            if _holds_git(Path(dirpath)):
                rp = Path(dirpath).resolve()
                if str(rp) not in seen:
                    seen.add(str(rp))
                    repos.append(rp)
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in opts.exclude_dirs]
    return repos


REPOSITORY, DIRECTORY, ONE_FILE = "repository", "directory", "file"
_KINDS = frozenset({REPOSITORY, DIRECTORY, ONE_FILE})


@dataclass(frozen=True)
class LocalTarget:
    """One thing to scan, and the scope that answers about it.

    Which matchers may run, what the verdict is about, where a whole-target walk starts and what
    went unlooked-at are answered here. A scope held as loose booleans is one every caller can
    forget to apply, and each of them did.

    `root` is what every path is relative to; `within` is the part of it that is read.
    """

    root: Path
    include_only: tuple[str, ...] | None
    kind: str
    within: str | None = None
    unread_destination: str | None = None
    rooted_at_a_repository: bool = False

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"kind must be one of {sorted(_KINDS)}, got {self.kind!r}")

    @property
    def is_repo(self) -> bool:
        return self.kind == REPOSITORY

    @property
    def names_one_file(self) -> bool:
        return self.kind == ONE_FILE

    @property
    def paths_are_project_relative(self) -> bool:
        """Whether a finding's path here is the one the project around it would use."""
        return self.is_repo or self.within is not None or self.rooted_at_a_repository

    @property
    def scan_root(self) -> Path:
        """Where a walk over the whole target starts."""
        return self.root / self.within if self.within else self.root

    @property
    def label(self) -> Path:
        """What the verdict is about — and what `--alert` titles an issue with."""
        if self.names_one_file and self.include_only:
            return self.root / self.include_only[0]
        return self.scan_root

    @property
    def key(self) -> tuple:
        """What makes this target the same target as another. A `|`-joined string let a directory
        named `a||` collide with a different path and be dropped before any scan."""
        return (self.root, self.include_only, self.within)

    def skipped(self) -> tuple[str, ...]:
        """What this scope does not look at, in the operator's words — computed from the scope
        rather than written out beside each branch that happens to remember."""
        if self.names_one_file:
            return ("what its history still stores",
                    "whether an installed package matches what was published",
                    "what a previous cleanup left behind",
                    "an audit against an external advisory service")
        if not self.is_repo:
            return ("what a commit introduced", "what earlier versions still hold")
        return ()

    def where_paths_are_from(self) -> str | None:
        """What is not evaluated because there is no project to measure paths from."""
        if self.paths_are_project_relative:
            return None
        return ("Nothing here is under git, so a file's path is measured from the path you named. "
                "Checks that key on where a file sits in a project — a workflow under "
                "`.github/workflows`, for one — apply only as far as that reaches. Name the folder "
                "the project starts at to give them the whole path.")

    def unlooked_at(self) -> str | None:
        """The disclosure this scope owes the operator, or None when it looked at everything."""
        skipped = self.skipped()
        if not skipped:
            return None
        what = "; ".join(skipped)
        if self.names_one_file:
            return (f"Only the file you named was read, so these did not run: {what}. "
                    "Scan the directory it sits in for those.")
        if self.within:
            return (f"Only the directory you named was read, so these did not run: {what}. "
                    "Scan the repository it sits in for those.")
        return ("This target is not a repository, so the checks that read a project's history did "
                f"not run: {what}.")

    def destination_note(self) -> str | None:
        """Why what is behind this link went unread."""
        if not self.unread_destination:
            return None
        return (f"This is a link into {self.unread_destination}, which was not read through. "
                "Name that path directly to scan what is behind it.")


def _one_file(named: Path) -> "LocalTarget":
    """One named file, rooted where its directory would have been scanned from.

    Keeping the root and using the path relative to it is what lets a finding's path, the allowlist
    globs, the report label and a SARIF uri stay what a scan of that directory would produce —
    re-rooting at the file's own parent flattens the path and silently changes all four.
    """
    here = named.parent.resolve()
    root = enclosing_repo_root(here)
    if not _holds_git(root):
        root = here
    rel = (here / named.name).relative_to(root)
    return LocalTarget(root, (str(rel),), ONE_FILE, rooted_at_a_repository=_holds_git(root))


def _a_directory(named: Path) -> "LocalTarget":
    """One named directory, rooted the same way a named file is.

    A directory inside a repository is read from the repository root and confined to itself, for
    the reason `_one_file` keeps its root: re-rooting at the directory drops every path-anchored
    signature (`.github/workflows/…`) and points a SARIF uri at a path the repository has not got.
    """
    here = named.resolve()
    if _holds_git(here):
        return LocalTarget(here, None, REPOSITORY)
    root = enclosing_repo_root(here)
    if not _holds_git(root) or root == here:
        return LocalTarget(here, None, DIRECTORY)
    return LocalTarget(root, None, DIRECTORY, str(here.relative_to(root)))


def _sensitive_destination(named: Path) -> str | None:
    """The write-sink a link lands in, by the detector's own table, or None."""
    try:
        return sink_label(os.readlink(named), named.resolve())
    except (OSError, RuntimeError):
        return None


def resolve_local_targets(patterns: list[str], opts: ScanOptions) -> list[LocalTarget]:
    """What the given patterns name, in order, deduped.

    A pattern that finds repositories resolves to those, so a sweep keeps working. A named path
    that finds none, and exists, is scanned as itself — a directory nobody put under git, or one
    file. A pattern that names nothing resolves to nothing, and the caller fails closed on that.
    """
    out: list[LocalTarget] = []
    seen: set[str] = set()
    for pat in patterns or []:
        named = Path(os.path.expanduser(pat))
        # Discovery promotes a path that is not there to its PARENT and walks that, so a typo or a
        # stale glob came back as whatever sat beside it — reported under those repositories' own
        # names, and `clean` there reads as "the path I named is clean". A pattern still discovers
        # through the walk; it just has to match something first.
        if not os.path.lexists(named) and not glob.glob(str(named)):
            continue
        # The link ENTRY, always and first: a redirect check has to see the link itself, and the
        # walk that discovers repositories follows it, so anything under it hides the entry.
        is_link, is_dir, is_file = _shape_of(named)
        candidates: list[LocalTarget] = [_one_file(named)] if is_link else []
        if candidates and (into := _sensitive_destination(named)):
            # Resolving the link is ours, not the operator's: reading through one that lands in a
            # credential store puts those paths in the report, the SARIF and an --alert issue body.
            # The link is still judged; what is behind it is left alone, and said so.
            out_key = replace(candidates[0], unread_destination=into)
            if out_key.key not in seen:
                seen.add(out_key.key)
                out.append(out_key)
            continue
        # A file holds no repositories, and discovery treats a `*` in its NAME as a pattern — so a
        # real file called `star*name.js` was answered by the repositories beside it.
        blocked: list[Path] = []
        found = [] if is_file else discover_local_repos([pat], opts, unreadable=blocked)
        # A directory discovery could not enter becomes a target of its own, so it reaches the
        # operator through the same fail-closed path as one they named directly.
        candidates += [LocalTarget(b, None, DIRECTORY) for b in blocked]
        if found:
            candidates += [LocalTarget(r, None, REPOSITORY) for r in found]
        elif is_dir:
            candidates.append(_a_directory(named))
        elif candidates:
            pass                                  # a dangling link: the entry is all there is
        elif is_file:
            candidates = [_one_file(named)]
        for c in candidates:
            if c.key not in seen:
                seen.add(c.key)
                out.append(c)
    return out


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
    """Resolve `--remote` targets to ('owner/name', ...). Ladder, first match wins:
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
def cloned_repo(slug: str, token: str | None, *, depth: int | None = 50):
    """Clone a remote `owner/name` into a throwaway directory (authenticated HTTPS — the
    token goes via the git-askpass env, never in the URL/argv), yield the clone `Path`, and remove
    it on exit. Yields `None` if the clone fails. The one shared way a command (`saw fix`,
    `saw guard setup`, `saw fix amend`) acts on a remote repo it hasn't got checked out.

    `depth=None` is a full clone (every branch). A shallow clone is `--single-branch` and
    cannot see commits or refs the amend path has to update.
    """
    tmp = Path(tempfile.mkdtemp(prefix="sab-clone-"))
    clone = tmp / "repo"
    try:
        with gitutil.github_https_auth(token) as (prefix, env):
            cmd = ["git", "clone", "--quiet"]
            if depth is not None:
                cmd += ["--depth", str(depth)]
            cmd += [f"{prefix}{slug}.git", str(clone)]
            r = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
        yield clone if r.returncode == 0 else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

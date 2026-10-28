#!/usr/bin/env python3
"""Audit the INSTALLED dependency tree against the lockfile + corpus."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, build_corroborated_loader_check
from stayawake.bots.security.dependencies import RESOLVERS, AdvisoryStore
from stayawake.bots.security.dependencies.installed import INSTALLED_TREES
from stayawake.bots.security.dependencies.purl import Purl
from stayawake.bots.security.dependencies.remediation import advisory_reference, malware_fix


class InstalledPackageAuditMatcher(Matcher):
    handles = "installed-package-audit"

    def __init__(self, trees=INSTALLED_TREES, resolvers=RESOLVERS,
                 store_factory=AdvisoryStore.default):
        self._trees = trees
        self._resolvers = resolvers
        self._store_factory = store_factory

    def scan(self, target, signatures, all_signatures=None):
        if not getattr(target, "reads_checkout", True):
            return []
        by_id = {s["id"]: s for s in signatures}
        store = self._store_factory(all_signatures or signatures)
        tamper_sig = by_id.get("tampered-installed-package")
        hook_sig = by_id.get("installed-lifecycle-hook")
        entry_sig = by_id.get("installed-entry-loader")
        hook_patterns = _confirmed_lifecycle_patterns(all_signatures) if hook_sig is not None else []
        entry_check = build_corroborated_loader_check(all_signatures) if (entry_sig is not None and all_signatures) else None
        deep = bool(getattr(target.opts, "deep", False))
        budget = [_DEEP_SWEEP_BUDGET]
        truncated: list = []
        findings: list[Finding] = []
        for tree in self._trees:
            declared = getattr(type(tree), "installations", None)
            groups = (list(tree.installations(target)) if callable(declared)
                      else [(None, None, list(tree.read(target)))])
            for owner, folder, installed in groups:
                locked = (self._locked(tree.ecosystem, _lock_root(target, owner, folder))
                          if (installed and tree.ghost_reconcilable) else _Lockfiles({}))
                comparable = owner is None or bool(locked.listed)
                if owner is not None and installed and not comparable:
                    _note_uncompared(target, owner)
                for pkg in installed:
                    where = folder if folder is not None else tree.install_folder(pkg.path)
                    advisory = (store.advisory_for(Purl(tree.ecosystem, pkg.name, pkg.version))
                                if (pkg.version and not store.is_empty()) else None)
                    if advisory is not None:
                        findings.append(_malicious(advisory, pkg))
                    elif tree.ghost_reconcilable and comparable and not locked.lists(pkg, where):
                        findings.append(_ghost(by_id.get("ghost-package"), pkg,
                                               locked.versions_of(pkg, where)))
                    if hook_patterns and pkg.hooks:
                        findings.append(_lifecycle_hook(hook_sig, hook_patterns, pkg))
                    if entry_check is not None:
                        findings.append(_loader_sweep(entry_sig, entry_check, target, tree, pkg,
                                                      deep, budget, truncated))
            if tamper_sig is not None:                # RECORD sha256 integrity (Python provides it)
                for t in tree.tampered(target):
                    findings.append(_tampered(tamper_sig, t))
        if deep and truncated:
            notes = getattr(target, "coverage_notes", None)
            if notes is not None:
                notes.append("Some installed packages could not be checked in full, so they are not "
                             "known to be clean.")
        return [f for f in findings if f is not None]

    def _locked(self, ecosystem: str, target) -> "_Lockfiles":
        """Collect what each folder's lockfiles list. Takes the ecosystem and the target. Returns
        each folder mapped to the packages listed there and the versions they are listed at."""
        listed: dict[str, dict[str, set]] = {}
        for r in self._resolvers:
            if getattr(r, "ecosystem", None) == ecosystem:
                for dep in r.resolve(target):
                    folder = str(PurePosixPath(dep.source_path).parent)
                    listed.setdefault(folder, {}).setdefault(dep.purl.name, set()).add(dep.purl.version)
        return _Lockfiles(listed)


@dataclass(frozen=True)
class _Lockfiles:
    """The packages each folder's lockfiles list, with the versions they are listed at."""

    listed: dict[str, dict[str, set]]

    def lists(self, pkg, folder: str) -> bool:
        """Tell whether a lockfile in the folder a package belongs to, or above it, lists it at the
        version installed. Takes the installed package and its folder. Returns the answer; a version
        either side does not name counts as listed."""
        versions = self.versions_of(pkg, folder)
        if versions is None:
            return False
        return not pkg.version or None in versions or pkg.version in versions

    def versions_of(self, pkg, folder: str) -> set | None:
        """Name the versions the lockfiles in or above a package's folder list it at. Takes the
        installed package and its folder. Returns them, or None when none of those lockfiles lists
        it."""
        found = [names[pkg.name] for listed_in, names in self.listed.items()
                 if pkg.name in names and _at_or_above(listed_in, folder)]
        return set().union(*found) if found else None


_OWNER_FILES = ("package.json", "package-lock.json", "npm-shrinkwrap.json",
                "yarn.lock", "pnpm-lock.yaml")


class _LockRoot:
    """The lockfiles of the project a linked install belongs to, and nothing else."""

    def __init__(self, root: Path, files: tuple[str, ...]):
        self.root = root
        self._files = files

    def iter_files(self):
        yield from self._files

    def read_bytes(self, rel: str, limit: int | None = None):
        path = self.root / rel
        try:
            if path.is_symlink() or not path.is_file():
                return None
            data = path.read_bytes()
        except OSError:
            return None
        return data if limit is None else data[:limit]

    def read_text(self, rel: str):
        raw = self.read_bytes(rel)
        return None if raw is None else raw.decode("utf-8", errors="replace")


def _lock_root(target, owner: Path | None, folder: str | None):
    """Return where a tree's lockfiles are read from. Takes the scan target, and the other project
    and folder when the install is a link to that project. Returns the target itself when the
    install lives here, otherwise just that project's lockfiles."""
    if owner is None:
        return target
    files = []
    for directory in _directories_up_to(owner / folder if folder and folder != "." else owner, owner):
        try:
            prefix = directory.resolve().relative_to(owner.resolve()).as_posix()
        except (OSError, ValueError):
            continue
        prefix = "" if prefix in ("", ".") else prefix
        for name in _OWNER_FILES:
            path = directory / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            files.append(name if not prefix else f"{prefix}/{name}")
    return _LockRoot(owner, tuple(files))


def _directories_up_to(start: Path, stop: Path) -> list[Path]:
    """Return `start` and each parent up to and including `stop`. Takes both. Returns them from
    `start` upward. Stops at the filesystem root when `stop` is not reached."""
    found = []
    here = start
    while True:
        found.append(here)
        if here == stop or here.parent == here:
            return found
        here = here.parent


def _note_uncompared(target, owner: Path) -> None:
    """Record that a linked install had no lockfile to compare. Takes the target and the other
    project. Returns nothing."""
    notes = getattr(target, "coverage_notes", None)
    if notes is None:
        return
    note = (f"node_modules is a link into {owner}, which has no lockfile, so the packages there "
            f"were not compared with one.")
    if note not in notes:
        notes.append(note)


def _at_or_above(folder: str, here: str) -> bool:
    """Tell whether a folder is a package's install folder or one of the folders above it. Takes
    both, relative to the target. Returns the answer."""
    return folder == "." or here == folder or here.startswith(f"{folder}/")


def _malicious(advisory, pkg) -> Finding:
    sig = advisory.signature
    cite = f" [{advisory.osv_id}]" if advisory.osv_id else ""
    fix = malware_fix(pkg.name, pkg.version, pkg.ecosystem)
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=pkg.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{pkg.name}@{pkg.version} INSTALLED on disk is known-malicious{cite} "
                 f"(caught even if the lockfile was not edited)",
        vector=sig["category"],
        fix_advice=fix.advice, dependency_state=fix.state, fix_command=fix.command,
        package=fix.package, package_name=fix.name,
        reference=advisory_reference(advisory.osv_id, advisory.aliases), composed_evidence=True)


def _ghost(sig, pkg, listed_at: set | None = None) -> Finding | None:
    if sig is None:
        return None
    if listed_at:
        shown = ", ".join(sorted(v for v in listed_at if v))
        evidence = (f"{pkg.name}@{pkg.version or '?'} is installed, but the lockfile lists {pkg.name} "
                    f"at {shown} — a postinstall may have swapped it")
    else:
        evidence = (f"{pkg.name}@{pkg.version or '?'} is installed but absent from the lockfile — "
                    f"a postinstall may have dropped it off-lockfile")
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=pkg.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=evidence, vector=sig["category"], composed_evidence=True)


def _tampered(sig, t) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=t.path,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{t.package}: {t.detail} — installed file modified after install",
        vector=sig["category"], composed_evidence=True)

def _confirmed_lifecycle_patterns(all_signatures):
    """Compiled patterns of the npm-lifecycle signatures (matcher `npm-manifest`) that are confirmed
    when an INSTALLED dependency carries them — `confidence_when_installed`, else `confidence` — the
    FP-safe install-time IoCs, reused from the signature DB (one source, no copy)."""
    return [(s["id"], re.compile(s["pattern"], re.IGNORECASE))
            for s in (all_signatures or [])
            if s.get("matcher") == "npm-manifest"
            and s.get("confidence_when_installed", s.get("confidence")) != "heuristic"
            and s.get("pattern")]


_DEEP_SWEEP_BUDGET = 500_000_000


def _loader_finding(sig, pkg, rel, kind, hit) -> Finding:
    return Finding(
        signature_id=sig["id"], category=sig["category"],
        severity=Severity.parse(sig["severity"]), path=rel,
        description=sig["description"], remediation=sig.get("remediation", "manual"),
        evidence=f"{pkg.name}@{pkg.version or '?'} {kind} {rel} carries loader fingerprint {hit}",
        vector=sig["category"], composed_evidence=True)


def _scan_file(check, target, rel, budget) -> str | None:
    """Run the confirmed loader check over the full body of `rel`.

    `read_source_windows` is FIFO-safe. Decrements `budget` (a mutable
    1-elt list) by bytes read when given (entries pass None — always scanned). Returns the hit id / None."""
    for _offset, text in target.read_source_windows(rel):
        if budget is not None:
            budget[0] -= len(text)
        hit = check(text)
        if hit:
            return hit
    return None


def _loader_sweep(sig, check, target, tree, pkg, deep, budget, truncated) -> Finding | None:
    """Run the confirmed loader check over a package's ENTRY files (always — the classic entry-loader
    tier, both modes), and — when `deep` — over ALL its other JS-family source files too, so a
    payload in a non-entry file isn't invisible. The non-entry portion draws on a shared byte `budget`
    so a huge/hostile tree can't force unbounded reads; `truncated` is flagged when that (or the
    per-package file cap) drops un-scanned files, so the caller can note the partial coverage. First
    hit wins."""
    for rel in pkg.entries:                       # entries: always scanned, never budget-limited
        hit = _scan_file(check, target, rel, None)
        if hit:
            return _loader_finding(sig, pkg, rel, "entry", hit)
    if not deep:
        return None
    entries = set(pkg.entries)
    for rel in tree.source_files(target, pkg, truncated):
        if rel in entries:
            continue                              # already scanned as an entry above
        if budget[0] <= 0:
            truncated.append(True)                # byte budget spent → remaining files un-scanned
            break
        hit = _scan_file(check, target, rel, budget)
        if hit:
            return _loader_finding(sig, pkg, rel, "file", hit)
    return None


def _lifecycle_hook(sig, patterns, pkg) -> Finding | None:
    for key, cmd in (pkg.hooks or {}).items():
        for pid, rx in patterns:
            if rx.search(cmd):
                return Finding(
                    signature_id=sig["id"], category=sig["category"],
                    severity=Severity.parse(sig["severity"]), path=pkg.path,
                    description=sig["description"], remediation=sig.get("remediation", "manual"),
                    evidence=f"{pkg.name}@{pkg.version or '?'} {key}: {cmd[:80]} (matches {pid})",
                    vector=sig["category"])
    return None

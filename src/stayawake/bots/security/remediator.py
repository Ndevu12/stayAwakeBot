#!/usr/bin/env python3
"""Remediator service: scan local repos → plan fixes → (with apply) fix safely.

Dry-run by default. With apply=True it writes fixes to the working tree (backing
originals up to .malware-quarantine/) and, when the repo was clean beforehand,
commits them to a fresh `security/auto-clean-<stamp>` branch — never main, never a
force-push, never pushed. The human reviews and opens the PR.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from stayawake.core.config import load_yaml
from stayawake.core.adapters import github_api
from stayawake.core import auth
from stayawake.core import git as gitutil
from stayawake.bots.security.signatures import load_signatures
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.service import discover_local_repos, _enclosing_repo_root, DEFAULT_CONFIG
from stayawake.bots.security.targets import ScanOptions, LocalRepoTarget
from stayawake.bots.security.models import CONFIRMED, SUSPECT_HEURISTIC, QUARANTINE_DIR
from stayawake.bots.security import remediation
from stayawake.bots.security import pr as pr_submit


def _residual_auto_fixable(repo: Path, sigs, allowlist, opts) -> list:
    """Re-scan a repo and return only findings that *should* have been auto-fixed —
    i.e. anything the remediator claims to handle but left behind."""
    fs = scan_target(LocalRepoTarget(repo, str(repo), opts), sigs, allowlist).findings
    return [f for f in fs if remediation.is_auto_fixable(f)]


def _options(settings: dict) -> ScanOptions:
    base = ScanOptions()
    return ScanOptions(
        exclude_dirs=set(settings.get("exclude_dirs", base.exclude_dirs)),
        max_file_bytes=int(settings.get("max_file_bytes", base.max_file_bytes)),
        remote_clone_depth=int(settings.get("remote_clone_depth", base.remote_clone_depth)),
    )


def _git(repo: Path, *args: str) -> bool:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0


def _is_clean(repo: Path) -> bool:
    r = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                       capture_output=True, text=True, check=False)
    return r.returncode == 0 and r.stdout.strip() == ""


def _commit_branch(repo: Path, applied) -> str | None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    branch = f"security/auto-clean-{stamp}"
    body = "\n".join(f"- {c.action}: {c.path}" for c in applied)
    if not _git(repo, "checkout", "-b", branch):
        return None
    # git only ignores UNTRACKED paths — untrack any pre-existing tracked quarantine
    # dir so live-malware backups are never committed onto the fix branch.
    _git(repo, "rm", "-r", "--cached", "--ignore-unmatch", QUARANTINE_DIR)
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.name=StayAwakeBot Security",
         "-c", "user.email=security-bot@stayawake.local",
         "commit", "-m", f"security: auto-remediate worm indicators\n\n{body}")
    return branch


def _resolve_config(config_path: str | None):
    """Load the remediation config without ever crashing on a missing file (#1054).
    None → the packaged default if it exists, else an empty config — so `saw fix` and
    `saw scan --fix` work on the current repo with no config, mirroring `saw scan`. An
    explicitly-passed --config that is missing prints a clear, actionable error and
    returns None (the caller exits non-zero) instead of a raw FileNotFoundError."""
    if config_path is None:
        p = Path(DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it "
              "to remediate the current repository.")
        return None
    return load_yaml(config_path)


def _classify(repo: Path, result, content_sig):
    """Split a repo's findings into the three reliable dispositions:
      - recoveries: code-loader findings whose clean version we can safely restore from git,
      - changes:    structure-safe auto-fixes (quarantine fonts / strip exact gitignore lines /
                    drop autorun JSON keys) — never a content reconstruction,
      - manuals:    everything we cannot safely auto-fix, each with a reason + recommended action.
    """
    others = [f for f in result.findings if f.category != "code-loader"]
    changes = remediation.plan(others)
    recoveries: list = []
    manuals: list = []
    # Code-loader findings grouped by PATH (many signatures hit one file). A path with ANY
    # CONFIRMED loader literal is a recovery candidate; a heuristic-ONLY match (a packed/
    # encoded shape that legit inlined assets and minified files also have) is NEVER
    # auto-recovered — it goes to manual review. This mirrors is_auto_fixable's confidence
    # gate and is what prevents destroying a legitimate file when no malware is present.
    cl_by_path: dict = {}
    for f in result.findings:
        if f.category == "code-loader":
            cl_by_path.setdefault(f.path, []).append(f)
    for path, fs in cl_by_path.items():
        confirmed = next((f for f in fs if getattr(f, "confidence", CONFIRMED) == CONFIRMED), None)
        if confirmed is None:                 # heuristic-only → review, never auto-recover
            f = fs[0]
            manuals.append(remediation.Manual(
                path, f.signature_id, SUSPECT_HEURISTIC,
                "heuristic match (a packed/encoded shape that legitimate assets and minified "
                f"files also have) — review. If legitimate, allowlist `{f.signature_id}`; if "
                "malicious, remove it or recover from a clean commit.", getattr(f, "line", None)))
            continue
        disp = remediation.classify_recovery(repo, confirmed, content_sig)
        (recoveries if isinstance(disp, remediation.Recovery) else manuals).append(disp)
    seen_other: set = set()
    for f in others:                          # non-code-loader with no safe auto-fix (evil-merge…)
        if remediation.is_auto_fixable(f) or f.path in cl_by_path or f.path in seen_other:
            continue
        seen_other.add(f.path)
        is_merge = f.category == "evil-merge"
        manuals.append(remediation.Manual(
            f.path, f.signature_id,
            "history-rewrite" if is_merge else "review",
            ("introduced content beyond a clean 3-way merge — needs a history rewrite "
             "(interactive rebase); not auto-fixable."
             if is_merge else f"{f.description[:80]} — review manually."),
            getattr(f, "line", None)))
    return recoveries, changes, manuals


def remediate_scanned(repo: Path, result, *, sigs, allowlist, opts,
                      apply: bool = False, open_pr: bool = False,
                      token: str | None = None) -> Counter:
    """Remediate ONE already-scanned repo and return a Counter of dispositions
    (recover/quarantine/strip/manual). Code-loader findings are RECOVERED from git (the
    file's last clean committed version) or deferred to manual — never surgically edited, so
    a fix can never corrupt valid code. The caller supplies the `ScanResult`, so the same
    analysis that produced the report drives the fix (no re-scan, no report-file coupling)."""
    content_sig = remediation.codeloader_content_sig([s for g in sigs.values() for s in g])
    recoveries, changes, manuals = _classify(repo, result, content_sig)

    tally: Counter = Counter()
    if not (recoveries or changes or manuals):
        return tally

    rel = str(repo).replace(str(Path.home()), "~")
    print(f"\n■ {rel}")
    for rec in recoveries:
        print(f"    recover     {rec.path}   → restore to {rec.label}")
        if rec.diff:
            print(rec.diff)
    for c in changes:
        print(f"    {c.action:11} {c.path}")
    if manuals:
        print("    ⚠ NEEDS REVIEW (auto-fix won't guess):")
        for m in manuals:
            loc = m.path + (f":{m.line}" if m.line else "")
            print(f"      • {loc} — {m.reason}: {m.action}")

    tally["recover"] = len(recoveries)
    tally["quarantine"] = sum(1 for c in changes if c.action == "quarantine")
    tally["strip"] = sum(1 for c in changes if c.action in ("strip-gitignore", "strip-settings"))
    tally["manual"] = len(manuals)

    if not apply:
        return tally
    if open_pr:
        if not token:
            print("    → " + auth.no_credential_hint("opening pull requests") + " Skipped.")
        else:
            print(f"    → {pr_submit.submit_fix_pr(repo, opts, sigs, allowlist, token)}")
        return tally

    # --- local apply: recover (git restore + verify) then the structure-safe changes ---
    was_clean = _is_clean(repo)
    quarantine = remediation.quarantine_path(repo)
    applied: list = []
    for rec in recoveries:
        if remediation.apply_recovery(repo, rec, quarantine, content_sig):
            applied.append(remediation.Change("recover", rec.path, rec.label))
            print(f"    → recovered {rec.path} from {rec.clean_rev[:7]} "
                  f"(original in {QUARANTINE_DIR}/)")
        else:
            print(f"    → could not safely recover {rec.path}; left for manual review.")
    applied += remediation.apply(repo, changes, quarantine)
    # Quarantine any STILL-auto-fixable residue (structure-safe failsafe); code-loader that
    # we couldn't recover stays put and is reported under NEEDS REVIEW (never force-edited).
    residual = _residual_auto_fixable(repo, sigs, allowlist, opts)
    if residual:
        applied += remediation.quarantine_residual(repo, residual, quarantine)
    remediation.ensure_ignored(repo)
    if not applied:
        return tally
    print(f"    → applied {len(applied)} change(s); originals in {QUARANTINE_DIR}/")
    if was_clean:
        branch = _commit_branch(repo, applied)
        print(f"    → committed to branch '{branch}'. Review and open a PR (do NOT push to main)."
              if branch else "    → could not create branch; review `git diff` and commit manually.")
    else:
        print("    → repo had uncommitted changes; left in working tree. Review `git diff`, "
              "then commit to a branch + open a PR.")
    return tally


def remediation_summary(tally: Counter, apply: bool) -> None:
    """Print the dry-run / applied footer + tally. Shared by `saw fix` and `saw scan --fix`."""
    auto = tally["recover"] + tally["quarantine"] + tally["strip"]
    if auto == 0 and tally["manual"] == 0:
        print("\nNo remediable findings.")
        return
    parts = []
    if tally["recover"]:
        parts.append(f"{tally['recover']} recover")
    if tally["quarantine"]:
        parts.append(f"{tally['quarantine']} quarantine")
    if tally["strip"]:
        parts.append(f"{tally['strip']} strip")
    if tally["manual"]:
        parts.append(f"{tally['manual']} need review")
    print(f"\n{'Applied' if apply else 'DRY-RUN'}: " + " · ".join(parts) + ".")
    if not apply and auto:
        print(f"Re-run with --apply (recover/quarantine; originals backed up to {QUARANTINE_DIR}/) "
              "or --apply --pr (push a fix branch + open one PR per repo).")
    if tally["manual"]:
        print("⚠ 'need review' items were NOT auto-fixed — see the reasons above.")


def remediate(config_path: str | None = None, apply: bool = False,
              open_pr: bool = False) -> int:
    """`saw fix`: scan configured/local repos and remediate. Config-optional (#1054) — with
    no config it falls back to the enclosing repository, mirroring `saw scan`. Returns a
    process exit code (0 ok; 2 when an explicitly-passed --config is missing)."""
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 2
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    token, _ = auth.resolve_token()

    # No configured local targets → remediate the repo we're standing in (mirrors `saw scan`).
    local_patterns = cfg.get("targets", {}).get("local", []) or [str(_enclosing_repo_root())]
    tally: Counter = Counter()
    for repo in discover_local_repos(local_patterns, opts):
        result = scan_target(LocalRepoTarget(repo, str(repo), opts), sigs, allowlist)
        tally += remediate_scanned(repo, result, sigs=sigs, allowlist=allowlist, opts=opts,
                                   apply=apply, open_pr=open_pr, token=token)
    remediation_summary(tally, apply)
    return 0


def submit_org_prs(config_path: str | None = None, token: str | None = None) -> int:
    """Event-driven / on-demand org sweep: for each configured GitHub repo, open or
    update ONE de-duplicated remediation PR (clean repos are skipped). Returns the
    number of repos that now have an open fix PR. Config-optional (#1054): a missing
    explicit --config is a clear message (returns 0), never a raw traceback.
    """
    cfg = _resolve_config(config_path)
    if cfg is None:
        return 0
    settings = cfg.get("settings", {})
    opts = _options(settings)
    sigs = load_signatures(settings.get("signatures_path"))
    allowlist = cfg.get("allowlist", [])
    source = "explicit"
    if not token:
        token, source = auth.resolve_token()
    if not token:
        print(auth.no_credential_hint("org remediation PRs") +
              " The token needs repo + pull-request write scope.")
        return 0

    gconf = cfg.get("targets", {}).get("github", {}) or {}
    slugs: list[str] = []
    for kind in ("users", "orgs"):
        for acct in gconf.get(kind, []) or []:
            slugs += github_api.list_repos(acct, kind, token,
                                           gconf.get("include_forks", False),
                                           gconf.get("include_archived", False))
    # With a GitHub App and no explicit accounts, sweep everything the install can see.
    if source == "github-app" and not slugs:
        slugs += github_api.list_installation_repos(token, gconf.get("include_archived", False))
    slugs = sorted(set(slugs))
    if not slugs:
        print("No GitHub targets configured (targets.github.users/orgs or an App installation).")
        return 0

    print(f"Sweeping {len(slugs)} repo(s) for worm indicators…")
    opened = 0
    for slug in slugs:
        tmp = Path(tempfile.mkdtemp(prefix="sab-org-"))
        clone = tmp / "repo"
        # Token via GIT_ASKPASS (env), never in the clone URL/argv.
        with gitutil.github_https_auth(token) as (prefix, env):
            r = subprocess.run(["git", "clone", "--quiet", "--depth", "50",
                                f"{prefix}{slug}.git", str(clone)],
                               capture_output=True, text=True, check=False, env=env)
        if r.returncode != 0:
            print(f"  {slug}: clone failed (check token access)")
            shutil.rmtree(tmp, ignore_errors=True)
            continue
        try:
            outcome = pr_submit.submit_fix_pr(clone, opts, sigs, allowlist, token)
            print(f"  {slug}: {outcome}")
            if "opened PR" in outcome or "updated existing PR" in outcome:
                opened += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print(f"Done. {opened} repo(s) have an open remediation PR (duplicates avoided).")
    return opened

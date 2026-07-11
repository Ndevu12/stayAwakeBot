#!/usr/bin/env python3
"""Submit a remediation as a real pull request — the way a security engineer would.

One stable fix branch per repo (`security/auto-clean`) → one rolling PR per repo.
Before opening, it checks the API for an existing open PR from that branch and
updates it instead of opening a duplicate. All work happens in an isolated git
worktree off the remote's default branch, so the user's working tree is untouched
and the PR contains only the fix. Targets the default branch for human review —
never commits to or force-pushes main.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from stayawake.core.adapters import github_api
from stayawake.core import git as gitutil
from stayawake.core.streaming import status
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR
from stayawake.bots.security import remediation

FIX_BRANCH = "security/auto-clean"
PATCHES_DIR = Path("sab-patches")   # where the read-only fallback writes .patch files
ISSUE_LABEL = "stayawake-security"  # de-dup marker for the issue fallback
_FORK_POLL_TRIES = 10               # async fork readiness: poll up to ~30s
_FORK_POLL_DELAY = 3
_BOT = ("-c", "user.name=StayAwakeBot Security", "-c", "user.email=security-bot@stayawake.local")


def _git(cwd: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args],
                          capture_output=True, text=True, check=False, env=env)


def _untrack_quarantine(repo: Path) -> bool:
    """git only ignores UNTRACKED paths, so untrack any pre-existing tracked
    quarantine dir before staging. Returns True if the quarantine is clean after."""
    _git(repo, "rm", "-r", "--cached", "--ignore-unmatch", QUARANTINE_DIR)
    return not _git(repo, "ls-files", QUARANTINE_DIR).stdout.strip()


def _save_patch(wt: Path, slug: str, out_dir: Path) -> Path | None:
    """Capture the fix commit as a git-am-able patch so a read-only run (no write access)
    never loses the work when the branch can't be pushed. Returns the path, or None on
    failure. This is the no-write floor of the remediation ladder."""
    r = _git(wt, "format-patch", "-1", "HEAD", "--stdout")
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = (out_dir / (slug.replace("/", "-") + ".patch")).resolve()
        dest.write_text(r.stdout, encoding="utf-8")
    except OSError:
        return None
    return dest


def _issue_body(slug: str, findings) -> str:
    lines = [f"StayAwakeBot detected self-propagating worm indicators in `{slug}` and could "
             "not open a fix PR automatically (no write access to this repository).",
             "", "## Indicators", ""]
    for f in findings[:50]:
        loc = f.path + (f":{f.line}" if getattr(f, "line", None) else "")
        lines.append(f"- **[{f.severity.label()}]** `{f.signature_id}` — `{loc}`")
    lines += ["", "A remediation has been generated. To apply it, grant the scanner repo + "
              "pull-request write access for an automated PR, or run "
              "`saw fix --pr` against a local clone to produce a patch.", "",
              "_Opened by StayAwakeBot Security. De-duplicated — re-runs won't open another._"]
    return "\n".join(lines)


def _open_issue_fallback(owner: str, name: str, findings, token: str) -> str | None:
    """Notify the repo via a de-duplicated issue when a fix can't be PR'd. Needs only
    `issues: write`; returns a short outcome, or None if it couldn't open one."""
    try:
        existing = github_api.list_open_issues(owner, name, token, labels=ISSUE_LABEL, quiet=True)
        if existing:
            return f"an open issue already tracks this (#{existing[0].get('number')})"
        issue = github_api.create_issue(
            owner, name, f"StayAwakeBot: worm indicators detected in {owner}/{name}",
            _issue_body(f"{owner}/{name}", findings), token, labels=[ISSUE_LABEL], quiet=True)
        if issue and issue.get("number"):
            return f"opened issue #{issue['number']} ({issue.get('html_url', '')})"
    except Exception:  # noqa: BLE001 — notification is best-effort; never mask the patch result
        pass
    return None


def _wait_for_fork(slug: str, token: str) -> bool:
    """A new fork is created asynchronously; poll until it's queryable (or give up)."""
    owner, name = slug.split("/", 1)
    for attempt in range(_FORK_POLL_TRIES):
        if github_api.get_repo(owner, name, token) is not None:
            return True
        if attempt < _FORK_POLL_TRIES - 1:
            time.sleep(_FORK_POLL_DELAY)
    return False


def _fork_and_pr(wt: Path, owner: str, name: str, base: str, applied, suspicious, token: str) -> str | None:
    """When we can't push to the upstream, push the fix to a fork under the authenticated
    user and open a cross-fork PR. Returns an outcome string when forking is viable
    (success OR a post-fork failure worth reporting), or None when forking isn't possible
    so the caller falls through to the patch/issue floor.

    Handles: no token identity, can't fork (permissions), forking your own repo, async
    fork not ready, push-to-fork failure, duplicate fork PR, and PR-creation failure."""
    # `get_authenticated_user` (GET /user) is enabledForGitHubApps=false, so an installation
    # token (the Actions GITHUB_TOKEN) returns None here — no fork identity. That's fine: under
    # Actions the upstream push succeeds with `contents: write`, so this fork fallback is never
    # reached. The fork path is for a PAT that lacks upstream write but can fork.
    me = (github_api.get_authenticated_user(token, quiet=True) or {}).get("login")
    if not me or me.lower() == owner.lower():
        return None  # no identity, or it's our own repo (a fork wouldn't help)
    fork = github_api.create_fork(owner, name, token, quiet=True)
    fork_slug = fork.get("full_name") if isinstance(fork, dict) else None
    if not fork_slug or "/" not in fork_slug:
        return None  # forking not permitted → fall back
    if not _wait_for_fork(fork_slug, token):
        return f"{owner}/{name}: forked to {fork_slug} but it wasn't ready in time — retry later"
    # Push the fix branch to the fork (token via GIT_ASKPASS, never in URL/argv).
    with gitutil.github_https_auth(token) as (prefix, env):
        pushed = _git(wt, "push", "--force", f"{prefix}{fork_slug}.git",
                      f"{FIX_BRANCH}:{FIX_BRANCH}", env=env).returncode == 0
    if not pushed:
        return None  # couldn't push to the fork either → fall back to patch/issue
    fork_owner = fork_slug.split("/", 1)[0]
    existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token, head_owner=fork_owner)
    if existing:
        pr = existing[0]
        return (f"{owner}/{name}: updated existing fork PR #{pr['number']} "
                f"({pr.get('html_url', '')}) from {fork_slug}")
    pr = github_api.create_pull(owner, name, title="security: auto-remediate worm indicators",
                                head=f"{fork_owner}:{FIX_BRANCH}", base=base,
                                body=_pr_body(f"{owner}/{name}", applied, suspicious), token=token)
    if pr and pr.get("number"):
        return (f"{owner}/{name}: opened fork PR #{pr['number']} ({pr.get('html_url', '')}) "
                f"from {fork_slug}")
    return f"{owner}/{name}: pushed to fork {fork_slug} but PR creation failed (check token scope)"


def slug_from_url(url: str) -> str | None:
    """Parse 'owner/name' from a GitHub SSH or HTTPS remote URL (pure)."""
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url.strip())
    return m.group(1) if m else None


def origin_slug(repo: Path) -> str | None:
    """Return 'owner/name' from the origin remote (SSH or HTTPS), else None."""
    return slug_from_url(_git(repo, "remote", "get-url", "origin").stdout)


def default_branch(repo: Path) -> str:
    out = _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD").stdout.strip()
    return out.rsplit("/", 1)[-1] if out else "main"


def _pr_body(slug: str, changes, suspicious=()) -> str:
    lines = [f"Automated worm remediation for `{slug}` by StayAwakeBot Security Sentinel.",
             "", "## Changes", ""]
    lines += [f"- `{c.action}` — `{c.path}`" for c in changes]
    if suspicious:
        # Honest disclosure: these are heuristic/suspicious findings (a packed/encoded shape a
        # legitimate asset can also have) that were NOT auto-fixed. The confirmed malware above
        # is cleaned; these still need a human eye, so the tree is never presented as fully clean.
        lines += ["", "## ⚠ Still needs review (not auto-fixed)",
                  "", "These are *suspicious* (heuristic) matches — possibly a legitimate inlined "
                  "asset/minified file, possibly a payload the confirmed signatures didn't name. "
                  "Review each; allowlist if legitimate, or remove if not.", ""]
        for f in suspicious[:50]:
            loc = f.path + (f":{f.line}" if getattr(f, "line", None) else "")
            lines.append(f"- `{f.signature_id}` — `{loc}`")
    lines += ["", "Originals are recoverable from git history. Evil-merge findings (if any) "
              "are reported separately and need a manual history rewrite.", "",
              "_Review and merge if correct. This is a single rolling PR — re-runs update it "
              "rather than opening duplicates._"]
    return "\n".join(lines)


@dataclass(frozen=True)
class _Fix:
    """The result of building a fix: the base branch it sits on, and the changes/findings
    used to commit it to FIX_BRANCH and to write the PR body."""
    base: str
    applied: list
    suspicious: list
    findings: list


def _build_fix(repo: Path, opts, signatures, allowlist, *,
               label: str = "", spin: bool = False) -> tuple["_Fix | None", str, Path | None]:
    """Compute the remediation in a throwaway worktree off the default branch and commit it
    to the local `security/auto-clean` branch. Pure git + scan — **no network, no GitHub
    API** — so it works offline and never force-pushes. Returns `(fix, outcome, wt)`:
    `fix` is None for skip/clean/abort (with `outcome` explaining), else the committed fix.
    The CALLER owns the returned worktree `wt` and MUST remove it (the branch ref persists
    after removal, ready to review or push). `label`/`spin` drive phase-accurate spinners
    (`scanning …` then `fixing …`) so a long sweep shows what it's actually doing."""
    base = default_branch(repo)
    # Prefer origin/<base> (fresh if the caller fetched) but fall back to the LOCAL base so
    # `saw fix` works offline / without a remote.
    baseref = (f"origin/{base}"
               if _git(repo, "rev-parse", "--verify", "--quiet", f"origin/{base}").returncode == 0
               else base)
    if _git(repo, "rev-parse", "--verify", "--quiet", baseref).returncode != 0:
        return None, "no default branch to build a fix from — skipped", None

    wt = Path(tempfile.mkdtemp(prefix="sab-fix-"))
    quarantine = Path(tempfile.mkdtemp(prefix="sab-bak-"))  # backups kept OUT of the branch
    if _git(repo, "worktree", "add", "-f", "-B", FIX_BRANCH, str(wt), baseref).returncode != 0:
        return None, "could not create worktree", wt

    content_sig = remediation.codeloader_content_sig([s for g in signatures.values() for s in g])

    def _scan():
        return scan_target(LocalRepoTarget(wt, str(repo), opts), signatures, allowlist).findings

    def _blocking(fs):
        return [f for f in fs if remediation.is_auto_fixable(f)
                or (f.category == "code-loader"
                    and getattr(f, "confidence", "confirmed") == "confirmed")]

    with status(f"scanning {label}…", enabled=spin):       # phase 1: detection (the slow part)
        findings = _scan()

    # phase 2: apply structure-safe fixes, recover code-loaders from git, verify, commit.
    with status(f"fixing {label}…", enabled=spin):
        applied = remediation.apply(wt, remediation.plan(findings), quarantine)
        # CONFIRMED code-loader findings are RECOVERED from git history, never surgically edited
        # — so the fix can never carry corrupted code. Heuristic-only matches are left for review.
        seen_cl: set = set()
        for f in findings:
            if (f.category != "code-loader" or getattr(f, "confidence", "confirmed") != "confirmed"
                    or f.path in seen_cl):
                continue
            seen_cl.add(f.path)
            disp = remediation.classify_recovery(wt, f, content_sig)
            if isinstance(disp, remediation.Recovery) and \
                    remediation.apply_recovery(wt, disp, quarantine, content_sig):
                applied.append(remediation.Change("recover", disp.path, disp.label))

        # Post-apply verification — never leave a fix that is still infected. BLOCKING = anything
        # still auto-fixable OR any CONFIRMED code-loader we couldn't recover; quarantine the
        # auto-fixable, and ABORT if a confirmed infection remains (needs manual review).
        fs = _scan()
        auto = [f for f in _blocking(fs) if remediation.is_auto_fixable(f)]
        if auto:
            applied += remediation.quarantine_residual(wt, auto, quarantine)
            fs = _scan()
        if _blocking(fs):
            return None, (f"ABORTED — {len(_blocking(fs))} finding(s) still present after "
                          "remediation; needs manual review"), wt
        if not applied:
            return None, f"'{base}' already clean — nothing to fix", wt
        suspicious = list(fs)   # heuristic-only residue, disclosed in the PR body

        if not _untrack_quarantine(wt):
            return None, f"ABORTED — could not untrack {QUARANTINE_DIR}/ (would commit backups)", wt
        _git(wt, "add", "-A")
        msg = "security: auto-remediate worm indicators\n\n" + \
              "\n".join(f"- {c.action}: {c.path}" for c in applied)
        _git(wt, *_BOT, "commit", "-m", msg)
    return _Fix(base, applied, suspicious, findings), "", wt


def prepare_fix(repo: Path, opts, signatures, allowlist, *, spin: bool = False) -> str:
    """`saw fix` (no --pr): build the fix on the local `security/auto-clean` branch and STOP.
    No push, no PR, no GitHub API — offline-safe, zero remote writes. The branch is left in
    the repo for the user to review and push (or publish with `saw fix --pr`)."""
    slug = origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        return (f"{slug}: prepared {len(fix.applied)} change(s) on '{FIX_BRANCH}' — review "
                f"`git -C {repo} diff {fix.base}...{FIX_BRANCH}`, then `saw fix --pr` to open a PR")
    finally:
        if wt:
            _git(repo, "worktree", "remove", "--force", str(wt))


def submit_fix_pr(repo: Path, opts, signatures, allowlist, token: str,
                  patches_dir: Path | None = None, *, spin: bool = False) -> str:
    """`saw fix --pr` (and the `--remote` sweep): build the fix, then PUSH `security/auto-clean`
    and open/update one dedup'd PR. If the branch can't be pushed (read-only access), walks the
    fork → patch → issue fallback ladder. Returns an outcome string."""
    slug = origin_slug(repo)
    if not slug:
        # No origin to PR against — still prepare the local branch so the work isn't lost.
        fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist,
                                      label=str(repo).replace(str(Path.home()), "~"), spin=spin)
        try:
            if fix is None:
                return outcome
            return f"no GitHub origin — prepared on '{FIX_BRANCH}'; add a remote and push to open a PR"
        finally:
            if wt:
                _git(repo, "worktree", "remove", "--force", str(wt))

    owner, name = slug.split("/", 1)
    _git(repo, "fetch", "--quiet", "origin", default_branch(repo))
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        base = fix.base
        with status(f"opening PR for {slug}…", enabled=spin):   # phase 3: push + PR / fallback
            # Token via GIT_ASKPASS (env), never in the URL/argv. Push the FIX_BRANCH ref.
            with gitutil.github_https_auth(token) as (prefix, env):
                pushed = _git(wt, "push", "--force", f"{prefix}{slug}.git",
                              f"{FIX_BRANCH}:{FIX_BRANCH}", env=env).returncode == 0
            if not pushed:
                # No write access — fork→PR, else patch + de-duplicated issue.
                forked = _fork_and_pr(wt, owner, name, base, fix.applied, fix.suspicious, token)
                if forked:
                    return forked
                patch = _save_patch(wt, slug, Path(patches_dir) if patches_dir else PATCHES_DIR)
                issue = _open_issue_fallback(owner, name, fix.findings, token)
                bits = []
                if patch:
                    bits.append(f"saved the fix as a patch at {patch} "
                                f"(apply on '{base}' with `git am {patch.name}`)")
                if issue:
                    bits.append(issue)
                if not bits:
                    return f"{slug}: branch push failed (check token write scope)"
                return f"{slug}: push rejected (no write access?) — " + "; ".join(bits) + "."

            existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token)
            if existing:
                pr = existing[0]
                return f"{slug}: updated existing PR #{pr['number']} ({pr.get('html_url','')}) — no duplicate"
            pr = github_api.create_pull(owner, name,
                                        title="security: auto-remediate worm indicators",
                                        head=FIX_BRANCH, base=base,
                                        body=_pr_body(slug, fix.applied, fix.suspicious), token=token)
            if pr and pr.get("number"):
                return f"{slug}: opened PR #{pr['number']} ({pr.get('html_url','')})"
            return f"{slug}: branch pushed but PR API call failed (network/SSL or token scope)"
    finally:
        if wt:
            _git(repo, "worktree", "remove", "--force", str(wt))


# ── discard: the inverse of fix (`saw discard`) ──────────────────────────────────
# Only ever touches the auto-generated FIX_BRANCH — never a real branch. `--branch` is pure
# git (SSL-immune; deleting the remote branch auto-closes its PR); `--pr` uses the API.

def discard_branch(repo: Path) -> str:
    """Delete the local `security/auto-clean` branch and origin's copy, using the repo's own
    `origin` auth (SSH key / credential helper) — no GitHub API, so it works even when the
    API is unreachable. Deleting the remote branch auto-closes any PR opened from it."""
    slug = origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    did: list[str] = []
    if _git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{FIX_BRANCH}").returncode == 0:
        if _git(repo, "branch", "-D", FIX_BRANCH).returncode == 0:
            did.append("local")
    if _git(repo, "ls-remote", "--exit-code", "--heads", "origin", FIX_BRANCH).returncode == 0:
        did.append("remote (PR auto-closed)" if _git(repo, "push", "origin", "--delete",
                   FIX_BRANCH).returncode == 0 else "remote delete FAILED")
    return (f"{slug}: discarded {FIX_BRANCH} ({', '.join(did)})" if did
            else f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard")


def discard_pr(repo: Path, token: str) -> str:
    """Close the open `security/auto-clean` PR on the repo's origin (API), leaving the branch."""
    slug = origin_slug(repo)
    if not slug:
        return f"{str(repo).replace(str(Path.home()), '~')}: no GitHub origin — no PR to discard"
    return discard_remote_pr(slug, token)


def discard_remote_branch(slug: str, token: str) -> str:
    """Delete FIX_BRANCH on a remote repo by slug, with no local clone — `git push --delete`
    straight to the authed URL (git TLS, SSL-immune). Auto-closes any PR from the branch."""
    with gitutil.github_https_auth(token) as (prefix, env):
        ls = subprocess.run(["git", "ls-remote", "--heads", f"{prefix}{slug}.git", FIX_BRANCH],
                            capture_output=True, text=True, env=env, check=False)
        if not ls.stdout.strip():
            return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"
        ok = subprocess.run(["git", "push", f"{prefix}{slug}.git", "--delete", FIX_BRANCH],
                            capture_output=True, text=True, env=env, check=False).returncode == 0
    return f"{slug}: deleted {FIX_BRANCH} (PR auto-closed)" if ok else f"{slug}: remote delete failed"


def discard_remote_pr(slug: str, token: str) -> str:
    """Close the open FIX_BRANCH PR(s) on a remote repo by slug (API)."""
    owner, name = slug.split("/", 1)
    existing = github_api.list_open_pulls(owner, name, FIX_BRANCH, token)
    if not existing:
        return f"{slug}: no open '{FIX_BRANCH}' PR"
    closed = [f"#{p['number']}" for p in existing
              if github_api.close_pull(owner, name, p["number"], token)]
    return (f"{slug}: closed PR {', '.join(closed)}" if closed
            else f"{slug}: failed to close PR (network/SSL or token scope)")

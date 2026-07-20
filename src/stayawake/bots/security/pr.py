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

import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.core.adapters import github_api
from stayawake.core import git as gitutil
from stayawake.utils import textsafe
from stayawake.utils.streaming import status
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR, CONFIRMED
from stayawake.bots.security import remediation
from stayawake.bots.security import proposal

FIX_BRANCH = "security/auto-clean"
ISSUE_LABEL = "stayawake-security"  # de-dup marker for the issue fallback
PARTIAL_LABEL = "security: partial" # marks a PR that fixes SOME but not all indicators (#1183)


def _mark_partial(outcome: str, partial: bool) -> str:
    """Guarantee a PARTIAL fix's outcome carries the marker so `remediator.fix` counts it as
    needs-review and the run exits non-zero (#1183 invariant #1) — NO MATTER which push / PR /
    fork / patch / issue branch produced it. This single structural gate replaces per-branch
    tagging, which an adversarial pass proved too easy to forget (four fallback returns dropped it,
    silently reporting a still-infected partial fix as a clean exit 0)."""
    return outcome if (not partial or "PARTIAL" in outcome) else f"{outcome}  [PARTIAL — manual review required]"


def manual_review_lines(manual, limit: int = 20) -> str:
    """Per-finding manual-review guidance for `saw fix`'s CLI stream (#1184): each residual as
    location + reason-code + the recommended (inspect-before-running) command classify_recovery
    already computed. Empty when there is no residual. Every field is `_plain`-sanitized (a crafted
    path can't inject terminal/Actions control sequences), the list is bounded (`…and N more`), and
    only locations / reasons / commands are shown — the payload bytes are NEVER echoed (#1184
    invariants 2–4). Recovery commands keep their 'review the diff before running' framing;
    validating a recovery sha's ancestry is #1185's source-trust rule."""
    if not manual:
        return ""
    lines = ["", "    Manual review needed (inspect before running any command):"]
    for m in manual[:limit]:
        loc = m.path + (f":{m.line}" if getattr(m, "line", None) else "")
        lines.append(f"      • {textsafe.plain(loc)}  ({textsafe.plain(getattr(m, 'reason', ''), 40)})")
        action = textsafe.plain(getattr(m, "action", ""), 300)
        if action:
            lines.append(f"        {action}")
    if len(manual) > limit:
        lines.append(f"      …and {len(manual) - limit} more")
    return "\n".join(lines)


def _untrack_quarantine(repo: Path) -> bool:
    """git only ignores UNTRACKED paths, so untrack any pre-existing tracked
    quarantine dir before staging. Returns True if the quarantine is clean after."""
    gitutil.unstage_cached(repo, QUARANTINE_DIR)
    return not gitutil.tracked_under(repo, QUARANTINE_DIR)


def _issue_body(slug: str, findings) -> str:
    # Same injection-safety contract as _pr_body (#1183 invariant #5): the slug, signature ids and
    # attacker-controlled paths all go through _code so a path like `x`](evil) can't inject markup.
    lines = [f"StayAwakeBot detected self-propagating worm indicators in {textsafe.code(slug)} and could "
             "not open a fix PR automatically (no write access to this repository).",
             "", "## Indicators", ""]
    for f in findings[:50]:
        loc = f.path + (f":{f.line}" if getattr(f, "line", None) else "")
        lines.append(f"- **[{textsafe.sanitize(f.severity.label(), 20)}]** {textsafe.code(f.signature_id)} — {textsafe.code(loc)}")
    lines += ["", "A remediation has been generated. To apply it, grant the scanner repo + "
              "pull-request write access for an automated PR, or run "
              "`saw fix --pr` against a local clone to produce a patch.", "",
              "_Opened by StayAwakeBot Security. De-duplicated — re-runs won't open another._"]
    return "\n".join(lines)


def _issue_spec(owner: str, name: str, findings) -> proposal.IssueSpec:
    """Build the de-duplicated notify issue for `saw fix`'s read-only floor: the findings-derived
    body (injection-safe) plus the fix dedup label. The generic filing/dedup lives in
    `proposal.file_dedup_issue`; the worm-specific content lives here."""
    return proposal.IssueSpec(
        title=f"StayAwakeBot: worm indicators detected in {owner}/{name}",
        body=_issue_body(f"{owner}/{name}", findings), label=ISSUE_LABEL)


def _reconcile_partial_label(owner: str, name: str, number: int, partial: bool, token: str) -> None:
    """Keep the `security: partial` label in sync with the fix's state (best-effort, never
    raises for the caller): add it on a partial fix, drop it when a re-run comes back fully clean
    so a rolling PR that gets finished isn't left wrongly flagged (#1183 invariants #2, #4)."""
    if partial:
        github_api.add_labels(owner, name, number, [PARTIAL_LABEL], token, quiet=True)
    else:
        github_api.remove_label(owner, name, number, PARTIAL_LABEL, token, quiet=True)


def _render_submit(res: proposal.SubmitResult, *, slug: str, base: str, partial: bool) -> str:
    """Render a `proposal.SubmitResult` into `saw fix`'s exact operator outcome — the fix-domain
    wording (the PARTIAL tag, the 'auto-clean' framing) lives HERE, never in the shared seam. The
    single `_mark_partial` choke point still wraps this return (#1183 invariant #1)."""
    semi = "PARTIAL (manual review required); " if partial else ""   # upstream-PR tag placement
    dash = "PARTIAL (manual review required) — " if partial else ""  # fork / floor tag placement
    if res.kind == "pr":
        if res.action == "updated":
            return f"{slug}: {semi}updated existing PR #{res.number} ({res.url}) — no duplicate"
        return f"{slug}: {semi}opened PR #{res.number} ({res.url})"
    if res.kind == "pr-create-failed":
        return f"{slug}: branch pushed but PR API call failed (network/SSL or token scope)"
    if res.kind == "fork-pr":
        verb = "updated existing fork PR" if res.action == "updated" else "opened fork PR"
        return f"{slug}: {dash}{verb} #{res.number} ({res.url}) from {res.fork_slug}"
    if res.kind == "fork-not-ready":
        return f"{slug}: forked to {res.fork_slug} but it wasn't ready in time — retry later"
    if res.kind == "fork-pr-create-failed":
        return f"{slug}: pushed to fork {res.fork_slug} but PR creation failed (check token scope)"
    # floor: patch and/or de-duplicated issue (or, if neither landed, an honest push failure).
    bits = []
    if res.patch_path:
        bits.append(f"saved the fix as a patch at {res.patch_path} "
                    f"(apply on '{base}' with `git am {res.patch_path.name}`)")
    if res.issue_note:
        bits.append(res.issue_note)
    if not bits:
        return f"{slug}: branch push failed (check token write scope)"
    return (f"{slug}: {dash}push rejected (no write access, or the branch requires "
            "signed commits?) — " + "; ".join(bits) + ".")


def _pr_body(slug: str, changes, suspicious=(), manual=()) -> str:
    """Render the PR body. `manual` (residual CONFIRMED findings that couldn't be auto-fixed)
    makes this a PARTIAL fix (#1183): the body says so loudly and lists each residual as a
    checklist. All untrusted text (paths, reasons) goes through `_code`/`_sanitize` (invariant #5)."""
    partial = bool(manual)
    lines = [
        (f"**⚠ PARTIAL remediation for {textsafe.code(slug)}** by StayAwakeBot Security Sentinel — this "
         "branch applies what is provably safe but is **NOT a clean tree** (see below)."
         if partial else
         f"Automated worm remediation for {textsafe.code(slug)} by StayAwakeBot Security Sentinel."),
        "", "## Changes applied", ""]
    change_lines = [f"- {textsafe.code(c.action, 40)} — {textsafe.code(c.path)}" for c in changes[:200]]
    if len(changes) > 200:                    # bound the body — a hostile tree can't bloat it
        change_lines.append(f"- …and {len(changes) - 200} more")
    lines += change_lines or ["- (none)"]
    if manual:
        # The honest heart of a partial fix: confirmed indicators that we did NOT touch (a
        # code-loader with no safe git recovery), each with its reason + recommended action. The
        # tree is never presented as clean — the gate stays red and this list says why.
        lines += ["", "## 🚨 Still infected — confirmed indicators NOT auto-fixed (manual action required)",
                  "", f"**{len(manual)} confirmed finding(s) could not be safely auto-remediated and "
                  "remain in this tree.** Do NOT merge this as a completed fix — the security gate stays "
                  "red. Resolve each, then re-run `saw fix --pr`:", ""]
        for m in manual[:50]:
            loc = m.path + (f":{m.line}" if getattr(m, "line", None) else "")
            # Every attacker-influenced field goes through _code — reason/action embed the raw path
            # (via classify_recovery), so rendering them BARE would let a path like `[x](evil)` inject
            # a link/image/HTML. Inside a code span they render literally (adversarial catch, #1183 #5).
            lines.append(f"- [ ] {textsafe.code(loc)} — {textsafe.code(getattr(m, 'signature_id', ''))} "
                         f"({textsafe.code(getattr(m, 'reason', ''), 40)}): "
                         f"{textsafe.code(getattr(m, 'action', ''))}")
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
            lines.append(f"- {textsafe.code(f.signature_id)} — {textsafe.code(loc)}")
    lines += ["", "Originals are recoverable from git history. Evil-merge findings (if any) "
              "are reported separately and need a manual history rewrite.", "",
              "_Review and merge if correct. This is a single rolling PR — re-runs update it "
              "rather than opening duplicates._"]
    return "\n".join(lines)


@dataclass(frozen=True)
class _Fix:
    """The result of building a fix: the base branch it sits on, and the changes/findings
    used to commit it to FIX_BRANCH and to write the PR body. `manual` holds the residual
    CONFIRMED findings that could NOT be auto-fixed — non-empty means a PARTIAL fix (#1183):
    the safe changes still ship, but the tree is not clean and the PR/gate must say so.
    `signed` is False when the fix commit had to be landed with signing forced OFF (the repo
    wanted signed commits but signing couldn't complete in the worktree)."""
    base: str
    applied: list
    suspicious: list
    findings: list
    manual: tuple = ()
    signed: bool = True

    @property
    def partial(self) -> bool:
        return bool(self.manual)


def _signing_note(fix: "_Fix | None") -> str:
    """A one-line ⚠ warning appended to the operator's outcome when the fix commit is UNSIGNED
    (signing failed in the worktree, so it was committed with `commit.gpgsign=false`). Empty
    otherwise. The fix still lands — but a repo that enforces signed commits will reject the
    push/merge until the branch is re-signed, so the operator must be told rather than left to
    wonder why the push bounced."""
    if fix is None or fix.signed:
        return ""
    return (f"\n    ⚠ the fix commit on '{FIX_BRANCH}' is UNSIGNED (commit signing failed in the "
            "worktree); if this repo enforces signed commits, re-sign it before pushing/merging.")


def _build_fix(repo: Path, opts, signatures, allowlist, *,
               label: str = "", spin: bool = False) -> tuple["_Fix | None", str, Path | None]:
    """Compute the remediation in a throwaway worktree off the default branch and commit it
    to the local `security/auto-clean` branch. Pure git + scan — **no network, no GitHub
    API** — so it works offline and never force-pushes. Returns `(fix, outcome, wt)`:
    `fix` is None for skip/clean/abort (with `outcome` explaining), else the committed fix.
    The CALLER owns the returned worktree `wt` and MUST remove it (the branch ref persists
    after removal, ready to review or push). `label`/`spin` drive phase-accurate spinners
    (`scanning …` then `fixing …`) so a long sweep shows what it's actually doing."""
    base = gitutil.default_branch(repo)
    # Prefer origin/<base> (fresh if the caller fetched) but fall back to the LOCAL base so
    # `saw fix` works offline / without a remote.
    baseref = f"origin/{base}" if gitutil.ref_exists(repo, f"origin/{base}") else base
    if not gitutil.ref_exists(repo, baseref):
        return None, "no default branch to build a fix from — skipped", None

    wt = Path(tempfile.mkdtemp(prefix="sab-fix-"))
    quarantine = Path(tempfile.mkdtemp(prefix="sab-bak-"))  # backups kept OUT of the branch
    if not gitutil.add_worktree(repo, wt, FIX_BRANCH, baseref):
        return None, "could not create worktree", wt

    content_sig = remediation.codeloader_content_sig([s for g in signatures.values() for s in g])

    def _scan():
        return scan_target(LocalRepoTarget(wt, str(repo), opts), signatures, allowlist).findings

    def _is_blocking(f):
        # Keeps the tree infected iff it would drive the scanner's INFECTED verdict — i.e. ANY
        # CONFIRMED finding (models.ScanResult.verdict = INFECTED when any f.confidence == CONFIRMED).
        # Auto-fixable findings are confirmed and get fixed/quarantined; confirmed non-auto-fixable
        # ones (code-loader, exfil, npm-lifecycle, supply-chain, evil-merge) go to the manual
        # checklist. Only a HEURISTIC finding is "suspicious" (non-blocking). Keying on code-loader
        # alone silently demoted confirmed non-loader malware to suspicious/clean (adversarial catch).
        return getattr(f, "confidence", CONFIRMED) == CONFIRMED

    def _blocking(fs):
        return [f for f in fs if _is_blocking(f)]

    with status(f"scanning {label}…", enabled=spin):       # phase 1: detection (the slow part)
        findings = _scan()

    # phase 2: apply structure-safe fixes, recover code-loaders from git, verify, commit.
    with status(f"fixing {label}…", enabled=spin):
        applied = remediation.apply(wt, remediation.plan(findings), quarantine)
        # CONFIRMED code-loader findings are RECOVERED from git history, never surgically edited
        # — so the fix can never carry corrupted code. When there is no PROVABLY-safe recovery the
        # finding is deferred to MANUAL review (captured here with its reason), never touched.
        seen_cl: set = set()
        manual_reviews: dict = {}          # path -> remediation.Manual (couldn't safely auto-fix)
        for f in findings:
            if (f.category != "code-loader" or getattr(f, "confidence", "confirmed") != "confirmed"
                    or f.path in seen_cl):
                continue
            seen_cl.add(f.path)
            disp = remediation.classify_recovery(wt, f, content_sig)
            if isinstance(disp, remediation.Recovery) and \
                    remediation.apply_recovery(wt, disp, quarantine, content_sig):
                applied.append(remediation.Change("recover", disp.path, disp.label))
            elif isinstance(disp, remediation.Manual):
                manual_reviews[disp.path] = disp   # no safe recovery → carry reason + action

        # Post-apply verification — never leave a fix presented as clean while infected. BLOCKING =
        # still auto-fixable OR any CONFIRMED code-loader we couldn't recover; quarantine the
        # auto-fixable residue (fail-safe), then re-scan for the ground-truth residual.
        fs = _scan()
        auto = [f for f in _blocking(fs) if remediation.is_auto_fixable(f)]
        if auto:
            applied += remediation.quarantine_residual(wt, auto, quarantine)
            fs = _scan()
        residual = _blocking(fs)
        suspicious = [f for f in fs if not _is_blocking(f)]   # heuristic-only residue
        # Every residual (confirmed finding still present) becomes a manual-review item, built from
        # the GROUND-TRUTH re-scan — a captured recovery reason where we have one, else a generic
        # note. The tree is never called clean while `manual` is non-empty.
        manual: list = []
        for path in sorted({f.path for f in residual}):
            m = manual_reviews.get(path)
            if m is None:
                f0 = next(f for f in residual if f.path == path)
                m = remediation.Manual(
                    path, f0.signature_id, "residual",
                    "Confirmed indicator still present after remediation — review and "
                    "remove/recover manually.", getattr(f0, "line", None))
            manual.append(m)

        if not applied:
            # Nothing was provably safe to ship. If confirmed findings remain, return a NOTIFY-ONLY
            # fix (no changes committed, `applied` empty) so the caller files a de-duplicated
            # manual-review issue and keeps the gate red — better than a silent dead-end (#1183).
            # Otherwise the tree was already clean.
            if residual:
                return _Fix(base, [], suspicious, findings, tuple(manual)), "", wt
            return None, f"'{base}' already clean — nothing to fix", wt

        # applied ≥ 1. If confirmed findings remain, this is a PARTIAL fix (#1183): ship the safe
        # changes and list every residual as manual-review work. The tree is never called clean.
        if not _untrack_quarantine(wt):
            return None, f"ABORTED — could not untrack {QUARANTINE_DIR}/ (would commit backups)", wt
        if not gitutil.stage_all(wt):
            return None, "ABORTED — could not stage the fix (git add failed)", wt
        subject = ("security: partial auto-remediation (manual review required)" if manual
                   else "security: auto-remediate worm indicators")
        msg = subject + "\n\n" + "\n".join(f"- {c.action}: {c.path}" for c in applied)
        # commit_fix checks the result and retries UNSIGNED if signing fails — so the branch
        # always advances (no phantom "prepared N" on an empty branch) and we learn whether the
        # commit is unsigned (surfaced to the operator via `_signing_note`).
        commit = gitutil.commit_fix(wt, msg)
        if not commit.committed:
            return None, "ABORTED — could not commit the fix (git commit failed)", wt
    return _Fix(base, applied, suspicious, findings, tuple(manual), signed=commit.signed), "", wt


def prepare_fix(repo: Path, opts, signatures, allowlist, *, spin: bool = False) -> str:
    """`saw fix` (no --pr): build the fix on the local `security/auto-clean` branch and STOP.
    No push, no PR, no GitHub API — offline-safe, zero remote writes. The branch is left in
    the repo for the user to review and push (or publish with `saw fix --pr`)."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied:
            # Nothing safely fixable, confirmed findings remain (#1183). `saw fix` (no --pr) does no
            # network, so it just reports the abort; `saw fix --pr` additionally files an issue.
            return (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                    "need manual review") + manual_review_lines(fix.manual)
        if fix.partial:
            return (f"{slug}: PARTIAL — prepared {len(fix.applied)} safe change(s) on '{FIX_BRANCH}', "
                    f"but {len(fix.manual)} confirmed finding(s) still need manual review "
                    f"(`git -C {repo} diff {fix.base}...{FIX_BRANCH}`)"
                    ) + _signing_note(fix) + manual_review_lines(fix.manual)
        return (f"{slug}: prepared {len(fix.applied)} change(s) on '{FIX_BRANCH}' — review "
                f"`git -C {repo} diff {fix.base}...{FIX_BRANCH}`, then `saw fix --pr` to open a PR"
                ) + _signing_note(fix)
    finally:
        if wt:
            gitutil.remove_worktree(repo, wt)


def submit_fix_pr(repo: Path, opts, signatures, allowlist, token: str,
                  patches_dir: Path | None = None, *, spin: bool = False) -> str:
    """`saw fix --pr` (and the `--remote` sweep): build the fix, then PUSH `security/auto-clean`
    and open/update one dedup'd PR. If the branch can't be pushed (read-only access), walks the
    fork → patch → issue fallback ladder. Returns an outcome string."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        # No origin to PR against — still prepare the local branch so the work isn't lost.
        fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist,
                                      label=str(repo).replace(str(Path.home()), "~"), spin=spin)
        try:
            if fix is None:
                return outcome
            if not fix.applied:
                return (f"ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                        "need manual review (no GitHub origin — cannot file an issue)"
                        ) + manual_review_lines(fix.manual)
            return _mark_partial(
                f"no GitHub origin — prepared on '{FIX_BRANCH}'; add a remote and push to open a PR",
                fix.partial) + _signing_note(fix) + manual_review_lines(fix.manual)
        finally:
            if wt:
                gitutil.remove_worktree(repo, wt)

    owner, name = slug.split("/", 1)
    gitutil.fetch(repo, "origin", gitutil.default_branch(repo))
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied:
            # Nothing safely fixable but confirmed indicators remain (#1183): there is no branch/PR
            # to push, so file a de-duplicated manual-review issue (the read-only floor's mechanism)
            # and abort with the count. The gate stays red (outcome carries ABORTED). Degrades
            # gracefully — no issue permission just drops the note, still aborts.
            with status(f"filing manual-review issue for {slug}…", enabled=spin):
                issue = proposal.file_dedup_issue(owner, name,
                                                  _issue_spec(owner, name, fix.findings), token)
            note = f"; {issue}" if issue else ""
            return (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                    f"need manual review{note}") + manual_review_lines(fix.manual)
        base = fix.base

        def _publish() -> str:
          with status(f"opening PR for {slug}…", enabled=spin):   # phase 3: push + PR / fallback
            # PARTIAL (#1183): the safe changes are pushed, but confirmed findings remain. Say so in
            # the title/body/label; the outcome carries 'PARTIAL' so the run exits non-zero.
            partial = fix.partial
            title = ("security: PARTIAL auto-remediation — manual review required" if partial
                     else "security: auto-remediate worm indicators")
            body = _pr_body(slug, fix.applied, fix.suspicious, fix.manual)
            # The shared ladder does push → fork → patch → dedup-issue and returns structured facts;
            # fix owns the outcome wording (`_render_submit`) and the PARTIAL label reconcile.
            res = proposal.submit_change_pr(wt, slug, base, branch=FIX_BRANCH, title=title,
                                            body=body, token=token,
                                            issue=_issue_spec(owner, name, fix.findings),
                                            patches_dir=patches_dir)
            if res.number is not None and res.kind in ("pr", "fork-pr"):
                _reconcile_partial_label(owner, name, res.number, partial, token)
            return _render_submit(res, slug=slug, base=base, partial=partial)

        # Single choke point: whatever branch _publish() returned, a PARTIAL fix is guaranteed to be
        # marked needs-review here (#1183 invariant #1) — no fallback path can silently pass clean —
        # and the per-finding manual-review guidance + any unsigned-commit warning are appended.
        return (_mark_partial(_publish(), fix.partial)
                + _signing_note(fix) + manual_review_lines(fix.manual))
    finally:
        if wt:
            gitutil.remove_worktree(repo, wt)


# ── discard: the inverse of fix (`saw discard`) ──────────────────────────────────
# Only ever touches the auto-generated FIX_BRANCH — never a real branch. `--branch` is pure
# git (SSL-immune; deleting the remote branch auto-closes its PR); `--pr` uses the API.

def discard_branch(repo: Path) -> str:
    """Delete the local `security/auto-clean` branch and origin's copy, using the repo's own
    `origin` auth (SSH key / credential helper) — no GitHub API, so it works even when the
    API is unreachable. Deleting the remote branch auto-closes any PR opened from it."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    did: list[str] = []
    failed: list[str] = []
    if gitutil.ref_exists(repo, f"refs/heads/{FIX_BRANCH}"):
        # Fail loud: a local `git branch -D` can be REFUSED (the branch is checked out — in the
        # working tree or a leftover fix worktree), and swallowing that used to report success.
        (did if gitutil.delete_branch(repo, FIX_BRANCH) else failed).append("local")
    if gitutil.remote_has_branch("origin", FIX_BRANCH, repo=repo):
        (did if gitutil.delete_remote_branch("origin", FIX_BRANCH, repo=repo)
         else failed).append("remote")
    if failed:
        # Never claim a discard we didn't make. Note any arm that DID succeed so a partial is honest.
        done = f"; deleted {', '.join(did)}" if did else ""
        return (f"{slug}: FAILED to delete {FIX_BRANCH} ({', '.join(failed)}) — "
                f"is it checked out?{done}")
    if did:
        note = " (PR auto-closed)" if "remote" in did else ""
        return f"{slug}: discarded {FIX_BRANCH} ({', '.join(did)}){note}"
    return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"


def discard_pr(repo: Path, token: str) -> str:
    """Close the open `security/auto-clean` PR on the repo's origin (API), leaving the branch."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        return f"{str(repo).replace(str(Path.home()), '~')}: no GitHub origin — no PR to discard"
    return discard_remote_pr(slug, token)


def discard_remote_branch(slug: str, token: str) -> str:
    """Delete FIX_BRANCH on a remote repo by slug, with no local clone — `git push --delete`
    straight to the authed URL (git TLS, SSL-immune). Auto-closes any PR from the branch."""
    with gitutil.github_https_auth(token) as (prefix, env):
        url = f"{prefix}{slug}.git"
        if not gitutil.remote_has_branch(url, FIX_BRANCH, env=env):
            return f"{slug}: no '{FIX_BRANCH}' branch — nothing to discard"
        ok = gitutil.delete_remote_branch(url, FIX_BRANCH, env=env)
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

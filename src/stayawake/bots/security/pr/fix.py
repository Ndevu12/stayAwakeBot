#!/usr/bin/env python3
"""`saw fix` — build the remediation change set, prepare it into the working tree, or submit it as a PR (proposed-only). Includes the small pre/post-submit git & label helpers."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.utils.streaming import status
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR, CONFIRMED
from stayawake.bots.security import remediation
from stayawake.core import proposal
from stayawake.bots.security.pr.constants import FIX_BRANCH, PARTIAL_LABEL
from stayawake.bots.security.pr.render import (
    manual_review_lines, computed_review_lines, suspicious_review_lines,
    _issue_spec, _mark_partial, _pr_body, _render_submit)

def _untrack_quarantine(repo: Path) -> bool:
    """git only ignores UNTRACKED paths, so untrack any pre-existing tracked
    quarantine dir before staging. Returns True if the quarantine is clean after."""
    gitutil.unstage_cached(repo, QUARANTINE_DIR)
    return not gitutil.tracked_under(repo, QUARANTINE_DIR)


def _reconcile_partial_label(owner: str, name: str, number: int, partial: bool, token: str) -> None:
    """Keep the `security: partial` label in sync with the fix's state (best-effort, never
    raises for the caller): add it on a partial fix, drop it when a re-run comes back fully clean
    so a rolling PR that gets finished isn't left wrongly flagged (#1183 invariants #2, #4)."""
    if partial:
        github_api.add_labels(owner, name, number, [PARTIAL_LABEL], token, quiet=True)
    else:
        github_api.remove_label(owner, name, number, PARTIAL_LABEL, token, quiet=True)


@dataclass(frozen=True)
class _Fix:
    """The result of building a fix: the base branch it sits on, and the changes/findings used to
    commit it to FIX_BRANCH and write the PR body. `applied` are the TRUSTED (structure-safe +
    git-corroborated) changes; `computed` are the #1209 review-required strips — applied on a SEPARATE
    commit but NOT git-corroborated, so they keep the run needs-review until a human reviews them.
    `manual` holds residual CONFIRMED findings that could NOT be auto-fixed. Any of `computed`/`manual`
    non-empty means a PARTIAL fix (#1183/#1209): the safe changes still ship, but the tree is not a
    trusted-clean one and the PR/gate must say so. `signed` is False when either fix commit had to be
    landed with signing forced OFF (the repo wanted signed commits but signing couldn't complete)."""
    base: str
    applied: list
    computed: tuple = ()
    suspicious: list = ()
    findings: list = ()
    manual: tuple = ()
    signed: bool = True

    @property
    def partial(self) -> bool:
        # A computed strip is applied but NOT git-corroborated — it MUST be reviewed before merge, so
        # a run carrying one is needs-review (gate red / exit 1) exactly like a residual manual item.
        # The `computed` arm is LOAD-BEARING, not redundant: after a computed strip the post-strip
        # rescan can report the tree CLEAN (empty `manual`), so `bool(self.computed)` is the only thing
        # that keeps a not-git-corroborated tree from going green. See the invariant at the `fs =
        # _scan()` rescan site in `_build_fix` (#1209/#1290) before touching this. Do NOT reduce to
        # `bool(self.manual)`.
        return bool(self.manual) or bool(self.computed)


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


def _manual_for(f0, path: str) -> "remediation.Manual":
    """Build the manual-review entry for a confirmed residual finding. Most are working-tree files
    ("remove/recover manually"), but an EVIL-MERGE finding is keyed to a merge COMMIT (`path` is the
    SHA, `related_paths` the files it introduced), so a generic "remove this from the file" is
    nonsensical. It gets history-provenance guidance instead: `saw fix` never rewrites history — that
    breaks every clone/fork/tag and is the maintainer's decision — so the honest action is to verify
    the payload's reach and decide on a rewrite by hand."""
    if getattr(f0, "vector", None) == "evil-merge":
        files = ", ".join(getattr(f0, "related_paths", ()) or []) or "see evidence"
        return remediation.Manual(
            path, f0.signature_id, "evil-merge",
            "Worm payload smuggled via this merge COMMIT (a history finding, not a file edit; "
            f"files: {files}). `saw fix` never rewrites history — it breaks clones/forks/tags. If the "
            "payload is gone from your working tree the tree is clean but the commit persists; verify "
            "no fork/tag still ships it, then decide on a history rewrite (git filter-repo) yourself.",
            getattr(f0, "line", None))
    return remediation.Manual(
        path, f0.signature_id, "residual",
        "Confirmed indicator still present after remediation — review and remove/recover manually.",
        getattr(f0, "line", None))


def _suspicious_only_outcome(label: str, fix: "_Fix") -> str:
    """The `saw fix` outcome for a repo whose ONLY findings are heuristic/suspicious — nothing
    confirmed, nothing auto-fixable. It DISCLOSES the set and defers to review, deliberately WITHOUT
    an `ABORTED`/`PARTIAL`/`error` marker so the run stays exit 0, consistent with a suspicious `saw
    scan` (which exits 0). This is the #1360 fix: `saw fix` must never call such a repo 'already
    clean' while `saw scan`/`saw hook` flag it — a self-contradiction that erodes trust."""
    n = len(fix.suspicious)
    plural = "" if n == 1 else "s"
    return (f"{label}: {n} suspicious (heuristic) finding{plural} — not auto-remediable; "
            "review with `saw scan` (not asserted as malware)") + suspicious_review_lines(fix.suspicious)


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

    # phase 2: apply the TRUSTED tier (structure-safe fixes + git-corroborated recoveries) and commit
    # it, then apply the COMPUTED #1209 strips (structurally proven but NOT git-corroborated) as a
    # SEPARATE, review-required commit — two trust levels, two commits, in one rolling PR.
    with status(f"fixing {label}…", enabled=spin):
        applied = remediation.apply(wt, remediation.plan(findings), quarantine)
        # CONFIRMED code-loader findings are RECOVERED from git history, never surgically edited. A
        # git-corroborated recovery is applied now (trusted tier). One with no clean ancestor but a
        # structurally-proven strip is a Suggested → applied as the separate computed tier below
        # (#1209). No safe fix at all → deferred to MANUAL, never touched.
        seen_cl: set = set()
        manual_reviews: dict = {}          # path -> Manual (no safe recovery at all)
        suggested: list = []               # Suggested dispositions to apply as the computed tier
        # #1363 PR2: a file BORN via an evil merge has no first-parent clean ancestor, so its code-loader
        # recovery would defer to manual. The evil-merge finding names the merge (commit_sha) and the
        # files it introduced (related_paths); the merge's clean 3-way auto-merge blob is a recovery
        # source for exactly those files. Offered to classify_recovery as a REVIEW-required Suggested
        # (second-parent-derived → never auto-applied). Map is path -> clean-merge blob.
        merge_clean: dict = {}
        for f in findings:
            if getattr(f, "vector", None) != "evil-merge" or not getattr(f, "commit_sha", None):
                continue
            for rp in getattr(f, "related_paths", ()):
                if rp not in merge_clean:
                    blob = gitutil.clean_merge_blob(wt, f.commit_sha, rp)
                    if blob is not None:
                        merge_clean[rp] = blob
        for f in findings:
            if (f.category != "code-loader" or getattr(f, "confidence", "confirmed") != "confirmed"
                    or f.path in seen_cl):
                continue
            seen_cl.add(f.path)
            disp = remediation.classify_recovery(wt, f, content_sig, merge_clean=merge_clean.get(f.path))
            if isinstance(disp, remediation.Recovery) and \
                    remediation.apply_recovery(wt, disp, quarantine, content_sig):
                applied.append(remediation.Change("recover", disp.path, disp.label))
            elif isinstance(disp, remediation.Suggested):
                suggested.append(disp)     # computed strip → applied + committed separately below
            elif isinstance(disp, remediation.Manual):
                manual_reviews[disp.path] = disp

        # Quarantine any AUTO-FIXABLE residue of the trusted tier (fail-safe). The computed-tier
        # payloads are code-loaders (NOT auto-fixable), so they survive here untouched — to be
        # applied as the separate review-required commit, never swept into the trusted commit.
        auto = [f for f in _blocking(_scan()) if remediation.is_auto_fixable(f)]
        if auto:
            applied += remediation.quarantine_residual(wt, auto, quarantine)

        # Commit the TRUSTED tier FIRST — before any computed strip touches disk — so the two trust
        # levels land as cleanly separated commits (`stage_all` after each write group captures only
        # that group's changes, since the previous group is already committed).
        if not _untrack_quarantine(wt):
            return None, f"ABORTED — could not untrack {QUARANTINE_DIR}/ (would commit backups)", wt
        signed = True
        if applied:
            if not gitutil.stage_all(wt):
                return None, "ABORTED — could not stage the fix (git add failed)", wt
            # commit_fix checks the result and retries UNSIGNED if signing fails — so the branch
            # always advances (no phantom "prepared N" on an empty branch) and we learn whether the
            # commit is unsigned (surfaced to the operator via `_signing_note`).
            commit = gitutil.commit_fix(wt, "security: auto-remediate worm indicators\n\n"
                                        + "\n".join(f"- {c.action}: {c.path}" for c in applied))
            if not commit.committed:
                return None, "ABORTED — could not commit the fix (git commit failed)", wt
            signed = commit.signed

        # COMPUTED tier (#1209): apply each structurally-proven strip (re-proved against the live
        # bytes inside apply_suggested) and commit it SEPARATELY, clearly labeled review-required. A
        # strip that no longer re-proves falls back to manual (still infected, never silently lost).
        computed: list = []
        for disp in suggested:
            if remediation.apply_suggested(wt, disp, quarantine, content_sig):
                computed.append(disp)
            else:
                manual_reviews[disp.path] = remediation.Manual(
                    disp.path, disp.signature_id, disp.reason,
                    "A computed payload strip could not be re-proved against the file on disk — "
                    "review and remove the payload manually.", disp.line)
        if computed:
            if not gitutil.stage_all(wt):
                return None, "ABORTED — could not stage the computed strip (git add failed)", wt
            commit = gitutil.commit_fix(
                wt, "security: computed payload strip — REVIEW REQUIRED (not git-corroborated)\n\n"
                + "\n".join(f"- strip-computed: {d.path}" for d in computed))
            if not commit.committed:
                return None, "ABORTED — could not commit the computed strip (git commit failed)", wt
            signed = signed and commit.signed

        # GROUND-TRUTH residual AFTER both tiers are applied — the honest "still infected" set. The
        # computed-tier paths are stripped, so they never appear here; only genuinely-manual do.
        #
        # LOAD-BEARING INVARIANT (#1209/#1290 — do NOT simplify `_Fix.partial` without reading this):
        # a COMPUTED strip removes the VISIBLE payload, so this rescan can legitimately report the tree
        # CLEAN — `residual`, `suspicious`, AND `manual` can ALL be empty even though we just applied a
        # NOT-git-corroborated (possibly scanner-invisible-RCE) change. When that happens, the ONLY
        # thing keeping the run needs-review (gate red / exit 1) is `bool(self.computed)` in
        # `_Fix.partial`. So `partial` MUST stay `bool(self.manual) OR bool(self.computed)`: dropping
        # the `computed` arm back to the pre-#1209 `bool(self.manual)` would silently turn such a tree
        # GREEN (exit 0) on the strength of a rescan that only proves the payload is no longer GREPPABLE.
        # This is pinned by `test_computed_strip_ships_partial_review_required`; keep both in lockstep.
        fs = _scan()
        residual = _blocking(fs)
        suspicious = [f for f in fs if not _is_blocking(f)]   # heuristic-only residue
        manual: list = []
        for path in sorted({f.path for f in residual}):
            m = manual_reviews.get(path)
            if m is None:
                f0 = next(f for f in residual if f.path == path)
                m = _manual_for(f0, path)
            manual.append(m)

        if not applied and not computed:
            # Nothing was provably safe to ship. If confirmed findings remain, return a NOTIFY-ONLY
            # fix (no changes committed) so the caller files a de-duplicated manual-review issue and
            # keeps the gate red — better than a silent dead-end (#1183).
            if residual:
                return _Fix(base, [], (), suspicious, findings, tuple(manual)), "", wt
            # No CONFIRMED indicator and nothing auto-fixable, but HEURISTIC (suspicious) findings
            # remain. This is NOT "already clean" — saying so contradicts `saw scan`/`saw hook`, which
            # flag the very same repo (the trust-eroding disagreement in #1360). Return a disclose-only
            # fix (no changes, no confirmed manual set) so the caller reports the suspicious findings
            # and defers to review. Heuristics are never auto-fixed (trust model), so — like a
            # suspicious `saw scan` — this stays exit 0; only the truly-empty tree is "already clean".
            if suspicious:
                return _Fix(base, [], (), suspicious, findings, ()), "", wt
            return None, f"'{base}' already clean — nothing to fix", wt
    return _Fix(base, applied, tuple(computed), suspicious, findings, tuple(manual),
                signed=signed), "", wt


def prepare_fix(repo: Path, opts, signatures, allowlist, *, spin: bool = False) -> str:
    """`saw fix` (no --pr): build the fix on the local `security/auto-clean` branch and STOP.
    No push, no PR, no GitHub API — offline-safe, zero remote writes. The branch is left in
    the repo for the user to review and push (or publish with `saw fix --pr`)."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied and not fix.computed:
            # Nothing auto-fixable. Suspicious-only (heuristics, nothing confirmed) → disclose + defer,
            # exit 0 (#1360). Otherwise confirmed findings remain (#1183): report the abort (no --pr =
            # no network, so no issue is filed here) and stay needs-review.
            if not fix.manual:
                return _suspicious_only_outcome(slug, fix)
            return (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                    "need manual review") + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious)
        if fix.partial:
            prepared = len(fix.applied) + len(fix.computed)
            need = ([f"{len(fix.computed)} computed strip(s) need review before merge"] if fix.computed else []) \
                + ([f"{len(fix.manual)} confirmed finding(s) still need manual review"] if fix.manual else [])
            return (f"{slug}: PARTIAL — prepared {prepared} change(s) on '{FIX_BRANCH}', "
                    f"but {' and '.join(need)} (`git -C {repo} diff {fix.base}...{FIX_BRANCH}`)"
                    ) + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual)
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
            if not fix.applied and not fix.computed:
                if not fix.manual:   # suspicious-only → disclose + defer, exit 0 (#1360)
                    return _suspicious_only_outcome(
                        str(repo).replace(str(Path.home()), "~"), fix)
                return (f"ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                        "need manual review (no GitHub origin — cannot file an issue)"
                        ) + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious)
            return _mark_partial(
                f"no GitHub origin — prepared on '{FIX_BRANCH}'; add a remote and push to open a PR",
                fix.partial) + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual)
        finally:
            if wt:
                gitutil.remove_worktree(repo, wt)

    owner, name = slug.split("/", 1)
    gitutil.fetch(repo, "origin", gitutil.default_branch(repo))
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied and not fix.computed:
            # Suspicious-only (#1360): heuristic findings, nothing confirmed. Do NOT file a manual-
            # review issue (a heuristic isn't asserted malware — filing would over-alarm and spam the
            # repo); just disclose and defer. Exit 0, consistent with a suspicious `saw scan`.
            if not fix.manual:
                return _suspicious_only_outcome(slug, fix)
            # Nothing safely fixable but confirmed indicators remain (#1183): there is no branch/PR
            # to push, so file a de-duplicated manual-review issue (the read-only floor's mechanism)
            # and abort with the count. The gate stays red (outcome carries ABORTED). Degrades
            # gracefully — no issue permission just drops the note, still aborts.
            with status(f"filing manual-review issue for {slug}…", enabled=spin):
                issue = proposal.file_dedup_issue(owner, name,
                                                  _issue_spec(owner, name, fix.findings), token)
            note = f"; {issue}" if issue else ""
            return (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                    f"need manual review{note}") + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious)
        base = fix.base

        def _publish() -> str:
          with status(f"opening PR for {slug}…", enabled=spin):   # phase 3: push + PR / fallback
            # PARTIAL (#1183): the safe changes are pushed, but confirmed findings remain. Say so in
            # the title/body/label; the outcome carries 'PARTIAL' so the run exits non-zero.
            partial = fix.partial
            title = ("security: PARTIAL auto-remediation — manual review required" if partial
                     else "security: auto-remediate worm indicators")
            body = _pr_body(slug, fix.applied, computed=fix.computed,
                            suspicious=fix.suspicious, manual=fix.manual)
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
                + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual))
    finally:
        if wt:
            gitutil.remove_worktree(repo, wt)

#!/usr/bin/env python3
"""`saw fix` — prepare a cleanup branch, or submit it as a PR."""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.lib.git.merge.liveness import introduced_liveness, PRESENT, GONE
from stayawake.utils.streaming import status
from stayawake.bots.security.scanner import scan_target
from stayawake.bots.security.targets import LocalRepoTarget
from stayawake.bots.security.models import QUARANTINE_DIR, CONFIRMED, HEURISTIC
from stayawake.bots.security import remediation
from stayawake.bots.security.remediation import installed
from stayawake.core import proposal
from stayawake.bots.security.pr.constants import FIX_BRANCH, PARTIAL_LABEL
from stayawake.bots.security.pr.branches import choose_fix_branch
from stayawake.bots.security.pr.render import (
    manual_review_lines, computed_review_lines, suspicious_review_lines,
    _issue_spec, _mark_partial, _pr_body, _render_submit)

class _Frozen:
    """A finding whose `confidence` is read once."""
    __slots__ = ("_inner", "confidence")

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "confidence", getattr(inner, "confidence", None))

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        raise AttributeError("frozen")

    def __delattr__(self, name):
        raise AttributeError("frozen")


def _freeze(findings):
    return [_Frozen(f) for f in findings]


def _untrack_quarantine(repo: Path) -> bool:
    """Untrack the quarantine directory. True if nothing under it is tracked after."""
    gitutil.unstage_cached(repo, QUARANTINE_DIR)
    return not gitutil.tracked_under(repo, QUARANTINE_DIR)


def _reconcile_partial_label(owner: str, name: str, number: int, partial: bool, token: str) -> None:
    """Add or drop the partial label to match `partial`."""
    if partial:
        github_api.add_labels(owner, name, number, [PARTIAL_LABEL], token, quiet=True)
    else:
        github_api.remove_label(owner, name, number, PARTIAL_LABEL, token, quiet=True)


@dataclass(frozen=True)
class _Fix:
    """A prepared fix: branch, applied changes, and leftover findings."""
    base: str
    branch: str
    applied: list
    computed: tuple = ()
    suspicious: list = ()
    findings: list = ()
    manual: tuple = ()
    signed: bool = True
    tree_note: str = ""

    @property
    def partial(self) -> bool:
        return bool(self.manual) or bool(self.computed)


def _with_tree(outcome: str, note: str) -> str:
    return outcome if not note else f"{outcome}\n    {note}"


def _lockfile_changes(wt: Path, report: installed.Report) -> list:
    changes = []
    try:
        origin = wt.resolve()
    except OSError:
        return changes
    for path in report.removed_lockfiles:
        try:
            rel = path.resolve().relative_to(origin)
        except (OSError, ValueError):
            continue
        changes.append(remediation.Change("remove", rel.as_posix()))
    return changes


def _signing_note(fix: "_Fix | None") -> str:
    """Warning when the fix commit is unsigned."""
    if fix is None or fix.signed:
        return ""
    return (f"\n    ⚠ the fix commit on '{getattr(fix, 'branch', FIX_BRANCH)}' is UNSIGNED "
            "(commit signing failed in the "
            "worktree); if this repo enforces signed commits, re-sign it before pushing/merging.")


class _AtPath:
    """A finding viewed at a working-tree path. Evil-merge findings are keyed to a commit."""

    def __init__(self, inner, path: str):
        self._inner = inner
        self.path = path

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _merge_sha(finding) -> str | None:
    if getattr(finding, "vector", None) != "evil-merge":
        return None
    return getattr(finding, "commit_sha", None) or getattr(finding, "path", None)


def _present_related(repo: Path | None, sha: str | None, paths) -> tuple[str, ...]:
    if repo is None or not sha:
        return ()
    return tuple(p for p in paths if introduced_liveness(repo, sha, p) == PRESENT)


def _related_all_gone(repo: Path | None, sha: str | None, paths) -> bool:
    if repo is None or not sha or not paths:
        return False
    return all(introduced_liveness(repo, sha, p) == GONE for p in paths)


def _manual_for(f0, path: str, repo: Path | None = None) -> "remediation.Manual":
    """Manual-review entry for a confirmed residual."""
    if getattr(f0, "vector", None) == "evil-merge":
        related = getattr(f0, "related_paths", ()) or ()
        files = ", ".join(related) or "see evidence"
        sha = _merge_sha(f0) or path
        live = _present_related(repo, sha, related)
        if live:
            text = (
                f"Worm payload smuggled via this merge COMMIT (files: {files}). "
                f"{', '.join(live)} still carries it in the working tree. "
                "`saw fix` does not change past commits; `saw fix amend` replaces this one."
            )
        elif _related_all_gone(repo, sha, related):
            text = (
                f"Worm payload smuggled via this merge COMMIT (files: {files}); your working tree "
                "no longer carries it. `saw fix` does not change past commits, so this one stays "
                "— as does any clone, fork or tag of it. `saw fix amend` replaces it."
            )
        else:
            text = (
                f"Worm payload smuggled via this merge COMMIT (files: {files}). "
                "Whether those files still carry it could not be established — do not treat the "
                "tree as clean. `saw fix` does not change past commits; `saw fix amend` replaces it."
            )
        return remediation.Manual(
            path, f0.signature_id, "evil-merge", text, getattr(f0, "line", None))
    return remediation.Manual(
        path, f0.signature_id, "residual",
        "Confirmed indicator still present after remediation — review and remove/recover manually.",
        getattr(f0, "line", None))


def _suspicious_only_outcome(label: str, fix: "_Fix") -> str:
    """Outcome when the only findings are heuristic."""
    n = len(fix.suspicious)
    plural = "" if n == 1 else "s"
    return (f"{label}: {n} suspicious (heuristic) finding{plural} — not auto-remediable; "
            "review with `saw scan` (not asserted as malware)") + suspicious_review_lines(fix.suspicious)


def _build_fix(repo: Path, opts, signatures, allowlist, *, base: str | None = None,
               label: str = "", spin: bool = False) -> tuple["_Fix | None", str, Path | None]:
    """Build the fix in a throwaway worktree. Returns `(fix, outcome, worktree)`."""
    base = base or gitutil.default_branch(repo)
    baseref = f"origin/{base}" if gitutil.ref_exists(repo, f"origin/{base}") else base
    if not gitutil.ref_exists(repo, baseref):
        return None, "no default branch to build a fix from — skipped", None

    wt = Path(tempfile.mkdtemp(prefix="sab-fix-"))
    quarantine = Path(tempfile.mkdtemp(prefix="sab-bak-"))
    branch = choose_fix_branch(
        base,
        exists=lambda n: gitutil.ref_exists(repo, f"origin/{n}"),
        fast_forwardable=lambda n: gitutil.is_ancestor(repo, f"origin/{n}", baseref))
    if not gitutil.add_worktree(repo, wt, branch, baseref):
        return None, "could not create worktree", wt

    content_sig = remediation.codeloader_content_sig([s for g in signatures.values() for s in g])

    def _scan():
        return scan_target(LocalRepoTarget(wt, str(repo), opts), signatures, allowlist)

    def _is_blocking(f):
        return getattr(f, "confidence", None) == CONFIRMED

    def _blocking(fs):
        return [f for f in fs if _is_blocking(f)]

    with status(f"scanning {label}…", enabled=spin):
        scan = _scan()
        findings = _freeze(scan.findings)

    tree_note = ""
    with status(f"fixing {label}…", enabled=spin):
        lockfile_changes: list = []
        applied: list = []
        seen_cl: set = set()
        manual_reviews: dict = {}
        suggested: list = []
        merge_clean: dict = {}
        if not scan.error:
            if _blocking(findings):
                try:
                    report = installed.remove_rebuildable(
                        repo,
                        exclude_dirs=getattr(opts, "exclude_dirs", None),
                        remove_lockfiles=not installed.lockfile_stays(),
                        lockfile_root=wt)
                    tree_note = report.note()
                    lockfile_changes = _lockfile_changes(wt, report)
                except OSError as exc:
                    tree_note = f"could not remove the installed tree ({exc})"
            applied = lockfile_changes + remediation.apply(wt, remediation.plan(findings), quarantine)
            for f in findings:
                sha = _merge_sha(f)
                if not sha:
                    continue
                for rp in getattr(f, "related_paths", ()):
                    if rp not in merge_clean:
                        blob = gitutil.clean_merge_blob(wt, sha, rp)
                        if blob is not None:
                            merge_clean[rp] = blob
            def _corroborated(f) -> bool:
                return (getattr(f, "category", None) == "code-loader"
                        and getattr(f, "confidence", None) == CONFIRMED)

            for f in sorted(findings, key=lambda x: 0 if _corroborated(x) else 1):
                if f.path in seen_cl:
                    continue
                conf = getattr(f, "confidence", None)
                corroborated = (getattr(f, "category", None) == "code-loader"
                                and conf == CONFIRMED)
                if not corroborated:
                    if conf != HEURISTIC:
                        continue
                    target = Path(wt) / f.path
                    try:
                        text = target.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if not remediation.has_concealment_seam(text, f.path, content_sig):
                        continue
                disp = remediation.classify_recovery(wt, f, content_sig, merge_clean=merge_clean.get(f.path))
                if isinstance(disp, remediation.Recovery) and \
                        remediation.apply_recovery(wt, disp, quarantine, content_sig):
                    seen_cl.add(f.path)
                    applied.append(remediation.Change("recover", disp.path, disp.label))
                elif not corroborated:
                    continue
                elif isinstance(disp, remediation.Suggested):
                    seen_cl.add(f.path)
                    suggested.append(disp)
                elif isinstance(disp, remediation.Manual):
                    manual_reviews[disp.path] = disp
            for f in findings:
                sha = _merge_sha(f)
                if not sha:
                    continue
                conf = getattr(f, "confidence", None)
                for rp in getattr(f, "related_paths", ()):
                    if rp in seen_cl:
                        continue
                    if introduced_liveness(wt, sha, rp) != PRESENT:
                        continue
                    disp = remediation.classify_recovery(
                        wt, _AtPath(f, rp), content_sig, merge_clean=merge_clean.get(rp))
                    if conf == CONFIRMED and isinstance(disp, remediation.Recovery) and \
                            remediation.apply_recovery(wt, disp, quarantine, content_sig):
                        seen_cl.add(rp)
                        applied.append(remediation.Change("recover", disp.path, disp.label))
                    elif isinstance(disp, remediation.Suggested):
                        seen_cl.add(rp)
                        suggested.append(disp)
                    elif isinstance(disp, remediation.Manual):
                        manual_reviews[rp] = disp

            rescan = _scan()
            auto = []
            if not rescan.error:
                auto = [f for f in _blocking(_freeze(rescan.findings)) if remediation.is_auto_fixable(f)]
            if auto:
                applied += remediation.quarantine_residual(wt, auto, quarantine)

            if not _untrack_quarantine(wt):
                return None, _with_tree(
                    f"ABORTED — could not untrack {QUARANTINE_DIR}/ (would commit backups)", tree_note), wt
            signed = True
            if applied:
                if not gitutil.stage_all(wt):
                    return None, _with_tree("ABORTED — could not stage the fix (git add failed)", tree_note), wt
                commit = gitutil.commit_fix(wt, "security: auto-remediate worm indicators\n\n"
                                            + "\n".join(f"- {c.action}: {c.path}" for c in applied))
                if not commit.committed:
                    return None, _with_tree("ABORTED — could not commit the fix (git commit failed)", tree_note), wt
                signed = commit.signed

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
                    return None, _with_tree(
                        "ABORTED — could not stage the computed strip (git add failed)", tree_note), wt
                commit = gitutil.commit_fix(
                    wt, "security: computed payload strip — REVIEW REQUIRED (not git-corroborated)\n\n"
                    + "\n".join(f"- strip-computed: {d.path}" for d in computed))
                if not commit.committed:
                    return None, _with_tree(
                        "ABORTED — could not commit the computed strip (git commit failed)", tree_note), wt
                signed = signed and commit.signed
        else:
            signed = True
            computed: list = []

        done = _scan()
        fs = _freeze(done.findings)
        residual = _blocking(fs)
        suspicious = [f for f in fs if not _is_blocking(f)]
        manual: list = []
        for path in sorted({f.path for f in residual}):
            m = manual_reviews.get(path)
            if m is None:
                f0 = next(f for f in residual if f.path == path)
                m = _manual_for(f0, path, repo=wt)
            manual.append(m)
        have = {m.path for m in manual}
        for f in findings:
            if getattr(f, "confidence", None) != CONFIRMED:
                continue
            sha = _merge_sha(f)
            if not sha or sha in have:
                continue
            # Restoring the live files does not remove the merge commit. Keep the history note.
            manual.append(_manual_for(f, sha, repo=wt))
            have.add(sha)

        if not applied and not computed:
            if residual:
                return _Fix(base, branch, [], (), suspicious, findings, tuple(manual),
                            tree_note=tree_note), "", wt
            if suspicious:
                return _Fix(base, branch, [], (), suspicious, findings, (),
                            tree_note=tree_note), "", wt
            if scan.error or done.error:
                return None, _with_tree("ABORTED — scan did not finish", tree_note), wt
            return None, _with_tree(f"'{base}' already clean — nothing to fix", tree_note), wt
    return _Fix(base, branch, applied, tuple(computed), suspicious, findings, tuple(manual),
                signed=signed, tree_note=tree_note), "", wt


def prepare_fix(repo: Path, opts, signatures, allowlist, *, base: str | None = None,
                spin: bool = False) -> str:
    """Prepare the fix on a local branch and stop. No push, no PR."""
    slug = gitutil.origin_slug(repo) or str(repo).replace(str(Path.home()), "~")
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, base=base,
                                  label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied and not fix.computed:
            if not fix.manual:
                return _with_tree(_suspicious_only_outcome(slug, fix), fix.tree_note)
            return _with_tree(
                (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                 "need manual review") + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious),
                fix.tree_note)
        if fix.partial:
            prepared = len(fix.applied) + len(fix.computed)
            need = ([f"{len(fix.computed)} computed strip(s) need review before merge"] if fix.computed else []) \
                + ([f"{len(fix.manual)} confirmed finding(s) still need manual review"] if fix.manual else [])
            return _with_tree(
                (f"{slug}: PARTIAL — prepared {prepared} change(s) on '{fix.branch}', "
                 f"but {' and '.join(need)} (`git -C {repo} diff {fix.base}...{fix.branch}`)"
                 ) + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual),
                fix.tree_note)
        return _with_tree(
            (f"{slug}: prepared {len(fix.applied)} change(s) on '{fix.branch}' — review "
             f"`git -C {repo} diff {fix.base}...{fix.branch}`, then `saw fix --pr` to open a PR"
             ) + _signing_note(fix),
            fix.tree_note)
    finally:
        if wt:
            gitutil.remove_worktree(repo, wt)


def submit_fix_pr(repo: Path, opts, signatures, allowlist, token: str,
                  patches_dir: Path | None = None, *, base: str | None = None,
                  spin: bool = False) -> str:
    """Push the fix branch and open or update one PR."""
    slug = gitutil.origin_slug(repo)
    if not slug:
        fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, base=base,
                                      label=str(repo).replace(str(Path.home()), "~"), spin=spin)
        try:
            if fix is None:
                return outcome
            if not fix.applied and not fix.computed:
                if not fix.manual:
                    return _with_tree(_suspicious_only_outcome(
                        str(repo).replace(str(Path.home()), "~"), fix), fix.tree_note)
                return _with_tree(
                    (f"ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                     "need manual review (no GitHub origin — cannot file an issue)"
                     ) + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious),
                    fix.tree_note)
            return _with_tree(
                _mark_partial(
                    f"no GitHub origin — prepared on '{fix.branch}'; add a remote and push to open a PR",
                    fix.partial) + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual),
                fix.tree_note)
        finally:
            if wt:
                gitutil.remove_worktree(repo, wt)

    owner, name = slug.split("/", 1)
    gitutil.fetch(repo, "origin", gitutil.default_branch(repo))
    fix, outcome, wt = _build_fix(repo, opts, signatures, allowlist, base=base,
                                  label=slug, spin=spin)
    try:
        if fix is None:
            return f"{slug}: {outcome}"
        if not fix.applied and not fix.computed:
            if not fix.manual:
                return _with_tree(_suspicious_only_outcome(slug, fix), fix.tree_note)
            with status(f"filing manual-review issue for {slug}…", enabled=spin):
                issue = proposal.file_dedup_issue(owner, name,
                                                  _issue_spec(owner, name, fix.findings), token)
            note = f"; {issue}" if issue else ""
            return _with_tree(
                (f"{slug}: ABORTED — nothing auto-fixable; {len(fix.manual)} confirmed finding(s) "
                 f"need manual review{note}") + manual_review_lines(fix.manual) + suspicious_review_lines(fix.suspicious),
                fix.tree_note)
        base = fix.base

        def _publish() -> str:
          with status(f"opening PR for {slug}…", enabled=spin):
            partial = fix.partial
            title = ("security: PARTIAL auto-remediation — manual review required" if partial
                     else "security: auto-remediate worm indicators")
            body = _pr_body(slug, fix.applied, computed=fix.computed,
                            suspicious=fix.suspicious, manual=fix.manual)
            res = proposal.submit_change_pr(wt, slug, base, branch=fix.branch, title=title,
                                            body=body, token=token,
                                            issue=_issue_spec(owner, name, fix.findings),
                                            patches_dir=patches_dir)
            if res.number is not None and res.kind in ("pr", "fork-pr"):
                _reconcile_partial_label(owner, name, res.number, partial, token)
            return _render_submit(res, slug=slug, base=base, partial=partial)

        return _with_tree(
            _mark_partial(_publish(), fix.partial)
            + _signing_note(fix) + computed_review_lines(fix.computed) + manual_review_lines(fix.manual),
            fix.tree_note)
    finally:
        if wt:
            gitutil.remove_worktree(repo, wt)

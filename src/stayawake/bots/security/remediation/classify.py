#!/usr/bin/env python3
"""Code-loader remediation DECISION: given a finding, recover from git, offer a computed `Suggested`
strip, or defer to `Manual` with a reason. A payload can't be excised by a textual transform (that
corrupts valid files) — the source of truth is git history. Returns a `Recovery` / `Suggested` /
`Manual` result. Defer-reason constants live in models.py."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib import git as gitutil
from stayawake.bots.security.models import (
    BORN_INFECTED, INTRINSIC_MATCH, LEGIT_CHANGES, UNTRACKED, NO_VCS, INSPECT_FAILED)
from stayawake.bots.security.obfuscation import analyze_file
from stayawake.bots.security.remediation.gates import (
    _seam_strip, _recovery_diff, _carries_payload, _ext, _safe_to_recover, _short)

@dataclass(frozen=True)
class Recovery:
    """A reliable fix: `clean_text` is what gets written. Normally that is the file's last clean
    committed version (a git restore); when `excised` is True it is instead the WORKING file with a
    concealment-hidden same-line payload surgically cut out (see `_seam_strip`) — every other byte
    preserved, so no legit edit is lost. `diff` is a redaction-aware preview (payload never printed
    raw). `excised` recoveries carry an extra apply-time gate (the result must not itself be packed).
    `clean_rev` is the source commit for a restore, or a marker for an excision."""
    path: str
    clean_rev: str
    label: str          # e.g. 'a1b2c3d ("chore: tailwind v4", 2026-05-12)'
    diff: str
    clean_text: str
    excised: bool = False


@dataclass(frozen=True)
class Manual:
    """A finding auto-fix can't safely act on — surfaced with WHY and the recommended action."""
    path: str
    signature_id: str
    reason: str
    action: str
    line: int | None = None


@dataclass(frozen=True)
class Suggested:
    """A COMPUTED concealment-seam excision that `_seam_strip` proved structurally safe — five
    self-contained gates hold (an unambiguous ≥16-char concealment boundary, a payload-free result,
    a result that isn't itself packed, NO detectable exec sink in the KEPT code, and only-removal /
    no fabricated byte) — but there is no clean committed ancestor to corroborate it against a
    scanner-INVISIBLE injection in the kept code (the file has no VCS / is untracked / is born
    infected / was legitimately edited since infection, so no whole-file trusted version exists).

    That missing corroboration is the ONE thing the git-match adds over the five gates, and it is
    exactly what a human reviewer + the quarantine backup close (see `_seam_strip`'s own note). So a
    Suggested is NOT trusted like a `Recovery`: it is still applied — `apply_suggested` writes the
    strip — but ONLY into the review branch as a SEPARATE, clearly-labeled commit that the operator
    must eyeball before merging (never auto-merged, and the run stays needs-review until they do).
    The PR review is the trust anchor; the tool never declares the host clean on its own. `diff` is
    the redaction-aware preview (payload shown only as a digest); `excised_text` the strip that gets
    written; `reason` the code for why it isn't git-corroborated; `action` the operator guidance."""
    path: str
    signature_id: str
    reason: str
    action: str
    diff: str
    excised_text: str
    line: int | None = None
def _try_suggest(work, ext, content_sig, fallback: "Manual"):
    """Escalate a DEFERRED finding to a computed `Suggested` fix when `_seam_strip` proves a safe
    concealment-seam excision. `_seam_strip`'s five gates are self-contained (they need no git
    ancestor), so this works for the cases that have no whole-file trusted version — no-VCS /
    untracked / born-infected / edited-since. Else return the given `Manual` unchanged (no clean
    seam, or a detectable exec sink survives in the kept code → genuinely inseparable).

    This never weakens auto-apply: a `Suggested` is NEVER written automatically — only a git-
    corroborated `Recovery` is (`apply_recovery`). The human reviewing the computed strip is the
    trust anchor for the ONE residual the git-match would otherwise cover (a scanner-invisible
    injection in the kept code)."""
    excised = _seam_strip(work, ext, content_sig)
    if excised is None:
        return fallback
    return _build_suggested(work, excised, content_sig,
                            fallback.path, fallback.signature_id, fallback.reason, fallback.line)


def _build_suggested(work, excised, content_sig, path, sig, reason, line) -> "Suggested":
    """Wrap an already-computed `_seam_strip` result as a `Suggested` fix (one home for the operator
    guidance + redacted diff)."""
    action = ("saw applied a computed payload-only strip to the review branch: it cuts the "
              "concealment-seam payload and keeps every other byte, and the kept code carries no "
              "payload or detectable exec sink. It is NOT git-corroborated (no clean committed "
              "version to compare against), so review that the kept code is untampered before "
              "merging — the original is quarantined and this change is not auto-merged.")
    return Suggested(path, sig, reason, action, _recovery_diff(work, excised, content_sig), excised, line)


def classify_recovery(repo, finding, content_sig):
    """Decide how to remediate ONE (confirmed) code-loader finding — always to a CLEAN COMMITTED
    version, so the result is trusted history rather than anything we synthesized. Two proofs that
    restoring the last clean first-parent version is safe:

      1. `_safe_to_recover` — the delta is a provably payload-only append (the ordinary shape), or
      2. a concealment-seam EXCISION of the working file REPRODUCES that clean version byte-for-byte
         (`_seam_strip(work) == clean_text`) — the worm's config shape (a payload hidden after a
         whitespace seam on a real line, plus a prepended require-shim) isn't a clean append, so (1)
         defers it; but if excising the seam + a now-dead shim yields EXACTLY the committed clean
         file, restoring it loses nothing and keeps nothing INJECTED — anything the worm added to
         the kept code (a stray edit, or an RCE the scanner can't see) would make the excised result
         DIFFER from the ancestor and is therefore refused. This is what makes the excision safe
         without a complete exec-sink detector. (It does trust committed history to the same degree
         a plain `git checkout` does: a scanner-invisible payload ALREADY committed to the mainline
         clean version would be restored as-is — the same irreducible residual the restore path has,
         reachable only by an attacker who already controls the repo's commits.)

    Else defer to Manual (with a specific reason). A clean committed ancestor is REQUIRED for both
    paths, so no-history / born-infected / untracked findings defer. Never edits a file except by
    writing a re-proven result through apply_recovery."""
    root = Path(repo)
    path, ext = finding.path, _ext(finding.path)
    line = getattr(finding, "line", None)
    sig = finding.signature_id
    target = root / path
    work = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""

    if not gitutil.is_git_repo(repo):
        return _try_suggest(work, ext, content_sig, Manual(
            path, sig, NO_VCS,
            "Not a git repository — no clean version to recover. Review and remove "
            "the payload manually, or delete the file.", line))
    if not gitutil.tracked(repo, path):
        return _try_suggest(work, ext, content_sig, Manual(
            path, sig, UNTRACKED,
            "Not tracked in git — no committed clean version to recover. Review and "
            "remove the payload, or delete the file.", line))

    # The history walk touches git for every commit that changed the file. Any failure here
    # (a corrupt object, an unreadable blob, an OS error) must NOT crash the caller — that
    # would abort remediation for this repo and, in the org sweep, every repo after it. On
    # failure we defer this one finding to manual review and carry on.
    try:
        clean = None
        # first_parent=True: the recovery source is a trust decision. An evil merge can make a
        # "clean-looking" blob reachable only through its malicious second parent; walking the
        # mainline (first-parent) chain only ever selects a version that actually landed on the
        # default branch, then `_carries_payload` re-validates it.
        for sha in gitutil.file_commits(repo, path, first_parent=True):
            c = gitutil.file_at(repo, sha, path)
            if c and not _carries_payload(c, content_sig):   # first version with no payload = clean
                clean = (sha, c)
                break

        if clean is None:
            if analyze_file(work, ext):       # packed/obfuscated → looks born-infected
                return _try_suggest(work, ext, content_sig, Manual(
                    path, sig, BORN_INFECTED,
                    "No clean version in git history and the content is packed/obfuscated "
                    "— likely born infected. Review and, if confirmed, remove/quarantine it.", line))
            return Manual(path, sig, INTRINSIC_MATCH,
                          "No clean version in history, but it is a plain literal — likely intentional "
                          f"(test/research data). If so, allowlist `{sig}` for `{path}`.", line)

        sha, clean_text = clean
        meta = gitutil.commit_meta(repo, sha)
        label = f'{sha[:7]} ("{_short(meta.get("subject", ""), 40)}", {meta.get("date", "")[:10]})'
        if _safe_to_recover(work, clean_text, content_sig):
            return Recovery(path, sha, label, _recovery_diff(work, clean_text, content_sig), clean_text)
        # Excision, corroborated by the clean ancestor: auto-apply ONLY when the payload-stripped
        # working file equals `clean_text` EXACTLY (matches trusted history → safe against even a
        # scanner-invisible injection). When `_seam_strip` yields a valid excision that DOESN'T match
        # the ancestor — a legit edit was made since infection — auto-apply is unsafe (the edit isn't
        # in trusted history), but the strip is still structurally proven, so offer it as a computed
        # Suggested fix for the operator to review rather than a bare hand-hunt checklist (#1209).
        excised = _seam_strip(work, ext, content_sig)
        if excised == clean_text:
            return Recovery(path, sha, label, _recovery_diff(work, clean_text, content_sig),
                            clean_text, excised=True)
        if excised is not None:
            return _build_suggested(work, excised, content_sig, path, sig, LEGIT_CHANGES, line)
        # No computable seam at all → genuinely inseparable; defer to a manual investigation.
        return Manual(path, sig, LEGIT_CHANGES,
                      f"Payload shares a line with real code and the payload-stripped file doesn't "
                      f"match a clean commit, and no safe concealment seam was found — can't auto-"
                      f"separate it. Delete just the payload run from that line, keeping the rest. Note "
                      f"`git checkout {sha[:7]} -- {path}` reverts the ENTIRE file to {sha[:7]} (diff it "
                      f"first so you don't lose other edits made since then).", line)
    except Exception:  # noqa: BLE001 — never let one file's history quirk abort the sweep
        return Manual(path, sig, INSPECT_FAILED,
                      "Could not read this file's git history to find a clean version. Inspect it "
                      f"manually and recover from a known-good commit: `git log -- {path}`.", line)

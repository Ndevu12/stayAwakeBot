#!/usr/bin/env python3
"""Presentation for the fix flow — build the PR/issue BODY, the review-line summaries, and render the submit result. Pure text, no I/O."""
from __future__ import annotations


from stayawake.utils import textsafe
from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security import remediation, proposal
from stayawake.bots.security.pr.constants import ISSUE_LABEL

def _mark_partial(outcome: str, partial: bool) -> str:
    """Guarantee a PARTIAL fix's outcome carries the marker so `remediator.fix` counts it as
    needs-review and the run exits non-zero (#1183 invariant #1) — NO MATTER which push / PR /
    fork / patch / issue branch produced it. This single structural gate replaces per-branch
    tagging, which an adversarial pass proved too easy to forget (four fallback returns dropped it,
    silently reporting a still-infected partial fix as a clean exit 0)."""
    return outcome if (not partial or "PARTIAL" in outcome) else f"{outcome}  [PARTIAL — manual review required]"


def _review_lines(items, header: str, limit: int = 20) -> str:
    """Shared CLI-stream renderer for a bounded list of review items (location · reason-code ·
    action). Every field is `_plain`-sanitized (a crafted path can't inject terminal/Actions control
    sequences), the list is bounded (`…and N more`), and only locations / reasons / guidance are
    shown — the payload bytes are NEVER echoed (#1184 invariants 2–4). Empty when there are none."""
    if not items:
        return ""
    lines = ["", f"    {header}"]
    for m in items[:limit]:
        loc = m.path + (f":{m.line}" if getattr(m, "line", None) else "")
        lines.append(f"      • {textsafe.plain(loc)}  ({textsafe.plain(getattr(m, 'reason', ''), 40)})")
        action = textsafe.plain(getattr(m, "action", ""), 300)
        if action:
            lines.append(f"        {action}")
    if len(items) > limit:
        lines.append(f"      …and {len(items) - limit} more")
    return "\n".join(lines)


def manual_review_lines(manual, limit: int = 20) -> str:
    """Per-finding manual-review guidance for `saw fix`'s CLI stream (#1184): each residual as
    location + reason-code + the recommended (inspect-before-running) command classify_recovery
    already computed. Recovery commands keep their 'review the diff before running' framing;
    validating a recovery sha's ancestry is #1185's source-trust rule. See `_review_lines` for the
    injection-safety contract."""
    return _review_lines(manual, "Manual review needed (inspect before running any command):", limit)


def computed_review_lines(computed, limit: int = 20) -> str:
    """CLI-stream guidance for the #1209 computed strips that WERE applied to the review branch but
    are NOT git-corroborated: each as location + reason-code + the review-before-merge guidance (the
    operator's review is the trust anchor for the one residual the git-match would otherwise close)."""
    return _review_lines(computed, "Computed strips applied — REVIEW the kept code before merging:", limit)


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
        from stayawake.core.identity import push_failure_message
        from stayawake.core.identity.classify import PushFailure
        if res.push_reason:
            return f"{slug}: {dash}{push_failure_message(PushFailure(res.push_reason, res.push_detail))}"
        return f"{slug}: branch push failed (check token write scope)"
    from stayawake.core.identity import push_failure_message
    from stayawake.core.identity.classify import PushFailure
    head = (push_failure_message(PushFailure(res.push_reason, res.push_detail))
            if res.push_reason else
            "push rejected (no write access, or the branch requires signed commits?)")
    return (f"{slug}: {dash}{head} — " + "; ".join(bits) + ".")


def _pr_body(slug: str, changes, computed=(), suspicious=(), manual=()) -> str:
    """Render the PR body. A PARTIAL fix (#1183/#1209) is any tree that is NOT fully git-corroborated
    clean — either residual CONFIRMED findings with no safe fix (`manual`), OR computed strips that
    ARE applied (a separate commit) but are NOT git-corroborated and MUST be reviewed before merge
    (`computed`). The body says so loudly and lists each. All untrusted text (paths, reasons) goes
    through `_code`/`_sanitize` (invariant #5)."""
    partial = bool(manual) or bool(computed)
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
    if computed:
        # #1209 REVIEW-REQUIRED tier: these strips ARE applied on this branch (as a SEPARATE commit
        # from the git-corroborated changes above), but they are NOT git-corroborated — the payload
        # was cut along a structurally-proven concealment seam, and the ONE residual the whole-file
        # git match would otherwise close (a scanner-invisible injection in the kept code) is closed
        # by THIS human review. So the reviewer MUST read the kept code before merging.
        lines += ["", "## 🔧 Computed strip applied — REVIEW the kept code before merging",
                  "", f"**{len(computed)} finding(s) were fixed by a saw-computed payload-only strip** "
                  "(a SEPARATE commit on this branch). saw cut the payload after the concealment seam "
                  "and kept every other byte; the kept code carries no payload or detectable exec "
                  "sink. But saw could NOT git-corroborate the result (no clean committed version to "
                  "compare against), so this is **not a trusted auto-fix** — read the diff for each and "
                  "confirm the kept code is untampered before merging. The gate stays red until you do:",
                  ""]
        # One code-wrapped line per finding (same injection-safe shape as the manual list — every
        # attacker-influenced field via `textsafe.code`, no raw diff embedded in the Markdown body,
        # so a crafted path/kept-line can't inject a link/image/HTML; the diff lives in the commit).
        for m in computed[:50]:
            loc = m.path + (f":{m.line}" if getattr(m, "line", None) else "")
            lines.append(f"- [ ] {textsafe.code(loc)} — {textsafe.code(getattr(m, 'signature_id', ''))} "
                         f"({textsafe.code(getattr(m, 'reason', ''), 40)}): "
                         f"{textsafe.code(getattr(m, 'action', ''))}")
    if manual:
        # The honest heart of a partial fix: confirmed indicators with no safe fix at all, each with
        # its reason + recommended action. The tree is never presented as clean.
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

#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the worm's entry and
propagation surfaces, and report actionable hygiene issues. Split per concern into this package:
"""
from __future__ import annotations

import subprocess          # noqa: F401  re-exported so tests can patch hygiene.subprocess.run globally
from pathlib import Path   # noqa: F401  re-exported so tests can patch hygiene.Path.home globally
from typing import Callable

from .models import (HygieneIssue, display_rank, INCIDENT_TRIGGER_IDS, ACTIVE_PERSISTENCE_IDS,
                     BLOCKED_ID, BLOCKED_SURFACE_ID,
                     CREDENTIAL_EXPOSURE_IDS, UNVERIFIED_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS,
                     UNCHECKED_GATE_IDS,
                     SURFACE_ABSENT_ID,
                     ROTATION_SAFE, ROTATION_SAFE_PENDING_CHECK,
                     ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN,
                     ROTATION_UNSAFE_STAGING,
                     TIER_UNCONFIRMED_STAGING, unconfirmed_staging_note,
                     TIER_LEFT_OUTSIDE_A_CONTROL, left_outside_a_control_note,
                     TIER_ACTIVE_PERSISTENCE, TIER_CREDENTIAL_EXPOSURE, incident_tier,
                     persistence_surface_is_enumerable, rotation_safety,
                     incident_response_sequence, credential_exposure_note)
from .outcome import (CheckOutcome, run_probe, CHECKED_CLEAN, FOUND, UNKNOWN, BLOCKED,
                      NOT_IMPLEMENTED)
from .credentials import check_credentials, keychain_predicate
from .runner import check_runner_persistence, services_predicate
from .os_service import check_persistence
from .coverage import check_persistence_coverage
from .autorun import check_autorun
from .global_prefix import check_global_install_tree
from .host_artifacts import check_host_artifacts
from .process import check_live_processes
from .app_bundle import check_app_bundles
from .agents import check_agents
from .watching import check_self_check
from .editor import check_editors
from .mechanism import (check_ssh_authorized_keys, check_shell_profile,
                        check_git_config_execution, git_config_predicate)
from .remote import check_branch_protection
from .document import as_document, finding_groups, rotation_sentence, scope_notes, shown
from stayawake.utils.render import MARKER, SEVERITY, block, marked_list, paint

__all__ = [
    "HygieneIssue", "INCIDENT_TRIGGER_IDS", "ROTATION_UNSAFE_IDS", "UNCHECKED_GATE_IDS", "rotation_safety",
    "incident_response_sequence",
    "check_credentials", "check_runner_persistence", "check_persistence",
    "check_persistence_coverage", "check_autorun", "check_host_artifacts",
    "check_app_bundles",
    "check_editors", "check_agents", "check_self_check", "check_ssh_authorized_keys", "check_shell_profile", "check_git_config_execution",
    "check_live_processes",
    "check_branch_protection", "audit", "audit_checks", "audit_outcomes", "as_document",
    "run_check", "render",
    "CheckOutcome", "CHECKED_CLEAN", "FOUND", "UNKNOWN", "BLOCKED", "NOT_IMPLEMENTED",
]

_PREDICATES: dict[str, Callable[[], str | None]] = {
    "cached credentials": keychain_predicate,
    "self-hosted runner": services_predicate,
    "git exec config": git_config_predicate,
}

_SURFACE_PROBES = frozenset({
    "editor settings", "agent permissions", "self-check", "self-hosted runner",
    "OS-service persistence",
    "persistence surface coverage", "host drop-files", "SSH authorized_keys",
    "shell startup files", "git exec config", "autorun surface", "application bundles",
    "running processes",
})

# The global install tree is not the persistence surface, so a blocked read of it says nothing
# about whether that surface was enumerated.
_NON_SURFACE_PROBES = frozenset({"cached credentials", "branch protection", "global install tree"})

_POSIX_ONLY_PROBES = frozenset({
    "self-hosted runner", "OS-service persistence", "SSH authorized_keys",
    "shell startup files", "autorun surface", "running processes",
})


def run_check(label: str, check: Callable[[], list[HygieneIssue]]) -> CheckOutcome:
    """One probe's outcome — the ONE place a probe's own self-test is looked up and applied, so the
    streaming CLI and the all-at-once path cannot differ on whether a check was trusted.

    A probe with no implementation for the running platform is NOT clean. It returns nothing for the
    same reason it returns nothing on a clean host, and grading the two alike is how a Windows run
    reported per-check clean results over a surface no code enumerates. The run-level finding comes
    from the coverage probe, so the report carries the gap once rather than five times."""
    if label in _POSIX_ONLY_PROBES and not persistence_surface_is_enumerable():
        return CheckOutcome(label, NOT_IMPLEMENTED)
    return run_probe(label, check, _PREDICATES.get(label),
                     certifies_surface=label not in _NON_SURFACE_PROBES)


def audit_outcomes(slug: str | None = None, token: str | None = None, branch: str = "main",
                   *, verify_artifacts: bool = False) -> list[CheckOutcome]:
    """Every probe's OUTCOME rather than only its findings — what it established, and whether it
    was in a position to establish anything."""
    return [run_check(label, check)
            for label, check in audit_checks(slug, token, branch,
                                             verify_artifacts=verify_artifacts)]

def audit(slug: str | None = None, token: str | None = None,
          branch: str = "main", *, verify_artifacts: bool = False) -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list (non-streaming).

    Delegates to audit_checks() so the SINGLE definition of what an audit runs is shared with the
    streaming CLI — neither may hand-assemble its own subset (that omission is how a probe once got
    silently dropped). A caller that needs to know whether a check was in a position to answer, and
    not only what it found, wants `audit_outcomes()`: the issue list alone cannot say."""
    return [issue
            for outcome in audit_outcomes(slug, token, branch, verify_artifacts=verify_artifacts)
            for issue in outcome.issues]


def audit_checks(slug: str | None = None, token: str | None = None, branch: str = "main",
                 *, verify_artifacts: bool = False
                 ) -> list[tuple[str, Callable[[], list[HygieneIssue]]]]:
    """The ordered (label, check) probes that make up an audit — the ONE definition of what
    `saw audit` runs, consumed by both audit() (all-at-once) and the streaming CLI (per-check
    spinner). Each `check` is a zero-arg callable returning list[HygieneIssue]. When a repo `slug`
    and `token` are supplied, the branch-protection gate on `branch` is included. `verify_artifacts`
    (the `--verify` opt-in) lets the host-artifact probe content-scan a lone weak dir."""
    return [
        # First, before the slow disk probes: a process is the only evidence here that can leave
        # mid-run. Measured last: 30s to reach, 0.1s to run — a 60s process was already gone.
        ("running processes", check_live_processes),
        ("cached credentials", check_credentials),
        ("editor settings", check_editors),
        ("agent permissions", check_agents),
        ("self-check", check_self_check),
        ("self-hosted runner", check_runner_persistence),
        ("OS-service persistence", check_persistence),
        ("persistence surface coverage", check_persistence_coverage),   # enumeration honesty
        ("host drop-files", lambda: check_host_artifacts(verify=verify_artifacts)),
        ("application bundles", lambda: check_app_bundles(verify=verify_artifacts)),
        ("global install tree", check_global_install_tree),
        ("SSH authorized_keys", check_ssh_authorized_keys),
        ("shell startup files", check_shell_profile),
        ("git exec config", check_git_config_execution),
        ("autorun surface", check_autorun),                             # novel-foothold monitor
        ("branch protection", lambda: check_branch_protection(slug, token, branch)),
    ]


# Per-issue markers come from the shared vocabulary (`utils.render.MARKER`) rather than a local
# map, so this surface and the scan report cannot drift on what a glyph means — the same reason
# SEVERITY lives there. Two things this fixes over the local map it replaces:
#   * `unknown` now HAS a marker. It used to fall through to the `info` bullet and render
#   * the warning marker is the text glyph `⚠`, not the emoji `⚠️`. The emoji is double-width,
#     so warning rows sat one column right of info rows in the same list. The banner heads below
#     keep the emoji deliberately: they are standalone attention lines, not aligned columns.
def _icon(severity: str) -> str:
    return MARKER.get(severity, MARKER["info"])


def _safe(text: str) -> str:
    """Prepare one untrusted field the way the report prints it. Takes the text. Returns it."""
    return shown(text)


def _banner(issue_ids: set[str], *, color: bool, width: int, content_scanned: bool = False) -> list[str]:
    """The incident banner, GRADED to the evidence (proportionality — see models): the full
    harden → rebuild → rotate-LAST runbook leads ONLY on active host persistence; a lone
    credential EXPOSURE gets a calm, proportionate note (not "harden and rebuild" over a cached
    token); hygiene / info-only findings get no banner. Empty list when none is warranted.

    The runbook is a genuine ORDERED procedure (rotate LAST) → a NUMBERED list; the note is a set
    of points/caveats, not a sequence → a BULLETED list. Both go through core.render.marked_list."""
    tier = incident_tier(issue_ids)
    if tier == TIER_ACTIVE_PERSISTENCE:
        head = "⚠️  Active host persistence detected — respond in THIS order (rotate LAST):"
        steps, ordered = incident_response_sequence(), True
    elif tier == TIER_CREDENTIAL_EXPOSURE:
        head = "⚠️  Credential exposure — no active host persistence detected:"
        steps, ordered = credential_exposure_note(), False
    elif tier == TIER_UNCONFIRMED_STAGING:
        head = "⚠️  The same staging artifact in more than one place — not evidence of a live implant:"
        steps, ordered = unconfirmed_staging_note(content_scanned=content_scanned), False
    elif tier == TIER_LEFT_OUTSIDE_A_CONTROL:
        head = "⚠️  A global resolution path was left outside a control — not evidence of a live implant:"
        steps, ordered = left_outside_a_control_note(content_scanned=content_scanned), False
    else:
        return []
    return ([paint(head, SEVERITY["warning"], on=color)] +
            marked_list(steps, ordered=ordered, indent=5, width=width))


def _rotation_verdict(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """The run-level ROTATION-SAFETY verdict — ALWAYS stated, reachable even with zero
    findings. Says explicitly whether credential rotation is safe, because rotating while a
    `gh-token-monitor` daemon is live arms a home-directory wiper. Three states (see models):
    SAFE (surface enumerated + clean), UNSAFE-persistence (a live foothold → the harden/rotate-LAST
    runbook follows in _banner), UNSAFE-unknown (surface could not be read → treat as unsafe)."""
    verdict = rotation_safety({i.id for i in issues})
    sentence = rotation_sentence(issues)
    if verdict in (ROTATION_SAFE, ROTATION_SAFE_PENDING_CHECK):
        return [paint(f"{MARKER['ok']} {sentence}", SEVERITY["ok"], on=color)]
    if verdict == ROTATION_UNSAFE_UNKNOWN:
        lines = [paint(f"{MARKER['unknown']}  {sentence}", SEVERITY["warning"], on=color)]
    else:
        lines = [paint(f"{MARKER['warning']}  {sentence}", SEVERITY["warning"], on=color)]
    # The UNKNOWN surface is disclosed on BOTH unsafe paths. `rotation_safety` is a PRIORITY
    # function — active persistence dominates — so keying this disclosure off its verdict hid the
    # list in the one state that needs it most: a live foothold PLUS a location nobody could read.
    # `unknown` items are split out of the finding groups (see render), so the verdict is their only
    # home; printing nothing meant a responder neutralised what was found, rotated, and was never told
    lines += _unknown_surface_disclosure(issues, color=color, width=width)
    return lines


def _unknown_surface_disclosure(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """What is UNKNOWN about the persistence surface, and what to do about it — which locations exist
    but could not be read, or that the surface is wholly ABSENT and so was never enumerated.
    Keyed off the id (never off the verdict, and never off `severity`), so the disclosure survives
    whichever verdict outranks it.

    The FIX renders here too: `unknown` items are split out of the finding groups, so this is their
    only home, and printing the problem without the instruction said rotation was unsafe and never
    what would resolve it. A BLOCKED check is the exception — it has a home of its own that names
    which check went quiet, which this line cannot."""
    lines: list[str] = []
    for i in issues:
        if i.id not in UNVERIFIED_PERSISTENCE_IDS or i.id in _BLOCKED_IDS:
            continue
        lines += block(_safe(i.detail), indent=5, width=width)
        lines += block(_safe(i.remediation), indent=5, width=width,
                       marker=f"{MARKER['detail']} fix  ", code=SEVERITY["info"], color=color)
    return lines


def _scope_note(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """Build the line that says what an audit's result covers. Takes the audit's issues, whether to
    colour, and the width. Returns the lines."""
    lines: list[str] = []
    for text in scope_notes(issues):
        lines += block(text, indent=2, width=width, marker=f"{MARKER['meta']} ",
                       code=SEVERITY["info"], color=color)
    return lines


_BLOCKED_IDS = {BLOCKED_ID, BLOCKED_SURFACE_ID}


def _not_checked(issue: HygieneIssue) -> bool:
    """Tell whether an issue says something was not checked and has no other place in the report.
    Takes the issue. Returns True for a check that did not run, and for any other result not known,
    except one about the start-up entries, which the rotation verdict above discloses."""
    return issue.id in _BLOCKED_IDS or (issue.severity == "unknown"
                                         and issue.id not in UNVERIFIED_PERSISTENCE_IDS)


def _blocked_block(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """What this run did not check — neither a finding nor the absence of one, so printed on its
    own, under every headline including the reassuring ones, where it is most easily missed."""
    blocked = [i for i in issues if _not_checked(i)]
    if not blocked:
        return []
    out = [paint(f"{MARKER['warning']}  Not checked — this run did not cover these:",
                 SEVERITY["warning"], on=color)]
    for issue in blocked:
        out.append(f"  {paint(MARKER['unknown'], SEVERITY['warning'], on=color)} "
                   f"{paint(_safe(issue.title), SEVERITY['warning'], on=color)}")
        out += block(_safe(issue.detail), indent=5, width=width)
        out += block(_safe(issue.remediation), indent=5, width=width,
                     marker=f"{MARKER['detail']} fix  ", code=SEVERITY["info"], color=color)
    return out + [""]


def render(issues: list[HygieneIssue], *, color: bool = False, width: int = 80,
           content_scanned: bool = False) -> str:
    """Human-facing audit report. `color` (ANSI, gated by the caller via
    core.terminal.supports_color) and `width` (terminal columns, from core.render.term_width)
    default to plain/80 so a piped or test invocation is deterministic. `content_scanned` says the
    audit already content-scanned what it found (`saw audit --verify`). Findings are grouped
    worst-first (warnings to act on, then weaker items to review); long detail/fix/runbook lines
    wrap to `width` with a hanging indent. The run-level rotation-safety verdict always
    leads — reachable even when no individual finding is present."""
    rotation = _rotation_verdict(issues, color=color, width=width)

    # `unknown` items (unverified persistence surface) are surfaced in the rotation verdict above, not
    # as findings — they are the ABSENCE of a look, not something found. Split them out of the groups.
    # Worst-first WITHIN each group: a live foothold above a credential exposure above the rest,
    # which is the order the response runbook asks for. Findings arrived in probe-registration
    # order, so what appeared first was whichever check happened to be listed first.
    criticals, warnings, reviews = finding_groups(issues)
    unrun = _blocked_block(issues, color=color, width=width)

    if not (criticals or warnings or reviews):
        ids = {i.id for i in issues}
        if SURFACE_ABSENT_ID in ids:
            # This one leads even when a check was also blocked: it is the destroyed-home reading,
            # and it was lost when "some checks did not run" was tested ahead of it.
            head = "Local security hygiene: nothing was found because nothing was there to examine."
            if unrun:
                head += " Some checks did not run either."
        elif ids & _BLOCKED_IDS:
            head = "Local security hygiene: nothing was found, and some checks did not run."
        elif ids & UNVERIFIED_PERSISTENCE_IDS:
            head = "Local security hygiene: no findings, but the persistence surface is UNVERIFIED."
        elif unrun:
            head = "Local security hygiene: nothing was found, and some checks did not run."
        else:
            head = f"{MARKER['ok']} Local security hygiene: no issues found."
        code = SEVERITY["ok"] if "no issues" in head else SEVERITY["warning"]
        return "\n".join([paint(head, code, on=color), ""] + rotation + [""] + unrun
                         + _scope_note(issues, color=color, width=width)).rstrip()

    counts = []
    if criticals:
        counts.append(f"{len(criticals)} critical")
    if warnings:
        counts.append(f"{len(warnings)} warning{'' if len(warnings) == 1 else 's'}")
    if reviews:
        counts.append(f"{len(reviews)} to review")
    n = len(criticals) + len(warnings) + len(reviews)
    lines = [f"Local security hygiene — {n} finding{'' if n == 1 else 's'}: " + ", ".join(counts), ""]
    lines += rotation + [""]

    banner = _banner({i.id for i in issues}, color=color, width=width, content_scanned=content_scanned)
    if banner:
        lines += banner + [""]
    lines += unrun

    ranked = {id(i): display_rank(i.id, i.severity) for i in issues}
    show_headers = sum(map(bool, (criticals, warnings, reviews))) > 1
    for gtitle, gsub, gsev, items in (
            ("CRITICAL", "act on this first", "critical", criticals),
            ("WARNINGS", "act on these", "warning", warnings),
            ("TO REVIEW", "weaker signals to verify / hygiene", "info", reviews)):
        if not items:
            continue
        if show_headers:
            lines.append(paint(gtitle, SEVERITY[gsev], on=color) +
                         paint(f"  {MARKER['meta']} {gsub}", SEVERITY["info"], on=color))
        for i in items:
            code = SEVERITY.get(ranked[id(i)], SEVERITY.get(i.severity))
            icon = _icon(ranked[id(i)])
            # Encoded here, not at construction: a filename from a world-writable directory is
            # attacker-chosen, and an escape sequence has zero display width — it corrupts `block`'s
            # wrap arithmetic AND executes on the terminal. `command` stays verbatim by design (#86);
            # it is built from our own literals, confirmed no discovered path reaches it.
            lines.append(f"  {paint(icon, code, on=color)} "
                         f"{paint(_safe(i.title), code, on=color)}")
            lines += block(_safe(i.detail), indent=5, width=width)
            lines += block(_safe(i.remediation), indent=5, width=width,
                           marker=f"{MARKER['detail']} fix  ",
                           code=SEVERITY["info"], color=color)
            if i.command:
                # The copy-pasteable command renders VERBATIM on its own line(s), never reflowed — a
                # wrapped command is unsafe to paste, and keeping it out of the prose makes it cleanly
                lines += [f"       {cmd_line}" for cmd_line in i.command.split("\n")]
            if i.reference:
                lines.append("     " + paint(f"{MARKER['detail']} details: ", SEVERITY["info"], on=color) + i.reference)
            lines.append("")
    lines += _scope_note(issues, color=color, width=width)
    return "\n".join(lines).rstrip()

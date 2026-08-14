#!/usr/bin/env python3
"""Local machine security-posture checks (the "harden the surface" layer).

Single responsibility: inspect the *developer machine* — not repositories — for the worm's entry and
propagation surfaces, and report actionable hygiene issues. Split per concern into this package:

  * credentials    — a cached GitHub token (Keychain / ~/.git-credentials)
  * runner         — a self-hosted Actions runner (rotation-surviving foothold)
  * os_service     — a planted OS service / launch agent (the rotation wiper)
  * host_artifacts — staged ingress tooling / exfil drop-files
  * editor         — VS Code auto-run tasks + Workspace Trust
  * mechanism      — wave-agnostic sinks: ~/.ssh, shell startup files, exec-on-git-command config (#1161)
  * remote         — repository branch protection (the only enforced CI gate)

`audit_checks()` here is the SINGLE composition site — neither `audit()` nor the streaming CLI may
hand-assemble its own subset (that omission is how a probe once got silently dropped). Repository
indicator scanning lives in the scanner/service; this is complementary. Probes are stdlib-only and
degrade gracefully when a path/tool is absent — the one exception is the opt-in
`--verify` content-scan, which delegates to the scanner engine via a LAZY import so the
default audit never pulls it in (see host_artifacts.check_host_artifacts).
"""
from __future__ import annotations

import subprocess          # noqa: F401  re-exported so tests can patch hygiene.subprocess.run globally
from pathlib import Path   # noqa: F401  re-exported so tests can patch hygiene.Path.home globally
from typing import Callable

from .models import (HygieneIssue, INCIDENT_TRIGGER_IDS, ACTIVE_PERSISTENCE_IDS,
                     CREDENTIAL_EXPOSURE_IDS, UNVERIFIED_PERSISTENCE_IDS, ROTATION_UNSAFE_IDS,
                     SURFACE_UNREADABLE_ID, SURFACE_ABSENT_ID,
                     ROTATION_SAFE, ROTATION_UNSAFE_PERSISTENCE, ROTATION_UNSAFE_UNKNOWN,
                     TIER_ACTIVE_PERSISTENCE, TIER_CREDENTIAL_EXPOSURE, incident_tier,
                     persistence_surface_is_enumerable, rotation_safety,
                     incident_response_sequence, credential_exposure_note)
from .credentials import check_credentials
from .runner import check_runner_persistence
from .os_service import check_persistence
from .coverage import check_persistence_coverage
from .autorun import check_autorun
from .host_artifacts import check_host_artifacts
from .editor import check_vscode
from .mechanism import check_ssh_authorized_keys, check_shell_profile, check_git_config_execution
from .remote import check_branch_protection
from stayawake.utils import textsafe
from stayawake.utils.render import MARKER, SEVERITY, block, marked_list, paint

__all__ = [
    "HygieneIssue", "INCIDENT_TRIGGER_IDS", "ROTATION_UNSAFE_IDS", "rotation_safety",
    "incident_response_sequence",
    "check_credentials", "check_runner_persistence", "check_persistence",
    "check_persistence_coverage", "check_autorun", "check_host_artifacts",
    "check_vscode", "check_ssh_authorized_keys", "check_shell_profile", "check_git_config_execution",
    "check_branch_protection", "audit", "audit_checks", "render",
]

def audit(slug: str | None = None, token: str | None = None,
          branch: str = "main", *, verify_artifacts: bool = False) -> list[HygieneIssue]:
    """Run every local-posture check and return the combined issue list (non-streaming).

    Delegates to audit_checks() so the SINGLE definition of what an audit runs is shared with the
    streaming CLI — neither may hand-assemble its own subset (that omission is how a probe once got
    silently dropped)."""
    issues: list[HygieneIssue] = []
    for _label, check in audit_checks(slug, token, branch, verify_artifacts=verify_artifacts):
        issues += check()
    return issues


def audit_checks(slug: str | None = None, token: str | None = None, branch: str = "main",
                 *, verify_artifacts: bool = False
                 ) -> list[tuple[str, Callable[[], list[HygieneIssue]]]]:
    """The ordered (label, check) probes that make up an audit — the ONE definition of what
    `saw audit` runs, consumed by both audit() (all-at-once) and the streaming CLI (per-check
    spinner). Each `check` is a zero-arg callable returning list[HygieneIssue]. When a repo `slug`
    and `token` are supplied, the branch-protection gate on `branch` is included. `verify_artifacts`
    (the `--verify` opt-in) lets the host-artifact probe content-scan a lone weak dir."""
    return [
        ("cached credentials", check_credentials),
        ("VS Code settings", check_vscode),
        ("self-hosted runner", check_runner_persistence),
        ("OS-service persistence", check_persistence),
        ("persistence surface coverage", check_persistence_coverage),   # #1332 enumeration honesty
        ("host drop-files", lambda: check_host_artifacts(verify=verify_artifacts)),
        ("SSH authorized_keys", check_ssh_authorized_keys),
        ("shell startup files", check_shell_profile),
        ("git exec config", check_git_config_execution),
        ("autorun surface", check_autorun),                             # #1333 novel-foothold monitor
        ("branch protection", lambda: check_branch_protection(slug, token, branch)),
    ]


# Per-issue markers come from the shared vocabulary (`utils.render.MARKER`) rather than a local
# map, so this surface and the scan report cannot drift on what a glyph means — the same reason
# SEVERITY lives there. Two things this fixes over the local map it replaces:
#   * `unknown` now HAS a marker. It used to fall through to the `info` bullet and render
#     unpainted (no SEVERITY entry either), so "the surface could not be verified" (#1332) was
#     pixel-identical to a review-worthy nudge — the exact distinction #1332 exists to draw.
#   * the warning marker is the text glyph `⚠`, not the emoji `⚠️`. The emoji is double-width,
#     so warning rows sat one column right of info rows in the same list. The banner heads below
#     keep the emoji deliberately: they are standalone attention lines, not aligned columns.
def _icon(severity: str) -> str:
    return MARKER.get(severity, MARKER["info"])


# `textsafe.plain` defangs AND truncates, and its 300-char default is sized for one untrusted VALUE,
# not for prose carrying one: measured, it printed 2 of 11 unreadable locations and cut the
# rotation-wiper warning mid-sentence. Bounded still, just past anything we compose.
_REPORT_FIELD_LIMIT = 4000


def _safe(text: str) -> str:
    """One call for every untrusted field here, so a field added later cannot skip the defanging."""
    return textsafe.plain(text, limit=_REPORT_FIELD_LIMIT)


def _banner(issue_ids: set[str], *, color: bool, width: int) -> list[str]:
    """The incident banner, GRADED to the evidence (proportionality — see models): the full
    isolate → rebuild → rotate-LAST runbook leads ONLY on active host persistence; a lone
    credential EXPOSURE gets a calm, proportionate note (not "isolate and rebuild" over a cached
    token); hygiene / info-only findings get no banner. Empty list when none is warranted.

    The runbook is a genuine ORDERED procedure (rotate LAST) → a NUMBERED list; the note is a set
    of points/caveats, not a sequence → a BULLETED list. Both go through core.render.marked_list."""
    # The two banner heads are the deliberate emoji exception. Everything else on this surface takes
    # its glyph from MARKER, but a banner is a STANDALONE attention line that renders only when an
    # incident is live — never inside an aligned list — so the width cost that bars emoji from the
    # marker vocabulary does not apply, and the extra weight is the point.
    tier = incident_tier(issue_ids)
    if tier == TIER_ACTIVE_PERSISTENCE:
        head = "⚠️  Active host persistence detected — respond in THIS order (rotate LAST):"
        steps, ordered = incident_response_sequence(), True
    elif tier == TIER_CREDENTIAL_EXPOSURE:
        head = "⚠️  Credential exposure — no active host persistence detected:"
        steps, ordered = credential_exposure_note(), False
    else:
        return []
    return ([paint(head, SEVERITY["warning"], on=color)] +
            marked_list(steps, ordered=ordered, indent=5, width=width))


def _rotation_verdict(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """The run-level ROTATION-SAFETY verdict (#1332) — ALWAYS stated, reachable even with zero
    findings. Says explicitly whether credential rotation is safe, because rotating while a
    `gh-token-monitor` daemon is live arms a home-directory wiper. Three states (see models):
    SAFE (surface enumerated + clean), UNSAFE-persistence (a live foothold → the isolate/rotate-LAST
    runbook follows in _banner), UNSAFE-unknown (surface could not be read → treat as unsafe)."""
    verdict = rotation_safety({i.id for i in issues})
    if verdict == ROTATION_SAFE:
        return [paint(f"{MARKER['ok']} Rotation safety: persistence surface enumerated and clean "
                      "— rotating credentials is safe.", SEVERITY["ok"], on=color)]
    if verdict == ROTATION_UNSAFE_PERSISTENCE:
        lines = [paint(f"{MARKER['warning']}  Rotation safety: UNSAFE — active host persistence "
                       "detected; do NOT rotate any credential yet (runbook below).",
                       SEVERITY["warning"], on=color)]
    else:
        # UNSAFE-unknown: name exactly what could not be read, so the gap is actionable, not vague.
        # Marker and colour say different things here, on purpose: `?` states the EPISTEMIC fact
        # (we could not establish this), `warning` states the REQUIRED ACTION (do not rotate — this
        # path drives the unconditional exit 3). Painting it `unknown` too would soften an act-now
        # instruction; marking it `warning` would claim we looked and found something. Neither is
        # true alone, which is what having two channels is for.
        # "established", not "fully verified": one line for both states, and the latter sends an
        # operator hunting for an unreadable location when there may be none.
        lines = [paint(f"{MARKER['unknown']}  Rotation safety: UNKNOWN — the persistence surface "
                       "could not be established, so treat credential rotation as UNSAFE "
                       "until it is.", SEVERITY["warning"], on=color)]
    # The UNKNOWN surface is disclosed on BOTH unsafe paths. `rotation_safety` is a PRIORITY
    # function — active persistence dominates — so keying this disclosure off its verdict hid the
    # list in the one state that needs it most: a live foothold PLUS a location nobody could read.
    # `unknown` items are split out of the finding groups (see render), so the verdict is their only
    # home; printing nothing meant a responder neutralised what was found, rotated, and was never told
    # a persistence location had gone unexamined — the wiper hazard #1332 exists to close.
    lines += _unknown_surface_disclosure(issues, color=color, width=width)
    return lines


def _unknown_surface_disclosure(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """What is UNKNOWN about the persistence surface, and what to do about it — which locations exist
    but could not be read, or that the surface is wholly ABSENT and so was never enumerated (#120).
    Keyed off the id (never off the verdict, and never off `severity`), so the disclosure survives
    whichever verdict outranks it.

    The FIX renders here too: `unknown` items are split out of the finding groups, so this is their
    only home, and printing the problem without the instruction said rotation was unsafe and never
    what would resolve it."""
    lines: list[str] = []
    for i in issues:
        if i.id not in UNVERIFIED_PERSISTENCE_IDS:
            continue
        lines += block(_safe(i.detail), indent=5, width=width)
        lines += block(_safe(i.remediation), indent=5, width=width,
                       marker=f"{MARKER['detail']} fix  ", code=SEVERITY["info"], color=color)
    return lines


def _scope_note(issues: list[HygieneIssue], *, color: bool, width: int) -> list[str]:
    """REVEAL what this audit does not scan (#1341), so no result is read as a host all-clear over the
    locations supply-chain malware stages in. These are tracked GAPS on a path to closure (#1376 global
    npm prefix, #1377 Docker images/volumes, #1378 `/var/tmp`-class survivors and other mounts, #1373
    account-level state, and the Windows autorun surface — enumerated nowhere in the tool, so a
    Windows host produces no persistence findings at all), never accepted out-of-scope. Always shown; presentation only — never a
    finding, never affects the verdict or exit code.

    The probed drop-paths are named from what the code ACTUALLY probes — home, `/tmp`, and the system
    temp dir (`tempfile.gettempdir()`, which is `/var/folders/…` on macOS, not `/tmp`). Naming a path
    the probe does not read, or omitting one it does, is the same defect this note exists to remove.

    Both halves track the run state, because one fixed sentence misdescribes two of the three:

    * WHAT WAS READ — when the persistence surface could not be fully enumerated (#1332 UNKNOWN), a flat
      "reads the host persistence surface" would restate, as the report's last word, the very over-claim
      the verdict four lines above just withdrew.
    * WHAT IT MEANS — "a clean result does not exclude those" is inapplicable once something WAS found;
      a responder needs the compromise scoped WIDER than this list, not a clean-run caveat.
    """
    # Test for the unverified surface DIRECTLY, never via rotation_safety(): that is a PRIORITY
    # function (models.rotation_safety) where active persistence DOMINATES, so an incident that also
    # has an unreadable location returns UNSAFE_PERSISTENCE and would silently take the flat
    # full-coverage wording — restating the over-claim the verdict just withdrew, in the highest-stakes
    # state of all. Presence of the id is the honest question here, not which verdict outranks which.
    # And for the UNREADABLE id specifically, not the UNKNOWN set: "the part it could read" is false
    # when every location was read and none existed.
    ids = {i.id for i in issues}
    surface_unverified = SURFACE_UNREADABLE_ID in ids
    if not persistence_surface_is_enumerable():
        # `user_persistence_dirs()` is `~/.config/systemd/user` + `~/Library/LaunchAgents`, so on
        # Windows it enumerates NOTHING and every autorun probe returns empty. Claiming to read a
        # surface here would make "no findings" mean "clean" when it means "not examined" — the same
        # over-claim #1332 removed on the readability axis, one axis over.
        surface_read = ("does NOT enumerate a host persistence surface on this platform — it reads "
                        "only a targeted set of known drop-paths")
    elif surface_unverified:
        surface_read = ("reads the part of the host persistence surface it could read, plus a "
                        "targeted set of known drop-paths")
    elif SURFACE_ABSENT_ID in ids:
        # A third wording: the flat claim would restate the coverage the verdict just withdrew, and
        # "the part it could read" is equally wrong — reading was never the problem here.
        surface_read = ("found no host persistence surface present to read, and reads a targeted "
                        "set of known drop-paths")
    else:
        surface_read = "reads the host persistence surface and a targeted set of known drop-paths"
    # "Scope your response past what is listed here" presupposes an active compromise whose extent may
    # exceed the list — so it is gated on that EXACT tier, asked of `incident_tier()`, the same
    # authority `_banner` consults. Credential exposure is deliberately NOT that: the run says the
    # host is not implicated, so it takes the neutral wording below rather than contradicting the
    # green rotation verdict printed above it.
    if incident_tier({i.id for i in issues}) == TIER_ACTIVE_PERSISTENCE:
        means = "This may not be the full extent — scope your response past what is listed here."
    elif surface_unverified:
        means = ("The surface above could not be fully read, so this is not a clean bill of health for "
                 "those either.")
    elif issues:
        means = "These locations were not examined."
    else:
        means = "A clean result does not exclude those."
    # A gap list that omits an axis reads as COVERAGE of it, which is the failure this note exists to
    # prevent. `saw audit` is a DISK scanner: an account-level foothold (a self-hosted runner registered
    # against the org) survives a full host rebuild and is invisible here — so it is named, not implied
    # (#1340, deferred to #1373). The audit's own runner probe is disk-only and reads as broader than it is.
    return [paint("Scope of this audit:", SEVERITY["info"], on=color)] + block(
        # "OTHER survivor temp dirs" is relative to the system temp dir named just above, and is
        # therefore true in every state: `tempfile.gettempdir()` honours $TMPDIR, so naming a specific
        # path here (e.g. /var/tmp) would be a false claim on any host that points $TMPDIR at it.
        f"{surface_read} (home, /tmp, the system temp dir, the working directory). It does NOT scan "
        "other survivor temp dirs, the global npm prefix, Docker images/volumes, other mounted "
        "filesystems, account/organization-level state such as self-hosted runner registrations, "
        "or Windows autorun locations (registry Run keys, the Startup folder, Scheduled Tasks) — "
        "persistence enumeration is macOS and Linux user-scope only. "
        f"{means}",
        indent=2, width=width)


def render(issues: list[HygieneIssue], *, color: bool = False, width: int = 80) -> str:
    """Human-facing audit report. `color` (ANSI, gated by the caller via
    core.terminal.supports_color) and `width` (terminal columns, from core.render.term_width)
    default to plain/80 so a piped or test invocation is deterministic. Findings are grouped
    worst-first (warnings to act on, then weaker items to review); long detail/fix/runbook lines
    wrap to `width` with a hanging indent. The run-level rotation-safety verdict (#1332) always
    leads — reachable even when no individual finding is present."""
    rotation = _rotation_verdict(issues, color=color, width=width)

    # `unknown` items (unverified persistence surface) are surfaced in the rotation verdict above, not
    # as findings — they are the ABSENCE of a look, not something found. Split them out of the groups.
    warnings = [i for i in issues if i.severity == "warning"]
    reviews = [i for i in issues if i.severity == "info"]

    if not (warnings or reviews):
        # No findings. The verdict still stands: "clean" if the surface was verified, "unknown" if not.
        # Ask the ids, not `severity == "unknown"`: severity only correlates with "was the surface
        # unverified?" because ONE probe emits that pairing today. The rotation verdict, the exit gate
        # and the scope note all key off UNVERIFIED_PERSISTENCE_IDS, so a second unknown-severity id
        # would otherwise split this heading three ways from the verdict printed under it.
        head = (f"{MARKER['ok']} Local security hygiene: no issues found."
                if not ({i.id for i in issues} & UNVERIFIED_PERSISTENCE_IDS)
                else "Local security hygiene: no findings, but the persistence surface is UNVERIFIED.")
        code = SEVERITY["ok"] if "no issues" in head else SEVERITY["warning"]
        return "\n".join([paint(head, code, on=color), ""] + rotation
                         + [""] + _scope_note(issues, color=color, width=width)).rstrip()

    counts = []
    if warnings:
        counts.append(f"{len(warnings)} warning{'' if len(warnings) == 1 else 's'}")
    if reviews:
        counts.append(f"{len(reviews)} to review")
    n = len(warnings) + len(reviews)
    lines = [f"Local security hygiene — {n} finding{'' if n == 1 else 's'}: " + ", ".join(counts), ""]
    lines += rotation + [""]

    banner = _banner({i.id for i in issues}, color=color, width=width)
    if banner:
        lines += banner + [""]

    # Group headers only when BOTH tiers are present (otherwise the counts line already says which).
    show_headers = bool(warnings) and bool(reviews)
    for gtitle, gsub, gsev, items in (
            ("WARNINGS", "act on these", "warning", warnings),
            ("TO REVIEW", "weaker signals to verify / hygiene", "info", reviews)):
        if not items:
            continue
        if show_headers:
            lines.append(paint(gtitle, SEVERITY[gsev], on=color) +
                         paint(f"  {MARKER['meta']} {gsub}", SEVERITY["info"], on=color))
        for i in items:
            code = SEVERITY.get(i.severity)
            icon = _icon(i.severity)
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
                # selectable (#1237). Rationale stays in `remediation`; the deep "why" is the details link.
                lines += [f"       {cmd_line}" for cmd_line in i.command.split("\n")]
            if i.reference:
                lines.append("     " + paint(f"{MARKER['detail']} details: ", SEVERITY["info"], on=color) + i.reference)
            lines.append("")
    lines += _scope_note(issues, color=color, width=width)
    return "\n".join(lines).rstrip()

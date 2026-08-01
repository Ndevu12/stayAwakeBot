#!/usr/bin/env python3
"""`saw guard setup` — install or update the Strix gate, always PROPOSED (working tree or PR via the
shared `proposal` ladder). Never commits to the default branch, never runs the repo's code."""
from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.adapters import github_api
from stayawake.lib import git as gitutil
from stayawake.utils import textsafe
from stayawake.utils.render import SEVERITY, paint
from stayawake.utils.streaming import status as spin_status
from stayawake.core import proposal
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.guard.constants import (
    STRIX_OWNER, STRIX_REPO, WORKFLOW_DIR, WORM_GUARD_FILE, SETUP_BRANCH)
from stayawake.bots.security.guard.detect import (
    check, classify_pin, find_strix, find_worm_gate, render,
    _local_workflows, _ref_workflows, _local_action_reader, _ref_action_reader)

# ── setup: install or update the gate, always PROPOSED (working tree or PR) ───────────────────────
# `saw guard setup` = check + act. It resolves the pin to write (latest Strix release → SHA, or an
# explicit --ref), plans the minimal change (create the workflow / surgically bump the pin / no-op),
# and delivers it for review: writes into the working tree by default, or opens a rolling PR with
# `--pr`. It NEVER commits to the default branch and never emits a floating pin silently.

# Rewrites ONLY the strix `uses:` ref on its line; everything else (indentation, the `uses:` key, the
# consumer's other steps/triggers) is preserved so a bump can't stomp the file. Tolerates an optional
# surrounding quote (`uses: "Ndevu12/strix@v0"`) and normalizes to the conventional unquoted form; the
# trailing `# comment` is replaced with the resolved release tag. If a form still slips past this,
# `setup()` refuses to claim a repin that changed nothing (never a silent no-op).
_STRIX_USES_LINE = re.compile(
    r"^(?P<pre>[ \t]*(?:-[ \t]+)?uses:[ \t]*)['\"]?Ndevu12/strix@\S+.*$",
    re.IGNORECASE | re.MULTILINE)


@dataclass
class Pin:
    """The immutable ref to write: a commit SHA, plus the release tag it came from (for a `# vX.Y.Z`
    comment). `tag` is None for an explicit `--ref <sha>` where we don't know the tag."""
    sha: str
    tag: str | None = None


@dataclass
class SetupPlan:
    """The minimal change setup will make. `content` is the full new file text (create/repin),
    None for a no-op/present/conflict. `old_ref`/`new_ref` drive the human summary; `detail`
    describes an existing non-Strix gate for the `present` action."""
    action: str                       # "create" | "repin" | "noop" | "present" | "conflict"
    path: str                         # workflow file, repo-relative
    content: str | None = None
    old_ref: str | None = None
    new_ref: str | None = None
    detail: str | None = None         # for "present": how the existing gate runs (mechanism label)


@dataclass
class SetupResult:
    plan: SetupPlan | None = None
    wrote: Path | None = None                     # working-tree write path (local mode)
    submit: proposal.SubmitResult | None = None   # PR-ladder outcome (`--pr`)
    slug: str | None = None
    signed: bool = True                           # False → the PR commit had to be landed unsigned
    dry_run: bool = False
    error: str | None = None


def resolve_pin(token: str | None = None, ref: str | None = None) -> Pin | None:
    """The Strix ref to pin. An explicit `ref` (SHA used verbatim; a tag resolved to its immutable
    SHA) supports offline/deterministic pinning; otherwise resolve the LATEST release to its commit
    SHA. Returns None when it can't resolve — setup then fails closed rather than emit a floating
    pin (trust-on-first-use: the SHA is reviewed in the diff/PR)."""
    if ref:
        if classify_pin(ref) == "sha":
            return Pin(ref)
        sha = github_api.ref_commit_sha(STRIX_OWNER, STRIX_REPO, f"tags/{ref}", token)
        return Pin(sha, ref) if sha else None
    rel = github_api.latest_release(STRIX_OWNER, STRIX_REPO, token)
    tag = rel.get("tag_name") if isinstance(rel, dict) else None
    if not tag:
        return None
    sha = github_api.ref_commit_sha(STRIX_OWNER, STRIX_REPO, f"tags/{tag}", token)
    return Pin(sha, tag) if sha else None


def render_workflow(pin: Pin, default_branch: str = "main") -> str:
    """The report-only, least-privilege worm-guard workflow, SHA-pinned. Remediation (which needs
    scoped write) is deliberately NOT enabled here — it's an opt-in follow-up. The gate is found by
    its `uses: Ndevu12/strix@<sha>` reference (not this filename), so re-running setup bumps the pin."""
    comment = f"  # {pin.tag}" if pin.tag else ""
    return (
        "# Strix worm-guard — installed/updated by `saw guard setup`.\n"
        "# Blocks a merge when Strix finds self-propagating worm indicators. Found by its\n"
        "# `uses: Ndevu12/strix@<sha>` reference (not this filename); re-run `saw guard setup` to bump\n"
        "# the SHA. Report-only least privilege (contents: read). Auto-remediation needs scoped write\n"
        "# — see the Strix README's Auto-remediation section; it is deliberately opt-in.\n"
        "name: Worm guard — block infected merges\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        f"    branches: [{default_branch}]\n"
        "\n"
        "permissions:\n"
        "  contents: read       # pure exit-code gate: green = clean, red = infected\n"
        "\n"
        "jobs:\n"
        "  worm-guard:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Checkout (full history so evil-merge detection sees the whole graph)\n"
        "        uses: actions/checkout@v4\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "      - name: Strix worm scan\n"
        f"        uses: Ndevu12/strix@{pin.sha}{comment}\n"
    )


def _repin(text: str, pin: Pin) -> str:
    """Surgically rewrite ONLY the strix `uses:` ref, preserving the rest of the file byte-for-byte."""
    comment = f"  # {pin.tag}" if pin.tag else ""
    return _STRIX_USES_LINE.sub(
        lambda m: f"{m.group('pre')}Ndevu12/strix@{pin.sha}{comment}", text)


_GATE_HOW = {"local-action": "a local scan action", "saw-run": "a direct `saw` step"}


def plan_setup(workflows: dict[str, str], default_branch: str, pin: Pin, *,
               read_action=None) -> SetupPlan:
    """Decide the minimal change: bump an existing Strix pin, no-op when already at the resolved SHA,
    leave an existing worm gate installed by ANOTHER mechanism alone ('present'), or create the gate
    when the repo is genuinely unguarded — never clobbering a file already at the create path."""
    gate = find_worm_gate(workflows, read_action=read_action)
    if gate is None:
        # Unguarded by any mechanism — install. But NEVER clobber a non-gate workflow already sitting
        # at the conventional path (data-loss guard, #1239).
        if WORM_GUARD_FILE in workflows:
            return SetupPlan("conflict", WORM_GUARD_FILE)
        return SetupPlan("create", WORM_GUARD_FILE, render_workflow(pin, default_branch),
                         new_ref=pin.sha)
    if gate.mechanism != "strix":
        # Already guarded by a local scan action / a direct `saw` step — don't install a duplicate.
        return SetupPlan("present", gate.workflow,
                         detail=_GATE_HOW.get(gate.mechanism, gate.mechanism))
    ref = gate.strix
    if ref.pin == "sha" and ref.ref.lower() == pin.sha.lower():
        return SetupPlan("noop", ref.workflow, old_ref=ref.ref, new_ref=pin.sha)
    return SetupPlan("repin", ref.workflow, _repin(workflows[ref.workflow], pin),
                     old_ref=ref.ref, new_ref=pin.sha)


def _setup_pr_body(plan: SetupPlan, base: str) -> str:
    """The install/bump PR body — carries the hardening a PR can't do itself (a change file can't
    set branch protection, CODEOWNERS, or the create-PR repo setting), stated honestly."""
    verb = "Installs" if plan.action == "create" else "Updates the pin of"
    tag = f" (`{plan.new_ref}`)" if plan.new_ref and len(plan.new_ref) == 40 else ""
    return "\n".join([
        f"{verb} the **Strix worm-guard** CI gate — opened by `saw guard setup`.",
        "",
        f"- **File:** {textsafe.code(plan.path)}",   # repo-controlled filename → injection-safe
        f"- **Pin:** `Ndevu12/strix@{plan.new_ref[:12]}…`{tag}",
        "- **Posture:** report-only least privilege (`contents: read`). Auto-remediation is opt-in.",
        "",
        "### Please finish the hardening (a PR can't set these):",
        "- [ ] Mark the **worm-guard** check **required** in branch protection.",
        "- [ ] Add **CODEOWNERS** on `.github/**` (and `config/security.yml`, if used).",
        "",
        "_A PR opened by a bot token may not trigger the new workflow on this PR — push an empty "
        "commit to run the gate on itself. This is a single rolling PR; re-runs update it._",
    ])


def _setup_pr(repo: Path, plan: SetupPlan, base: str, token: str | None, spin: bool) -> SetupResult:
    """Build the change in a throwaway worktree off the default branch and open/update one rolling
    PR via the shared `proposal` ladder — never a push to the default branch."""
    from stayawake.core.identity import Intent, require

    slug = gitutil.origin_slug(repo)
    if not slug:
        return SetupResult(plan=plan, error="no GitHub origin — cannot open a PR (drop --pr to write "
                                            "the file locally, or add a remote)")
    # AuthZ BEFORE worktree/commit — missing `workflow` must not look like 'no write access' after
    # expensive work. Uses resolve_session() so App / gh / env all go through one gate.
    decision = require(Intent.OPEN_GUARD_PR, repo_slug=slug)
    if not decision.allowed:
        return SetupResult(plan=plan, slug=slug, error=decision.message)
    if not token:
        from stayawake.core.identity import resolve_session
        token = resolve_session(repo_slug=slug).token
    if not token:
        return SetupResult(plan=plan, slug=slug, error=decision.message)

    baseref = f"origin/{base}" if gitutil.ref_exists(repo, f"origin/{base}") else base
    gitutil.fetch(repo, "origin", base)
    wt = Path(tempfile.mkdtemp(prefix="sab-guard-"))
    if not gitutil.add_worktree(repo, wt, SETUP_BRANCH, baseref):
        gitutil.remove_worktree(repo, wt)
        return SetupResult(plan=plan, slug=slug, error="could not create a worktree for the PR")
    try:
        dest = wt / plan.path
        if not is_safe_write_target(dest, wt):        # never write the gate through a planted symlink (#1218)
            return SetupResult(plan=plan, slug=slug,
                               error=f"refusing to write {plan.path} — it is a symlink or escapes the worktree")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plan.content, encoding="utf-8")
        if not gitutil.stage_all(wt):
            return SetupResult(plan=plan, slug=slug, error="could not stage the workflow change")
        verb = "install" if plan.action == "create" else "update"
        commit = gitutil.commit_fix(
            wt, f"ci(security): {verb} the Strix worm-guard gate\n\n"
                f"Pin Ndevu12/strix@{plan.new_ref[:12]}. Opened by `saw guard setup`.")
        if not commit.committed:
            return SetupResult(plan=plan, slug=slug, error="could not commit the workflow change")
        title = ("ci(security): install the Strix worm-guard gate" if plan.action == "create"
                 else "ci(security): update the Strix worm-guard pin")
        with spin_status(f"opening guard PR for {slug}…", enabled=spin):
            res = proposal.submit_change_pr(wt, slug, base, branch=SETUP_BRANCH, title=title,
                                            body=_setup_pr_body(plan, base), token=token)
        return SetupResult(plan=plan, slug=slug, submit=res, signed=commit.signed)
    finally:
        gitutil.remove_worktree(repo, wt)


def setup(repo: str | Path | None = None, *, token: str | None = None, ref: str | None = None,
          dry_run: bool = False, pr: bool = False, branch: str | None = None,
          spin: bool = False, pin: "Pin | None" = None) -> SetupResult:
    """Install or update the Strix gate on a LOCAL repo. Default: write the change into the working
    tree for the operator to review + commit + PR. `--pr`: open a rolling PR via the ladder. Either
    way the default branch is only ever proposed to, never pushed. A sweep passes a precomputed `pin`
    (resolved once); otherwise it resolves the latest release here (fails closed offline → pass `ref`)."""
    repo = Path(repo or ".")
    if pin is None:
        pin = resolve_pin(token, ref)
    if pin is None:
        return SetupResult(error="couldn't resolve the latest Strix release "
                                 "(offline? pass --ref <sha|tag> to pin explicitly)")
    default_branch = branch or gitutil.default_branch(repo)
    if pr:
        # `--pr` targets origin's default branch, so plan against WHAT ORIGIN HAS — never a dirty or
        # UNTRACKED working tree. A worm-guard.yml written by a prior local `setup` (uncommitted) must
        # not mask that origin lacks the gate, or `--pr` would wrongly no-op and never open the PR.
        gitutil.fetch(repo, "origin", default_branch)
        baseref = (f"origin/{default_branch}" if gitutil.ref_exists(repo, f"origin/{default_branch}")
                   else default_branch)
        workflows = _ref_workflows(repo, baseref)
        reader = _ref_action_reader(repo, baseref)
    else:
        workflows = _local_workflows(repo)
        reader = _local_action_reader(repo)
    plan = plan_setup(workflows, default_branch, pin, read_action=reader)
    if plan.action == "present":
        # Already guarded by another mechanism — nothing to install; render explains.
        return SetupResult(plan=plan)
    if plan.action == "conflict":
        # A file already occupies the install path but isn't a recognizable worm gate — refuse to
        # overwrite it (data loss, #1239). A real gate at that path resolves to "present" above.
        return SetupResult(plan=plan, error=f"a workflow already exists at {plan.path} but isn't a "
                           "recognizable worm gate — not overwriting it. Remove or rename it, then "
                           "re-run `saw guard setup`.")
    if plan.action == "repin" and f"strix@{pin.sha}" not in (plan.content or ""):
        # find_strix (YAML-aware) saw a gate the line-surgical rewrite couldn't touch (an exotic
        # `uses:` form). Never claim a bump that changed nothing — tell the operator to edit it.
        return SetupResult(plan=plan, error=f"found a Strix gate in {plan.path} but couldn't "
                           f"surgically rewrite its pin — set `uses: Ndevu12/strix@{pin.sha}` there manually")
    if plan.action == "noop" or dry_run:
        return SetupResult(plan=plan, dry_run=dry_run)
    if pr:
        return _setup_pr(repo, plan, default_branch, token, spin)
    # LOCAL: write into the working tree for the operator to review, commit on a branch, and PR.
    dest = repo / plan.path
    if not is_safe_write_target(dest, repo):          # never write the gate through a planted symlink (#1218)
        return SetupResult(plan=plan,
                           error=f"refusing to write {plan.path} — it is a symlink or escapes the repo")
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plan.content, encoding="utf-8")
    except OSError as e:
        return SetupResult(plan=plan, error=f"could not write {plan.path}: {e}")
    return SetupResult(plan=plan, wrote=dest)


def _short(ref: str | None) -> str:
    return f"{ref[:12]}…" if ref and len(ref) == 40 else (ref or "?")


def render_setup(result: SetupResult, *, color: bool = False) -> str:
    """Human-facing outcome for a SetupResult — rendering lives in the module, not the CLI (SRP)."""
    ok, warn, dim = SEVERITY["ok"], SEVERITY["warning"], SEVERITY["info"]
    if result.error:
        return paint(f"⚠️  {result.error}", warn, on=color)
    plan = result.plan
    if plan.action == "present":
        return (paint("✓ already guarded", ok, on=color) +
                f" — {plan.path} already runs a worm scan via {plan.detail}. Not installing a "
                "duplicate. To adopt the SHA-pinned `Ndevu12/strix` gate instead, remove it first.")
    if plan.action == "noop":
        return (paint("✓ already up to date", ok, on=color) +
                f" — {plan.path} pins Ndevu12/strix@{_short(plan.new_ref)} (latest). Nothing to do.")

    verb = "install" if plan.action == "create" else "update the pin in"
    if result.dry_run:
        head = paint(f"— dry run: would {verb} {plan.path}", dim, on=color) + \
            f"  (→ Ndevu12/strix@{_short(plan.new_ref)})"
        preview = plan.content if plan.action == "create" else _repin_preview(plan)
        return head + "\n\n" + preview

    if result.wrote is not None:
        return (paint(f"✓ wrote {plan.path}", ok, on=color) +
                f"  ({plan.action} · pinned @{_short(plan.new_ref)})\n"
                "  Review the diff, commit on a branch, and open a PR — do NOT push to the default "
                "branch.\n  (Or re-run with --pr to open the PR for you.)")

    if result.submit is not None:
        return _render_setup_submit(result, color=color)
    return ""


def _repin_preview(plan: SetupPlan) -> str:
    """Show just the rewritten `uses:` line for a repin dry-run (the rest of the file is untouched)."""
    for line in (plan.content or "").splitlines():
        if _STRIX_USES_LINE.match(line):
            return f"  {line.strip()}"
    return ""


def _render_setup_submit(result: SetupResult, *, color: bool) -> str:
    """Render the PR-ladder outcome for `--pr`. The ladder returns structured facts; the guard-domain
    wording lives here (mirrors how `saw fix` renders its own SubmitResult)."""
    ok, warn = SEVERITY["ok"], SEVERITY["warning"]
    res, slug = result.submit, result.slug
    sign = ("" if result.signed else
            paint("\n  ⚠ the PR commit is UNSIGNED (signing failed in the worktree); if this repo "
                  "enforces signed commits, re-sign before merging.", warn, on=color))
    if res.kind == "pr":
        verb = "updated existing" if res.action == "updated" else "opened"
        return paint(f"✓ {verb} guard PR #{res.number}", ok, on=color) + f" ({res.url}) on {slug}" + sign
    if res.kind == "fork-pr":
        verb = "updated existing" if res.action == "updated" else "opened"
        return (paint(f"✓ {verb} guard fork PR #{res.number}", ok, on=color) +
                f" ({res.url}) from {res.fork_slug}" + sign)
    if res.kind in ("pr-create-failed", "fork-pr-create-failed"):
        return paint(f"⚠️  {slug}: branch pushed but the PR API call failed (check token scope)",
                     warn, on=color) + sign
    if res.kind == "fork-not-ready":
        return paint(f"⚠️  {slug}: forked to {res.fork_slug} but it wasn't ready in time — retry later",
                     warn, on=color)
    # floor: classified push failure + optional patch
    from stayawake.core.identity import push_failure_message
    from stayawake.core.identity.classify import PushFailure
    why = push_failure_message(PushFailure(res.push_reason or "unknown", res.push_detail or ""))
    where = f" (saved a patch at {res.patch_path})" if res.patch_path else ""
    return paint(f"⚠️  {slug}: {why}{where}", warn, on=color) + sign



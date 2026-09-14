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
    STRIX_OWNER, STRIX_REPO, WORKFLOW_DIR, WORM_GUARD_FILE, SETUP_BRANCH,
    CHECKOUT_ACTION, SETUP_PYTHON_ACTION)
from stayawake.bots.security.guard.detect import (
    check, classify_pin, find_strix, find_worm_gate, grade_config, render,
    _local_workflows, _ref_workflows, _local_action_reader, _ref_action_reader)


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
    action: str
    path: str
    content: str | None = None
    old_ref: str | None = None
    new_ref: str | None = None
    detail: str | None = None


@dataclass
class SetupResult:
    plan: SetupPlan | None = None
    wrote: Path | None = None
    submit: proposal.SubmitResult | None = None
    slug: str | None = None
    signed: bool = True
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


def resolve_scanner_version(token: str | None = None) -> str | None:
    """The `stayawakebot` release the gate installs. Without it the action runs `pip install
    stayawakebot`, so the SHA-pinned step fetches whatever is newest at run time and the pin buys
    nothing. Returns None when it cannot be resolved — setup then fails closed rather than provision
    an unpinned scanner, the same posture `resolve_pin` takes for the action SHA."""
    rel = github_api.latest_release("Ndevu12", "stayAwakeBot", token)
    tag = rel.get("tag_name") if isinstance(rel, dict) else None
    if not isinstance(tag, str):
        return None
    version = tag.lstrip("vV").strip()
    return version if re.fullmatch(r"\d+\.\d+\.\d+", version) else None


def render_workflow(pin: Pin, default_branch: str = "main", scanner: str | None = None) -> str:
    """The worm-guard workflow `saw guard setup` installs.

    Takes the action pin, the default branch to gate, and the scanner version to pin. Returns the
    full workflow text: a `worm-guard` job that scans and reports, a `remediate` job reachable only
    on an infected verdict, and a weekly `pin-drift` job. Described in `docs/reference/cli/guard.md`.
    """
    version_line = f"          version: '{scanner}'\n" if scanner else ""
    scanner_spec = f"stayawakebot=={scanner}" if scanner else "stayawakebot"
    return (
        "name: Worm guard — block infected merges\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        f"    branches: [{default_branch}]\n"
        "  schedule:\n"
        "    - cron: '0 7 * * 1'\n"
        "  workflow_dispatch:\n"
        "\n"
        "permissions: {}\n"
        "\n"
        "jobs:\n"
        "  worm-guard:\n"
        "    if: github.event_name != 'schedule'\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "      pull-requests: write\n"
        "      security-events: write\n"
        "    outputs:\n"
        "      verdict: ${{ steps.scan.outputs.verdict }}\n"
        "      infected: ${{ steps.scan.outputs.infected }}\n"
        "    steps:\n"
        f"      - uses: {CHECKOUT_ACTION.uses()}\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        "      - id: scan\n"
        f"        uses: Ndevu12/strix@{pin.sha}\n"
        "        with:\n"
        f"{version_line}"
        "          remediate: 'off'\n"
        "          github-token: ${{ github.token }}\n"
        "          pr-comment: true\n"
        "          upload-sarif: true\n"
        "          upload-artifact: true\n"
        "\n"
        "  remediate:\n"
        "    needs: worm-guard\n"
        "    if: ${{ !cancelled() && (needs.worm-guard.outputs.verdict == 'infected'"
        " || needs.worm-guard.outputs.infected != '0') }}\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: write\n"
        "      pull-requests: write\n"
        "    steps:\n"
        f"      - uses: {CHECKOUT_ACTION.uses()}\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        f"      - uses: Ndevu12/strix@{pin.sha}\n"
        "        with:\n"
        f"{version_line}"
        "          remediate: pr\n"
        "          github-token: ${{ secrets.GH_SECURITY_TOKEN || github.token }}\n"
        "          upload-artifact: true\n"
        "\n"
        "  pin-drift:\n"
        "    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      contents: read\n"
        "      issues: write\n"
        "    steps:\n"
        f"      - uses: {CHECKOUT_ACTION.uses()}\n"
        f"      - uses: {SETUP_PYTHON_ACTION.uses()}\n"
        "        with:\n"
        "          python-version: '3.x'\n"
        "      - env:\n"
        "          GITHUB_TOKEN: ${{ github.token }}\n"
        "        run: |\n"
        f"          pip install {scanner_spec}\n"
        "          saw guard drift\n"
    )


def _repin(text: str, pin: Pin) -> str:
    """Surgically rewrite ONLY the strix `uses:` ref, preserving the rest of the file byte-for-byte."""
    comment = f"  # {pin.tag}" if pin.tag else ""
    return _STRIX_USES_LINE.sub(
        lambda m: f"{m.group('pre')}Ndevu12/strix@{pin.sha}{comment}", text)


_GATE_HOW = {"local-action": "a local scan action", "saw-run": "a direct `saw` step"}


def plan_setup(workflows: dict[str, str], default_branch: str, pin: Pin, *,
               read_action=None, scanner: str | None = None) -> SetupPlan:
    """Decide the minimal change: bump an existing Strix pin, no-op when already at the resolved SHA,
    leave an existing worm gate installed by ANOTHER mechanism alone ('present'), or create the gate
    when the repo is genuinely unguarded — never clobbering a file already at the create path."""
    gate = find_worm_gate(workflows, read_action=read_action)
    if gate is None:
        if WORM_GUARD_FILE in workflows:
            return SetupPlan("conflict", WORM_GUARD_FILE)
        return SetupPlan("create", WORM_GUARD_FILE, render_workflow(pin, default_branch, scanner),
                         new_ref=pin.sha)
    if gate.mechanism != "strix":
        return SetupPlan("present", gate.workflow,
                         detail=_GATE_HOW.get(gate.mechanism, gate.mechanism))
    ref = gate.strix
    config = grade_config(ref)
    if config.degraded and ref.workflow == WORM_GUARD_FILE:
        return SetupPlan("repair", ref.workflow, render_workflow(pin, default_branch, scanner),
                         old_ref=ref.ref, new_ref=pin.sha, detail=_degraded_detail(config))
    if ref.pin == "sha" and ref.ref.lower() == pin.sha.lower():
        return SetupPlan("noop", ref.workflow, old_ref=ref.ref, new_ref=pin.sha,
                         detail=_degraded_detail(config) if config.degraded else None)
    return SetupPlan("repin", ref.workflow, _repin(workflows[ref.workflow], pin),
                     old_ref=ref.ref, new_ref=pin.sha,
                     detail=_degraded_detail(config) if config.degraded else None)


def _degraded_detail(config) -> str:
    """One line naming what is wrong with a gate's configuration, for the setup summary."""
    parts = []
    if config.ignored_inputs:
        parts.append(f"passes {', '.join(config.ignored_inputs)}, which the action does not take")
    if config.reports_nothing:
        parts.append("reports a finding nowhere")
    if config.standing_write:
        parts.append("can write to the repository on every run")
    return "; ".join(parts)


def _setup_pr_body(plan: SetupPlan, base: str) -> str:
    """The install/bump PR body — carries the hardening a PR can't do itself (a change file can't
    set branch protection, CODEOWNERS, or the create-PR repo setting), stated honestly."""
    verb = ("Installs" if plan.action == "create"
            else "Rewrites the configuration of" if plan.action == "repair"
            else "Updates the pin of")
    tag = f" (`{plan.new_ref}`)" if plan.new_ref and len(plan.new_ref) == 40 else ""
    return "\n".join([
        f"{verb} the **Strix worm-guard** CI gate — opened by `saw guard setup`.",
        "",
        f"- **File:** {textsafe.code(plan.path)}",
        *([f"- **Replaced because** the gate {plan.detail}. Jobs and settings this file carried "
           "beyond the gate itself are not preserved — review the diff."]
          if plan.action == "repair" and plan.detail else []),
        f"- **Pin:** `Ndevu12/strix@{plan.new_ref[:12]}…`{tag}",
        "- **Gate job** (`worm-guard`): scans PRs/pushes and reports what it finds — a PR comment, a "
        "code-scanning alert and a run artifact. It **cannot push to this repository** "
        "(`contents: read`).",
        "- **Remediation job** (`remediate`): opens ONE rolling `security/auto-clean` fix PR. It is the "
        "only job that can push, and it is reachable only once the scan has already reported an "
        "infected verdict — so on a clean run nothing here holds write access. The gate stays **red "
        "until that fix PR is merged**: remediation opens the fix, it does not make the check pass.",
        "- **Pin-drift job** (`pin-drift`): weekly (+ manual) it files ONE self-closing issue if the "
        "pinned Strix release falls behind (`issues: write` only).",
        "",
        "### Please finish the hardening (a PR can't set these):",
        "- [ ] Mark the **worm-guard** check **required** in branch protection.",
        "- [ ] Add **CODEOWNERS** on `.github/**` (and `config/security.yml`, if used).",
        "- [ ] Enable **Settings → Actions → General → “Allow GitHub Actions to create and approve pull "
        "requests”** so the gate can open the fix PR.",
        "- [ ] *(optional)* add a **`GH_SECURITY_TOKEN`** secret (a PAT with repo + PR scope) so the fix "
        "PR itself gets scanned — a PR opened with the built-in token does not re-trigger this gate.",
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
        if not is_safe_write_target(dest, wt):
            return SetupResult(plan=plan, slug=slug,
                               error=f"refusing to write {plan.path} — it is a symlink or escapes the worktree")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plan.content, encoding="utf-8")
        if not gitutil.stage_all(wt):
            return SetupResult(plan=plan, slug=slug, error="could not stage the workflow change")
        verb = ("install" if plan.action == "create"
                else "repair" if plan.action == "repair" else "update")
        commit = gitutil.commit_fix(
            wt, f"ci(security): {verb} the Strix worm-guard gate\n\n"
                f"Pin Ndevu12/strix@{plan.new_ref[:12]}. Opened by `saw guard setup`.")
        if not commit.committed:
            return SetupResult(plan=plan, slug=slug, error="could not commit the workflow change")
        title = ("ci(security): install the Strix worm-guard gate" if plan.action == "create"
                 else "ci(security): the worm gate reports its findings and holds no standing write"
                 if plan.action == "repair"
                 else "ci(security): update the Strix worm-guard pin")
        with spin_status(f"opening guard PR for {slug}…", enabled=spin):
            res = proposal.submit_change_pr(wt, slug, base, branch=SETUP_BRANCH, title=title,
                                            body=_setup_pr_body(plan, base), token=token)
        return SetupResult(plan=plan, slug=slug, submit=res, signed=commit.signed)
    finally:
        gitutil.remove_worktree(repo, wt)


def setup(repo: str | Path | None = None, *, token: str | None = None, ref: str | None = None,
          dry_run: bool = False, pr: bool = False, branch: str | None = None,
          spin: bool = False, pin: "Pin | None" = None,
          scanner: str | None = None) -> SetupResult:
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
    if scanner is None:
        scanner = resolve_scanner_version(token)
    if scanner is None:
        return SetupResult(error="couldn't resolve the scanner release to pin — not installing "
                                 "a gate that would take whatever is newest when it runs "
                                 "(offline?)")
    default_branch = branch or gitutil.default_branch(repo)
    if pr:
        gitutil.fetch(repo, "origin", default_branch)
        baseref = (f"origin/{default_branch}" if gitutil.ref_exists(repo, f"origin/{default_branch}")
                   else default_branch)
        workflows = _ref_workflows(repo, baseref)
        reader = _ref_action_reader(repo, baseref)
    else:
        workflows = _local_workflows(repo)
        reader = _local_action_reader(repo)
    plan = plan_setup(workflows, default_branch, pin, read_action=reader, scanner=scanner)
    if plan.action == "present":
        return SetupResult(plan=plan)
    if plan.action == "conflict":
        return SetupResult(plan=plan, error=f"a workflow already exists at {plan.path} but isn't a "
                           "recognizable worm gate — not overwriting it. Remove or rename it, then "
                           "re-run `saw guard setup`.")
    if plan.action == "repin" and f"strix@{pin.sha}" not in (plan.content or ""):
        return SetupResult(plan=plan, error=f"found a Strix gate in {plan.path} but couldn't "
                           f"surgically rewrite its pin — set `uses: Ndevu12/strix@{pin.sha}` there manually")
    if plan.action == "noop" or dry_run:
        return SetupResult(plan=plan, dry_run=dry_run)
    if pr:
        return _setup_pr(repo, plan, default_branch, token, spin)
    dest = repo / plan.path
    if not is_safe_write_target(dest, repo):
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

    verb = ("install" if plan.action == "create"
            else "repair" if plan.action == "repair" else "update the pin in")
    if result.dry_run:
        head = paint(f"— dry run: would {verb} {plan.path}", dim, on=color) + \
            f"  (→ Ndevu12/strix@{_short(plan.new_ref)})"
        preview = (plan.content if plan.action in ("create", "repair")
                   else _repin_preview(plan))
        return head + "\n\n" + preview

    if result.wrote is not None:
        why = f"\n  Replaced because the gate {plan.detail}." if plan.detail else ""
        return (paint(f"✓ wrote {plan.path}", ok, on=color) +
                f"  ({plan.action} · pinned @{_short(plan.new_ref)})" + why + "\n"
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
    from stayawake.core.identity import push_failure_message
    from stayawake.core.identity.classify import PushFailure
    why = push_failure_message(PushFailure(res.push_reason or "unknown", res.push_detail or ""))
    where = f" (saved a patch at {res.patch_path})" if res.patch_path else ""
    return paint(f"⚠️  {slug}: {why}{where}", warn, on=color) + sign

#!/usr/bin/env python3
"""`saw guard` — detect and grade the Strix CI gate on a repo (#1229).

The gate is found by its ACTION REFERENCE — a `uses: Ndevu12/strix@<ref>` step — NOT by the workflow
filename or the job name. A consumer may name either anything (proven: ndevuspace-blog ships
`worm-scan.yml` with job `strix`), so only the action reference is reliable. From that step we derive
the job's status-check context, grade the pin (a commit SHA is best, an exact release tag is fine, a
moving alias is weak), and — best-effort, online — whether the pin is behind the latest Strix release.

`saw guard check` is READ-ONLY; `saw guard setup` (this module too) installs or updates the workflow
— but only ever by PROPOSING it: it writes into the working tree for review, or opens a rolling PR
via the shared `proposal` ladder. It never commits to the default branch and never runs the repo's
code.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from stayawake.lib.adapters import github_api
from stayawake.lib import auth
from stayawake.lib import git as gitutil
from stayawake.utils import textsafe
from stayawake.utils.config import load_yaml
from stayawake.utils.render import SEVERITY, paint
from stayawake.utils.streaming import Streamer, stream_enabled, status as spin_status
from stayawake.utils.terminal import supports_color
from stayawake.bots.security import proposal
from stayawake.bots.security import resolution
from stayawake.bots.security.targets import ScanOptions

# The canonical Strix action. Detection is scoped to it (a fork/mirror is out of scope for v1).
STRIX_OWNER, STRIX_REPO = "Ndevu12", "strix"
WORKFLOW_DIR = ".github/workflows"
WORM_GUARD_FILE = f"{WORKFLOW_DIR}/worm-guard.yml"   # created when no Strix gate exists yet
SETUP_BRANCH = "security/guard-setup"                # rolling branch for the `--pr` install/bump

# `Ndevu12/strix@<ref>` optionally followed by a trailing `# comment`; owner match is case-insensitive
# (GitHub owners are case-insensitive) but the ref is preserved verbatim.
_STRIX_USES = re.compile(r"^Ndevu12/strix@(?P<ref>\S+?)\s*(?:#.*)?$", re.IGNORECASE)
_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_EXACT_TAG = re.compile(r"^v\d+\.\d+\.\d+$")


@dataclass
class StrixRef:
    """One `uses: Ndevu12/strix@<ref>` occurrence and what it tells us."""
    workflow: str      # workflow file, repo-relative
    job: str           # the job's status-check context (its `name:`, else the job id)
    ref: str           # the `@<ref>` exactly as written
    pin: str           # "sha" (best) | "tag" (exact vX.Y.Z) | "floating" (@v0/@v1/@main/branch)


def classify_pin(ref: str) -> str:
    if _SHA.match(ref):
        return "sha"
    if _EXACT_TAG.match(ref):
        return "tag"
    return "floating"


def find_strix(workflows: dict[str, str]) -> StrixRef | None:
    """Return the first `uses: Ndevu12/strix@<ref>` across `{path: yaml_text}` (paths sorted), or
    None. Filename- and job-name-agnostic; malformed YAML files are skipped, not fatal."""
    for path in sorted(workflows):
        try:
            doc = yaml.safe_load(workflows[path])
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                m = _STRIX_USES.match(str(step.get("uses", "")).strip())
                if m:
                    ctx = job.get("name") or job_id
                    return StrixRef(workflow=path, job=str(ctx), ref=m.group("ref"),
                                    pin=classify_pin(m.group("ref")))
    return None


# A step that runs the saw scanner directly — `saw scan`/`saw audit` at a command boundary, or the
# `stayawakebot` package. This is the signal that a workflow (or a local composite action) IS a worm
# gate even when it doesn't use the packaged `Ndevu12/strix` action.
_RUNS_SAW = re.compile(r"(?:^|[\s;&|(])saw\s+(?:scan|audit)\b|\bstayawakebot\b", re.IGNORECASE)


def _runs_saw(text: str) -> bool:
    """Does `text` (a `run:` script or an action.yml) invoke the scanner? Comments are stripped first
    so a documentation line like `# to run locally: saw scan .` can't false-positive as a gate — a
    false 'guarded' would make `setup` wrongly skip installing one."""
    uncommented = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    return bool(_RUNS_SAW.search(uncommented))


@dataclass
class WormGate:
    """A worm gate found by ANY mechanism — so `check`/`setup` reason about "is this repo guarded?",
    not just "does it use Ndevu12/strix?". `mechanism` is "strix" (the packaged action — gradeable:
    `strix` carries the StrixRef), "local-action" (a `uses: ./…` composite action that runs saw), or
    "saw-run" (a `run:` step that invokes the scanner). Only "strix" can be pin/freshness-graded."""
    mechanism: str
    workflow: str
    detail: str
    strix: StrixRef | None = None


def find_worm_gate(workflows: dict[str, str], *, read_action=None) -> WormGate | None:
    """Detect a worm gate by any known mechanism. The packaged `Ndevu12/strix` action wins (it's the
    one we can grade); otherwise look for a step that runs the scanner directly, or a local composite
    action (`uses: ./…`) that does — resolved via the optional `read_action(uses) -> text|None`
    (filesystem locally, the API for a remote repo; when absent, local-action gates aren't resolved)."""
    ref = find_strix(workflows)
    if ref is not None:
        return WormGate("strix", ref.workflow, f"Ndevu12/strix@{ref.ref}", strix=ref)
    for path in sorted(workflows):
        try:
            doc = yaml.safe_load(workflows[path])
        except yaml.YAMLError:
            continue
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not isinstance(jobs, dict):
            continue
        for job in jobs.values():
            steps = job.get("steps") if isinstance(job, dict) else None
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run = step.get("run")
                if isinstance(run, str) and _runs_saw(run):
                    return WormGate("saw-run", path, "a step runs the saw scanner")
                uses = str(step.get("uses", "")).strip()
                if uses.startswith("./") and read_action is not None:
                    text = read_action(uses)
                    if isinstance(text, str) and _runs_saw(text):
                        return WormGate("local-action", path, uses)
    return None


def _local_action_reader(repo: Path):
    """Resolve a `uses: ./path` local composite action to its action.yml text (or None)."""
    def read(uses: str) -> str | None:
        rel = uses[2:].strip("/")                      # "./.github/actions/x" → ".github/actions/x"
        for fn in ("action.yml", "action.yaml"):
            try:
                return (repo / rel / fn).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return None
    return read


def _remote_action_reader(owner: str, name: str, token: str | None):
    def read(uses: str) -> str | None:
        rel = uses[2:].strip("/")
        for fn in ("action.yml", "action.yaml"):
            text = github_api.get_file_text(owner, name, f"{rel}/{fn}", token)
            if text is not None:
                return text
        return None
    return read


@dataclass
class Freshness:
    state: str                 # "fresh" | "behind" | "floating" | "unknown"
    latest_tag: str | None = None
    detail: str = ""


@dataclass
class LatestStrix:
    """The latest published Strix release, resolved ONCE. A sweep precomputes this and passes it to
    each repo's `freshness` so the releases API isn't re-hit per repo."""
    tag: str | None = None
    sha: str | None = None     # commit SHA of tags/<tag>


def latest_strix(token: str | None = None) -> LatestStrix:
    """Resolve the latest Strix release (tag + its commit SHA) once — for a `check` sweep."""
    rel = github_api.latest_release(STRIX_OWNER, STRIX_REPO, token)
    tag = rel.get("tag_name") if isinstance(rel, dict) else None
    if not tag:
        return LatestStrix()
    return LatestStrix(tag, github_api.ref_commit_sha(STRIX_OWNER, STRIX_REPO, f"tags/{tag}", token))


def freshness(ref: StrixRef, token: str | None = None, *, latest: LatestStrix | None = None) -> Freshness:
    """Best-effort: is `ref` behind the latest published Strix release? Network; degrades to
    'unknown' (never raises, never guesses) when the releases API can't be reached. Pass a
    precomputed `latest` (from `latest_strix`) to grade without a network call — used by the sweep."""
    if latest is None:
        rel = github_api.latest_release(STRIX_OWNER, STRIX_REPO, token)
        tag = rel.get("tag_name") if isinstance(rel, dict) else None
        latest = LatestStrix(tag)               # sha fetched lazily below, only if `ref` is SHA-pinned
    if not latest.tag:
        return Freshness("unknown", detail="couldn't reach the Strix releases API")
    if ref.pin == "floating":
        return Freshness("floating", latest.tag,
                         "a moving alias — tracks its line automatically; pin a SHA for reproducibility")
    if ref.pin == "tag":
        ok = ref.ref == latest.tag
        return Freshness("fresh" if ok else "behind", latest.tag,
                         "" if ok else f"pinned {ref.ref}, latest release is {latest.tag}")
    latest_sha = latest.sha if latest.sha is not None else github_api.ref_commit_sha(
        STRIX_OWNER, STRIX_REPO, f"tags/{latest.tag}", token)
    if not latest_sha:
        return Freshness("unknown", latest.tag, "couldn't resolve the latest release commit")
    ok = ref.ref.lower() == latest_sha.lower()
    return Freshness("fresh" if ok else "behind", latest.tag,
                     "" if ok else f"pinned {ref.ref[:12]}…, {latest.tag} is {latest_sha[:12]}…")


@dataclass
class GuardStatus:
    present: bool
    ref: StrixRef | None = None
    fresh: Freshness | None = None
    required: bool | None = None       # None = not checked (local/no token); else branch-protection result
    branch: str | None = None          # set only for a remote check → also signals "remote" to render()
    error: str | None = None           # e.g. couldn't read a remote repo
    # A worm gate present by a NON-Strix mechanism (a local composite action / a direct `saw` step):
    # `present` is True but `ref` is None — the repo IS guarded, just not by the gradeable Strix action.
    mechanism: str | None = None       # "local-action" | "saw-run" when ref is None; None otherwise
    gate_file: str | None = None       # the workflow file that carries the non-Strix gate

    @property
    def healthy(self) -> bool:
        """The gate passes verification: present, SHA-pinned, not stale, and (where we could check)
        required. Only a Strix gate is *verifiable* — a non-Strix worm gate is protective but its pin
        /freshness/required-status can't be tracked, so it is not 'healthy' for `-f/--fail` (the render
        says so plainly). A guard-domain policy, not the CLI's."""
        if not self.present or self.ref is None or self.ref.pin != "sha":
            return False
        if self.fresh is not None and self.fresh.state == "behind":
            return False
        return self.required is not False


def _local_workflows(repo: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        entries = sorted((repo / WORKFLOW_DIR).iterdir())
    except OSError:
        return out
    for f in entries:
        if f.suffix in (".yml", ".yaml"):
            try:
                out[f"{WORKFLOW_DIR}/{f.name}"] = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return out


def _remote_workflows(owner: str, repo: str, token: str | None) -> dict[str, str] | None:
    entries = github_api.list_dir(owner, repo, WORKFLOW_DIR, token)
    if entries is None:
        return None                    # dir missing / repo unreadable — distinct from "present, empty"
    out: dict[str, str] = {}
    for e in entries:
        if (isinstance(e, dict) and e.get("type") == "file"
                and str(e.get("name", "")).endswith((".yml", ".yaml"))):
            text = github_api.get_file_text(owner, repo, str(e.get("path")), token)
            if text is not None:
                out[str(e.get("path"))] = text
    return out


def _context_required(prot: dict | None, context: str) -> bool:
    rsc = (prot or {}).get("required_status_checks") or {}
    contexts = set(rsc.get("contexts") or [])
    contexts |= {c.get("context") for c in (rsc.get("checks") or []) if isinstance(c, dict)}
    return context in contexts


def remote_gate(slug: str, token: str | None) -> StrixRef | None:
    """The Strix gate declared in a remote repo's (`owner/name`) workflows, or None. Read-only —
    a thin public seam so other commands (e.g. `saw audit`) can ask "does this repo run Strix, and
    under what status-check context?" without re-implementing the detection."""
    if not slug or "/" not in slug:
        return None
    owner, _, name = slug.partition("/")
    return find_strix(_remote_workflows(owner, name, token) or {})


def check(*, repo: str | Path | None = None, slug: str | None = None, branch: str = "main",
          token: str | None = None, offline: bool = False,
          latest: "LatestStrix | None" = None) -> GuardStatus:
    """Inspect one repo's Strix gate. Local (a working-tree `repo` path) or remote (`slug`,
    `owner/name`, via the API). `offline` skips the freshness network call; a sweep passes a
    precomputed `latest` so freshness is graded without a per-repo release lookup."""
    if slug:
        owner, _, name = slug.partition("/")
        workflows = _remote_workflows(owner, name, token)
        if workflows is None:
            return GuardStatus(present=False, error=f"could not read {slug} (missing/private/no token?)")
        reader = _remote_action_reader(owner, name, token)
    else:
        workflows = _local_workflows(Path(repo or "."))
        reader = _local_action_reader(Path(repo or "."))

    gate = find_worm_gate(workflows, read_action=reader)
    if gate is None:
        return GuardStatus(present=False)
    if gate.mechanism != "strix":                      # guarded, but not by the gradeable Strix action
        return GuardStatus(present=True, mechanism=gate.mechanism, gate_file=gate.workflow,
                           branch=branch if slug else None)

    ref = gate.strix
    fresh = None if offline else freshness(ref, token, latest=latest)
    required: bool | None = None
    if slug and token:
        owner, _, name = slug.partition("/")
        prot = github_api.get_branch_protection(owner, name, branch, token)
        required = _context_required(prot, ref.job)
    return GuardStatus(present=True, ref=ref, fresh=fresh, required=required,
                       branch=branch if slug else None)


def render(status: GuardStatus, *, color: bool = False) -> str:
    """Human-facing report for a GuardStatus. Colour is gated by the caller (core.terminal). The
    branch-protection line shows only for a remote check (signalled by `status.branch`)."""
    ok, warn, dim = SEVERITY["ok"], SEVERITY["warning"], SEVERITY["info"]
    remote = status.branch is not None
    lines: list[str] = []

    if not status.present:
        if status.error:
            return paint(f"⚠️  {status.error}", warn, on=color)
        lines.append(paint("✗ No worm gate found", warn, on=color) +
                     " — no workflow runs a worm scan (`Ndevu12/strix`, a local scan action, or `saw`).")
        lines.append(paint("     Run `saw guard setup` to add one.", dim, on=color))
        return "\n".join(lines)

    if status.ref is None:                             # guarded by a NON-Strix mechanism
        how = {"local-action": "a local scan action", "saw-run": "a direct `saw` step"}.get(
            status.mechanism, status.mechanism or "another mechanism")
        lines.append(paint("✓ Worm gate found", ok, on=color) +
                     f" — {status.gate_file} runs a worm scan via {how}.")
        lines.append("  " + paint("• not the pinned Strix action", dim, on=color) +
                     " — its pin, freshness, and required-status can't be tracked. `saw guard setup` "
                     "can adopt the SHA-pinned `Ndevu12/strix` gate.")
        return "\n".join(lines)

    r = status.ref
    lines.append(paint("✓ Strix gate found", ok, on=color) + f" — {r.workflow} (job “{r.job}”)")

    if r.pin == "sha":
        lines.append("  " + paint("✓ pinned to a commit SHA", ok, on=color) + f"  (@{r.ref[:12]}…)")
    elif r.pin == "tag":
        lines.append("  " + paint("• pinned to a release tag", dim, on=color) +
                     f"  (@{r.ref}) — a SHA is immutable; `saw guard setup` can rewrite it")
    else:
        lines.append("  " + paint("⚠ floating ref", warn, on=color) +
                     f"  (@{r.ref}) — the action's code can change under you; pin a SHA")

    if status.fresh is not None:
        f = status.fresh
        if f.state == "fresh":
            lines.append("  " + paint("✓ up to date", ok, on=color) + f"  (latest {f.latest_tag})")
        elif f.state == "behind":
            lines.append("  " + paint("⚠ behind latest", warn, on=color) + f"  — {f.detail}")
        elif f.state == "floating":
            lines.append("  " + paint("• moving alias", dim, on=color) + f"  — {f.detail}")
        else:
            lines.append("  " + paint("• freshness unknown", dim, on=color) + f"  — {f.detail}")

    if remote:
        if status.required is True:
            lines.append("  " + paint("✓ required", ok, on=color) +
                         f"  — branch protection on {status.branch} requires “{r.job}”")
        elif status.required is False:
            lines.append("  " + paint("⚠ not a required check", warn, on=color) +
                         f"  — {status.branch} protection does NOT require “{r.job}”; an infected PR can still merge")
        # status.required is None → no token, couldn't check → stay quiet
    return "\n".join(lines)


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
    slug = gitutil.origin_slug(repo)
    if not slug:
        return SetupResult(plan=plan, error="no GitHub origin — cannot open a PR (drop --pr to write "
                                            "the file locally, or add a remote)")
    baseref = f"origin/{base}" if gitutil.ref_exists(repo, f"origin/{base}") else base
    gitutil.fetch(repo, "origin", base)
    wt = Path(tempfile.mkdtemp(prefix="sab-guard-"))
    if not gitutil.add_worktree(repo, wt, SETUP_BRANCH, baseref):
        gitutil.remove_worktree(repo, wt)
        return SetupResult(plan=plan, slug=slug, error="could not create a worktree for the PR")
    try:
        dest = wt / plan.path
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
          spin: bool = False) -> SetupResult:
    """Install or update the Strix gate on a LOCAL repo. Default: write the change into the working
    tree for the operator to review + commit + PR. `--pr`: open a rolling PR via the ladder. Either
    way the default branch is only ever proposed to, never pushed. Fails closed if the pin can't be
    resolved (offline → pass `ref`)."""
    repo = Path(repo or ".")
    pin = resolve_pin(token, ref)
    if pin is None:
        return SetupResult(error="couldn't resolve the latest Strix release "
                                 "(offline? pass --ref <sha|tag> to pin explicitly)")
    default_branch = branch or gitutil.default_branch(repo)
    plan = plan_setup(_local_workflows(repo), default_branch, pin,
                      read_action=_local_action_reader(repo))
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
    # floor: no push access — the change is saved as a patch (issue floor not used for setup)
    where = f" (saved a patch at {res.patch_path})" if res.patch_path else ""
    return paint(f"⚠️  {slug}: no write access — could not open the guard PR{where}", warn, on=color) + sign


# ── sweep: resolve targets (local repos / remote slugs) and check each — like saw scan/fix ────────
# `saw guard check` takes positional TARGETS (local paths, or owner/repo slugs under --remote),
# discovers local git repos, or resolves remote repos via the shared #1075 ladder (resolution.py).
# Streams per repo; one repo's failure never aborts the run.

def _guard_config(config_path: str | None):
    """Load the config, tolerating a missing default (like `saw fix`). An explicitly-given --config
    that is missing is an error (returns None → the caller exits 2)."""
    if config_path is None:
        p = Path(resolution.DEFAULT_CONFIG)
        return load_yaml(p) if p.exists() else {}
    if not Path(config_path).is_file():
        print(f"error: config '{config_path}' not found. Pass --config <path>, or omit it to act on "
              "the current repository.", file=sys.stderr)
        return None
    return load_yaml(config_path)


def _local_patterns(cfg: dict, paths) -> list[str]:
    cfg_local = (cfg.get("targets", {}) or {}).get("local", []) or []
    return list(paths) if paths else (list(cfg_local) or [str(resolution.enclosing_repo_root())])


def _disp(repo: Path) -> str:
    return str(repo).replace(os.path.expanduser("~"), "~")


def _indent(text: str) -> str:
    return "\n".join("    " + ln for ln in text.splitlines())


def _safe_check(**kw) -> GuardStatus:
    """One repo's error must never abort the sweep — a failed check becomes an error status."""
    try:
        return check(**kw)
    except Exception as exc:  # noqa: BLE001 — isolate one repo, keep the sweep going
        return GuardStatus(present=False, error=f"check failed — {exc}")


def check_targets(*, paths=None, slugs=None, users=None, orgs=None, remote: bool = False,
                  config_path: str | None = None, branch: str = "main",
                  fail: bool = False, no_stream: bool = False) -> int:
    """`saw guard check` across many repos. LOCAL by default (discover git repos under the given
    paths / configured `targets.local` / the enclosing repo); `remote=True` (or naming users/orgs)
    resolves GitHub repos via the #1075 ladder and checks each over the API. The latest Strix release
    is resolved ONCE and reused for every repo's freshness. Streams per repo. Returns 2 on a missing
    --config, 1 when `fail` and any gate isn't a healthy pinned Strix gate, else 0."""
    cfg = _guard_config(config_path)
    if cfg is None:
        return 2
    remote = remote or bool(users) or bool(orgs)
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream))
    color = supports_color(sys.stdout)
    statuses: list[GuardStatus] = []

    if remote:
        bad = resolution.invalid_slugs(slugs)
        if bad:
            prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
            return 2
        resolved, token, _src = resolution.resolve_remote(cfg, ScanOptions(),
                                                          users=users, orgs=orgs, slugs=slugs)
        if not resolved:
            prog.line(resolution.REMOTE_EMPTY_HINT)
            return 0
        latest = latest_strix(token)
        prog.line(f"Checking {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'}…")
        for i, slug in enumerate(resolved, 1):
            prog.line(f"  [{i}/{len(resolved)}] {slug}")
            st = _safe_check(slug=slug, branch=branch, token=token, latest=latest)
            prog.line(_indent(render(st, color=color)))
            statuses.append(st)
    else:
        repos = resolution.discover_local_repos(_local_patterns(cfg, paths), ScanOptions())
        if not repos:
            prog.line("No local git repositories found.")
            return 0
        token, _ = auth.resolve_token()      # optional — eases freshness rate limits (public repo works without)
        latest = latest_strix(token)
        prog.line(f"Checking {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
        for i, repo in enumerate(repos, 1):
            prog.line(f"  [{i}/{len(repos)}] {_disp(repo)}")
            st = _safe_check(repo=repo, token=token, latest=latest)
            prog.line(_indent(render(st, color=color)))
            statuses.append(st)

    guarded = sum(1 for s in statuses if s.present)
    verified = sum(1 for s in statuses if s.healthy)
    unhealthy = [s for s in statuses if not s.healthy]
    n = len(statuses)
    prog.line(f"\nChecked {n} repositor{'y' if n == 1 else 'ies'}: {guarded} with a worm gate, "
              f"{verified} a verified SHA-pinned Strix gate.")
    return 1 if (fail and unhealthy) else 0


def _safe_setup(repo, **kw) -> SetupResult:
    """One repo's error must never abort the setup sweep — a failure becomes an error result."""
    try:
        return setup(repo, **kw)
    except Exception as exc:  # noqa: BLE001 — isolate one repo, keep the sweep going
        return SetupResult(error=f"setup failed — {exc}")


def setup_targets(*, paths=None, slugs=None, users=None, orgs=None, remote: bool = False,
                  config_path: str | None = None, ref: str | None = None, dry_run: bool = False,
                  pr: bool = False, branch: str | None = None, no_stream: bool = False) -> int:
    """`saw guard setup` across many repos, like `saw fix`. LOCAL by default (discover git repos;
    write/prepare the gate into each working tree, or `--pr` to open a PR each); `remote=True`
    resolves GitHub repos via the #1075 ladder, clones each, and opens a PR (a remote repo has no
    working tree, so `--pr` is implied). Never pushes to a default branch. Streams per repo; one
    repo's error never aborts the run. Returns 2 on a missing --config, 1 if any repo errored, else 0."""
    cfg = _guard_config(config_path)
    if cfg is None:
        return 2
    remote = remote or bool(users) or bool(orgs)
    prog = Streamer(enabled=stream_enabled(sys.stdout, force_off=no_stream))
    color = supports_color(sys.stdout)
    results: list[SetupResult] = []

    if remote:
        bad = resolution.invalid_slugs(slugs)
        if bad:
            prog.line(f"error: --remote targets must be owner/repo slugs; got {bad}")
            return 2
        resolved, token, _src = resolution.resolve_remote(cfg, ScanOptions(),
                                                          users=users, orgs=orgs, slugs=slugs)
        if not token:
            prog.line(auth.no_credential_hint("cloning and opening guard PRs") + "\n")
            return 2
        if not resolved:
            prog.line(resolution.REMOTE_EMPTY_HINT)
            return 0
        prog.line(f"Setting up {len(resolved)} GitHub repositor{'y' if len(resolved) == 1 else 'ies'}…")
        for i, slug in enumerate(resolved, 1):
            prog.line(f"  [{i}/{len(resolved)}] {slug}")
            with spin_status(f"cloning {slug}…", enabled=prog.enabled), \
                    resolution.cloned_repo(slug, token) as clone:
                if clone is None:
                    res = SetupResult(error=f"{slug}: clone failed (check token access)")
                else:                                    # a remote repo has no working tree → always PR
                    res = _safe_setup(clone, token=token, ref=ref, dry_run=dry_run, pr=True,
                                      branch=branch, spin=prog.enabled)
            prog.line(_indent(render_setup(res, color=color)))
            results.append(res)
    else:
        token, _ = auth.resolve_token() if (pr or not ref) else (None, None)
        repos = resolution.discover_local_repos(_local_patterns(cfg, paths), ScanOptions())
        if not repos:
            prog.line("No local git repositories found.")
            return 0
        prog.line(f"Setting up {len(repos)} local repositor{'y' if len(repos) == 1 else 'ies'}…")
        for i, repo in enumerate(repos, 1):
            prog.line(f"  [{i}/{len(repos)}] {_disp(repo)}")
            res = _safe_setup(repo, token=token, ref=ref, dry_run=dry_run, pr=pr,
                              branch=branch, spin=prog.enabled)
            prog.line(_indent(render_setup(res, color=color)))
            results.append(res)

    errored = [r for r in results if r.error]
    n = len(results)
    prog.line(f"\nSet up {n} repositor{'y' if n == 1 else 'ies'}"
              + (f"; {len(errored)} errored." if errored else "."))
    return 1 if errored else 0

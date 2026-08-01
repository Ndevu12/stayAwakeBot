#!/usr/bin/env python3
"""`saw guard` detection + grading — find the Strix CI gate by its ACTION REFERENCE
(`uses: Ndevu12/strix@<ref>`, not filename/job), derive its status-check context, grade the pin, and
best-effort check freshness against the latest Strix release. READ-ONLY (`saw guard check`)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from stayawake.lib.adapters import github_api
from stayawake.lib import auth
from stayawake.lib import git as gitutil
from stayawake.utils.render import SEVERITY, paint
from stayawake.bots.security.guard.constants import (
    STRIX_OWNER, STRIX_REPO, WORKFLOW_DIR, WORM_GUARD_FILE)

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


def _ref_workflows(repo: Path, ref: str) -> dict[str, str]:
    """Workflow files as they exist ON a git ref (e.g. `origin/main`) — so `--pr` plans against the
    PR TARGET (the default branch), not a possibly-untracked working-tree file (#1243 follow-up)."""
    out: dict[str, str] = {}
    for path in gitutil.list_tree(repo, ref, WORKFLOW_DIR):
        if path.endswith((".yml", ".yaml")):
            text = gitutil.file_at(repo, ref, path)
            if text:
                out[path] = text
    return out


def _ref_action_reader(repo: Path, ref: str):
    """Resolve a `uses: ./path` local composite action to its action.yml AS IT EXISTS ON `ref`."""
    def read(uses: str) -> str | None:
        rel = uses[2:].strip("/")
        for fn in ("action.yml", "action.yaml"):
            text = gitutil.file_at(repo, ref, f"{rel}/{fn}")
            if text:
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
    error: str | None = None           # a REAL remote read failure (auth/scope/rate/network) — never a 404
    # A worm gate present by a NON-Strix mechanism (a local composite action / a direct `saw` step):
    # `present` is True but `ref` is None — the repo IS guarded, just not by the gradeable Strix action.
    mechanism: str | None = None       # "local-action" | "saw-run" when ref is None; None otherwise
    gate_file: str | None = None       # the workflow file that carries the non-Strix gate
    no_ci: bool = False                # remote repo has no `.github/workflows/` (404) — the NORMAL
                                       # "nothing to gate" state, NOT a read failure (#1243)

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


@dataclass
class RemoteRead:
    """Result of reading a remote repo's `.github/workflows/` (#1243). `cause` distinguishes the
    NORMAL 'no CI' (a 404 — the repo simply has no workflows dir) from a REAL read failure
    (auth/scope/rate/network), which the old bare-`None` conflated into a token-blaming error."""
    workflows: dict[str, str]          # the workflow files (empty when no CI / a real failure)
    cause: str | None = None           # None = read OK; "not_found" = no CI (calm); else a real failure
    retry_after: int | None = None     # seconds until rate-limit reset (for cause="rate_limited")


def _remote_workflows(owner: str, repo: str, token: str | None) -> RemoteRead:
    r = github_api.read_dir(owner, repo, WORKFLOW_DIR, token)
    if r.cause == "not_found":
        return RemoteRead({}, cause="not_found")            # no workflows dir → no CI, not an error
    if r.cause is not None:
        return RemoteRead({}, cause=r.cause, retry_after=r.retry_after)   # real read failure
    out: dict[str, str] = {}
    for e in r.value:
        if (isinstance(e, dict) and e.get("type") == "file"
                and str(e.get("name", "")).endswith((".yml", ".yaml"))):
            fr = github_api.read_file(owner, repo, str(e.get("path")), token)
            if fr.cause is None:
                out[str(e.get("path"))] = fr.value
    return RemoteRead(out)


def _read_error(slug: str, cause: str, retry_after: int | None = None) -> str:
    """Turn a real remote-read failure cause into an accurate, actionable message — never blaming the
    token for what is usually just 'this repo has no CI' (#1243). `not_found` is handled upstream as
    the calm no-CI state and never reaches here."""
    if cause == "unauthorized":
        return (f"not authenticated to read {slug} — run `gh auth login` or set GH_SECURITY_TOKEN")
    if cause == "rate_limited":
        when = f" — retry in {retry_after}s" if retry_after is not None else ""
        return f"GitHub rate limit hit reading {slug}{when}"
    if cause == "forbidden":
        return f"can't read {slug} — is it private, or does the token lack repo scope?"
    if cause == "network":
        return f"network error reading {slug}"
    return f"couldn't read {slug} ({cause})"


def _context_required(prot: dict | None, context: str) -> bool:
    rsc = (prot or {}).get("required_status_checks") or {}
    contexts = set(rsc.get("contexts") or [])
    contexts |= {c.get("context") for c in (rsc.get("checks") or []) if isinstance(c, dict)}
    return context in contexts


@dataclass
class GateProbe:
    """`probe_remote_gate` result: the Strix gate (or None if genuinely absent) AND whether the
    workflows could be read. `cause` is set ONLY on a real read failure (auth/scope/rate/network) —
    so a caller (e.g. `saw audit`) can tell 'this repo has no gate' apart from 'I couldn't read it',
    instead of the old `or {}` that laundered a read failure into a false 'no gate' (#1243)."""
    ref: StrixRef | None = None
    cause: str | None = None           # None on read OK / 404-no-CI; else the real failure cause


def probe_remote_gate(slug: str, token: str | None) -> GateProbe:
    """Read-only public seam: does a remote repo run the Strix gate, under what status-check context,
    and could we even read it? `saw audit` uses this so a read failure doesn't masquerade as 'no gate'."""
    if not slug or "/" not in slug:
        return GateProbe()
    owner, _, name = slug.partition("/")
    rr = _remote_workflows(owner, name, token)
    if rr.cause is not None and rr.cause != "not_found":
        return GateProbe(cause=rr.cause)                    # real read failure — NOT a "no gate" answer
    return GateProbe(ref=find_strix(rr.workflows))


def remote_gate(slug: str, token: str | None) -> StrixRef | None:
    """The Strix gate in a remote repo's workflows, or None. Thin value wrapper over
    `probe_remote_gate` (a read failure → None, same as before) for callers that don't need the cause."""
    return probe_remote_gate(slug, token).ref


def check(*, repo: str | Path | None = None, slug: str | None = None, branch: str = "main",
          token: str | None = None, offline: bool = False,
          latest: "LatestStrix | None" = None) -> GuardStatus:
    """Inspect one repo's Strix gate. Local (a working-tree `repo` path) or remote (`slug`,
    `owner/name`, via the API). `offline` skips the freshness network call; a sweep passes a
    precomputed `latest` so freshness is graded without a per-repo release lookup."""
    if slug:
        owner, _, name = slug.partition("/")
        rr = _remote_workflows(owner, name, token)
        if rr.cause == "not_found":
            return GuardStatus(present=False, no_ci=True, branch=branch)   # no CI — calm, not an error
        if rr.cause is not None:
            return GuardStatus(present=False, branch=branch,
                               error=_read_error(slug, rr.cause, rr.retry_after))
        workflows = rr.workflows
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
        if status.no_ci:                                   # 404 on .github/workflows — the normal state
            return paint("• no CI workflows", dim, on=color) + " — nothing to gate here."
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



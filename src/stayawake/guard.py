#!/usr/bin/env python3
"""`saw guard` — detect and grade the Strix CI gate on a repo (#1229).

The gate is found by its ACTION REFERENCE — a `uses: Ndevu12/strix@<ref>` step — NOT by the workflow
filename or the job name. A consumer may name either anything (proven: ndevuspace-blog ships
`worm-scan.yml` with job `strix`), so only the action reference is reliable. From that step we derive
the job's status-check context, grade the pin (a commit SHA is best, an exact release tag is fine, a
moving alias is weak), and — best-effort, online — whether the pin is behind the latest Strix release.

This module is READ-ONLY (it powers `saw guard check`); `saw guard setup` (writing the workflow)
builds on the same detection. It never runs the scanned repo's code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from stayawake.core.adapters import github_api

# The canonical Strix action. Detection is scoped to it (a fork/mirror is out of scope for v1).
STRIX_OWNER, STRIX_REPO = "Ndevu12", "strix"
WORKFLOW_DIR = ".github/workflows"

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


@dataclass
class Freshness:
    state: str                 # "fresh" | "behind" | "floating" | "unknown"
    latest_tag: str | None = None
    detail: str = ""


def freshness(ref: StrixRef, token: str | None = None) -> Freshness:
    """Best-effort: is `ref` behind the latest published Strix release? Network; degrades to
    'unknown' (never raises, never guesses) when the releases API can't be reached."""
    rel = github_api.latest_release(STRIX_OWNER, STRIX_REPO, token)
    latest_tag = rel.get("tag_name") if isinstance(rel, dict) else None
    if not latest_tag:
        return Freshness("unknown", detail="couldn't reach the Strix releases API")
    if ref.pin == "floating":
        return Freshness("floating", latest_tag,
                         "a moving alias — tracks its line automatically; pin a SHA for reproducibility")
    if ref.pin == "tag":
        ok = ref.ref == latest_tag
        return Freshness("fresh" if ok else "behind", latest_tag,
                         "" if ok else f"pinned {ref.ref}, latest release is {latest_tag}")
    latest_sha = github_api.ref_commit_sha(STRIX_OWNER, STRIX_REPO, f"tags/{latest_tag}", token)
    if not latest_sha:
        return Freshness("unknown", latest_tag, "couldn't resolve the latest release commit")
    ok = ref.ref.lower() == latest_sha.lower()
    return Freshness("fresh" if ok else "behind", latest_tag,
                     "" if ok else f"pinned {ref.ref[:12]}…, {latest_tag} is {latest_sha[:12]}…")


@dataclass
class GuardStatus:
    present: bool
    ref: StrixRef | None = None
    fresh: Freshness | None = None
    required: bool | None = None       # None = not checked (local/no token); else branch-protection result
    branch: str | None = None
    error: str | None = None           # e.g. couldn't read a remote repo


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


def check(*, repo: str | Path | None = None, slug: str | None = None, branch: str = "main",
          token: str | None = None, offline: bool = False) -> GuardStatus:
    """Inspect one repo's Strix gate. Local (a working-tree `repo` path) or remote (`slug`,
    `owner/name`, via the API). `offline` skips the freshness network call."""
    if slug:
        owner, _, name = slug.partition("/")
        workflows = _remote_workflows(owner, name, token)
        if workflows is None:
            return GuardStatus(present=False, error=f"could not read {slug} (missing/private/no token?)")
    else:
        workflows = _local_workflows(Path(repo or "."))

    ref = find_strix(workflows)
    if ref is None:
        return GuardStatus(present=False)

    fresh = None if offline else freshness(ref, token)
    required: bool | None = None
    if slug and token:
        owner, _, name = slug.partition("/")
        prot = github_api.get_branch_protection(owner, name, branch, token)
        required = _context_required(prot, ref.job)
    return GuardStatus(present=True, ref=ref, fresh=fresh, required=required,
                       branch=branch if slug else None)

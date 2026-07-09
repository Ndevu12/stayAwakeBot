#!/usr/bin/env python3
"""GitHub Actions workflow matcher — planted / impersonated CI persistence (#1091).

`saw` already walks `.github/workflows/*.yml` (they are not pruned and `.yml`/`.yaml`
are source extensions), but no matcher inspected them. This YAML-aware structural matcher
closes the Shai-Hulud 2.0 / Mini "plant-a-workflow" CI-persistence + camouflage blind spot:

  * `workflow-injection-run` — an injection-prone trigger (pull_request_target / issue_comment /
    issues / discussion / discussion_comment / workflow_run) reaching a `run:` step that
    interpolates an UNTRUSTED `${{ github.event.* }}` field (the "open a Discussion → payload
    fires" weakness). Runs with write-scoped secrets, so untrusted text in `run:` = script
    injection / secret theft.
  * `workflow-dependabot-impersonation` — a workflow masquerading as Dependabot (name/filename)
    that also does something Dependabot never does: self-hosted `runs-on`, a remote-fetch-into-
    interpreter `run:`, or a dangerous injection expression.

Both are `confidence: heuristic` → SUSPICIOUS (a repo can legitimately own such a workflow), so
they inform the user without a false "infected" alarm. Kept separate from the `.vscode`-scoped
`structural-json` matcher (whose gate must not be relaxed) and parses YAML, not JSON.

Detection dispatches by the signature `kind` (mirroring StructuralJsonMatcher); the signature
carries the metadata (id/category/severity/confidence/remediation) and this module the logic.
"""
from __future__ import annotations

import re

import yaml

from stayawake.bots.security.models import Finding, Severity
from stayawake.bots.security.matchers.base import Matcher, REMOTE_FETCH_INTO_INTERPRETER

# Triggers that run with the BASE repo's write-scoped token while carrying attacker-controllable
# event payloads — the injection-prone set (GitHub's own "script injection" guidance).
DANGEROUS_TRIGGERS = frozenset({
    "pull_request_target", "issue_comment", "issues",
    "discussion", "discussion_comment", "workflow_run",
})

# An untrusted `${{ github.event.<obj>...<leaf> }}` (or `github.head_ref`) interpolation. The
# object must be an attacker-writable event field and the leaf a free-text value (title/body/
# message/ref/...). `[^}]*` between them stays inside ONE interpolation (never crosses `}`), so
# it spans `.head.ref` / `commits[0].message` yet not a neighbouring expression. Numeric/id leaves
# (`.number`, `.id`, `.sha`) are deliberately excluded — they are not injectable → fewer FPs.
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{[^}]*\bgithub\.(?:"
    r"head_ref"
    r"|event\.(?:issue|pull_request|comment|discussion|review|review_comment|"
    r"head_commit|commits|pages|workflow_run)\b[^}]*"
    r"\.(?:title|body|message|ref|label|name|email|page_name|default_branch|login)"
    r")[^}]*\}\}",
    re.IGNORECASE | re.DOTALL,
)

# A remote fetch piped straight into an interpreter — the shared (bounded) shape from base.py, used
# by the npm-lifecycle and structural-json matchers too, so it can't drift.
REMOTE_FETCH = REMOTE_FETCH_INTO_INTERPRETER
SELF_HOSTED = re.compile(r"\bself-hosted\b", re.IGNORECASE)
DEPENDABOT = re.compile(r"dependabot", re.IGNORECASE)


class WorkflowYamlMatcher(Matcher):
    handles = "workflow-yaml"

    def scan(self, target, signatures):
        by_kind = {s["kind"]: s for s in signatures if s.get("kind")}
        findings: list[Finding] = []
        for rel in target.iter_files():
            if not self._is_workflow(rel):
                continue
            try:
                data = yaml.safe_load(target.read_text(rel) or "")
            except yaml.YAMLError:
                continue                         # malformed workflow — skip, never crash the scan
            if isinstance(data, dict):
                findings.extend(self._inspect(rel, data, by_kind))
        return findings

    @staticmethod
    def _is_workflow(rel: str) -> bool:
        return "/.github/workflows/" in f"/{rel}" and rel.lower().endswith((".yml", ".yaml"))

    # ── YAML shape helpers (every field is attacker-shaped, so type-guard everything) ──
    @staticmethod
    def _triggers(data: dict) -> set[str]:
        # PyYAML parses the bareword `on:` key as the boolean True (YAML 1.1), so real
        # workflows land under data[True]; only a quoted "on" stays a string. Read both.
        raw = data.get("on")
        if raw is None:
            raw = data.get(True)
        if isinstance(raw, str):
            return {raw}
        if isinstance(raw, (list, dict)):
            return {t for t in raw if isinstance(t, str)}
        return set()

    @staticmethod
    def _jobs(data: dict):
        jobs = data.get("jobs")
        return [j for j in jobs.values() if isinstance(j, dict)] if isinstance(jobs, dict) else []

    def _run_steps(self, data: dict) -> list[str]:
        out = []
        for job in self._jobs(data):
            steps = job.get("steps")
            if isinstance(steps, list):
                out += [s["run"] for s in steps if isinstance(s, dict) and isinstance(s.get("run"), str)]
        return out

    def _runs_on_labels(self, data: dict) -> list[str]:
        out = []
        for job in self._jobs(data):
            ro = job.get("runs-on")
            if isinstance(ro, str):
                out.append(ro)
            elif isinstance(ro, list):
                out += [x for x in ro if isinstance(x, str)]
        return out

    # ── Detection ────────────────────────────────────────────────────────────────────
    def _inspect(self, rel, data, by_kind) -> list[Finding]:
        out = []
        runs = self._run_steps(data)

        sig = by_kind.get("dangerous-trigger-run-injection")
        if sig:
            triggers = self._triggers(data) & DANGEROUS_TRIGGERS
            hit = next((r for r in runs if UNTRUSTED_EXPR.search(r)), None)
            if triggers and hit is not None:
                expr = UNTRUSTED_EXPR.search(hit).group(0)
                out.append(self._emit(sig, rel,
                                      f"trigger {sorted(triggers)} → run interpolates {expr[:70]}"))

        sig = by_kind.get("dependabot-impersonation")
        if sig and self._is_dependabot_named(rel, data):
            labels = self._runs_on_labels(data)
            reason = None
            if any(SELF_HOSTED.search(l) for l in labels):
                reason = "self-hosted runs-on"
            elif any(REMOTE_FETCH.search(r) for r in runs):
                reason = "remote-fetch|interpreter in run"
            elif any(UNTRUSTED_EXPR.search(r) for r in runs):
                reason = "untrusted github.event.* in run"
            if reason:
                out.append(self._emit(sig, rel, f"Dependabot-named workflow with {reason}"))
        return out

    @staticmethod
    def _is_dependabot_named(rel: str, data: dict) -> bool:
        base = rel.rsplit("/", 1)[-1]
        return bool(DEPENDABOT.search(base) or DEPENDABOT.search(str(data.get("name") or "")))

    @staticmethod
    def _emit(sig, rel, ev):
        return Finding(signature_id=sig["id"], category=sig["category"],
                       severity=Severity.parse(sig["severity"]), path=rel,
                       description=sig["description"], remediation=sig.get("remediation", "manual"),
                       evidence=ev, vector=sig["category"])

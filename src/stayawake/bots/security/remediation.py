#!/usr/bin/env python3
"""Remediation engine — turn findings into safe, reversible changes.

Each finding carries a `remediation` id (from the signature DB); this module maps
ids to concrete `Change`s and applies them. Every applied change first backs the
original up to a quarantine directory (reversible). Pure planning is separate from
side-effecting apply so dry-run is trivial.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from stayawake.core import git as gitutil
from stayawake.bots.security.matchers.base import load_jsonc, build_content_sig
from stayawake.bots.security.models import (
    HEURISTIC, QUARANTINE_DIR,
    BORN_INFECTED, INTRINSIC_MATCH, LEGIT_CHANGES, UNTRACKED, NO_VCS,
)
from stayawake.bots.security.obfuscation import analyze_file

# remediation id → internal action. NOTE: the code-loader family (`strip-appended-payload`)
# is deliberately ABSENT here — those findings are NEVER surgically edited (that is what
# corrupted valid files: a textual transform can't reliably excise a polymorphic payload).
# Instead they go through git RECOVERY (restore the file's last clean committed version) or
# are deferred to manual review — see classify_recovery(). The actions below are the
# reliable, structure-safe ones: whole-file quarantine, exact-line / JSON-key removal.
_ACTIONS = {
    "quarantine-file": "quarantine",
    "quarantine-dir": "quarantine",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKERS = {"branch_structure.json", "temp_auto_push.bat", "temp_interactive_push.bat"}

# Quarantine / remediation backups must stay local and never be committed.
# `ensure_ignored` guarantees a target repo's .gitignore carries this before we
# `git add` a fix, so backups never leak into a commit or PR.
_QUARANTINE_COMMENT = "# Malware quarantine / remediation artifacts (kept local, never committed)"
_QUARANTINE_PATTERNS = (QUARANTINE_DIR + "/",)


def is_auto_fixable(finding) -> bool:
    """True if a finding has a known automatic remediation AND we are confident enough to
    auto-edit. A HEURISTIC finding (a packed-blob / oversized-line shape a base64 asset or
    crypto vector also produces) is surfaced but NEVER auto-stripped — auto-editing a file
    we are not sure is malicious is exactly how a false positive becomes a corrupted file.
    Such findings fall through to the manual list instead."""
    if getattr(finding, "confidence", "confirmed") == HEURISTIC:
        return False
    return getattr(finding, "remediation", "manual") in _ACTIONS


def quarantine_path(root: Path) -> Path:
    return root / QUARANTINE_DIR


@dataclass(frozen=True)
class Change:
    action: str        # strip-payload | quarantine | strip-gitignore | strip-settings
    path: str          # repo-relative path the action targets
    detail: str = ""


def _fonts_dir(rel: str) -> str:
    """Map a path inside a camouflage fonts dir to that directory."""
    parts = rel.split("/")
    if "fonts" in parts:
        i = len(parts) - 1 - parts[::-1].index("fonts")
        return "/".join(parts[: i + 1])
    return str(Path(rel).parent)


def plan(findings) -> list[Change]:
    """Map findings to a deduped list of changes (pure — no filesystem access)."""
    changes: dict[tuple[str, str], Change] = {}
    for f in findings:
        if not is_auto_fixable(f):
            continue                      # manual (e.g. evil-merge) or heuristic — not auto-fixed
        action = _ACTIONS[getattr(f, "remediation", "manual")]
        path = f.path
        if f.remediation == "quarantine-dir":
            path = _fonts_dir(f.path)
        if action == "vscode":
            if f.path.endswith("tasks.json"):
                c = Change("quarantine", f.path, "VS Code auto-run task harness")
            elif f.path.endswith("settings.json"):
                c = Change("strip-settings", f.path, "remove allowAutomaticTasks/tasks")
            else:
                continue
        else:
            c = Change(action, path, f.description[:60])
        changes[(c.action, c.path)] = c
    return list(changes.values())


# ── individual transforms (structure-safe: exact-line / JSON-key removal only) ──

def strip_gitignore_text(text: str) -> str:
    return "\n".join(l for l in text.splitlines()
                     if l.strip() not in _GITIGNORE_MARKERS).rstrip("\n") + "\n"


def strip_settings_autorun(text: str) -> str:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        return text
    data.pop("task.allowAutomaticTasks", None)
    data.pop("tasks", None)
    return json.dumps(data, indent=2) + "\n"


def ensure_ignored(root: Path) -> bool:
    """Guarantee `root/.gitignore` ignores quarantine/remediation artifacts.

    Appends any missing patterns (and the explanatory comment) idempotently.
    Returns True if the file was changed. Called before `git add` so backups
    never land in a commit or PR.
    """
    gi = root / ".gitignore"
    if gi.is_symlink():
        return False                      # refuse to follow a symlinked .gitignore (write-through guard)
    text = gi.read_text(encoding="utf-8", errors="replace") if gi.exists() else ""
    present = {l.strip() for l in text.splitlines()}
    missing = [p for p in _QUARANTINE_PATTERNS if p not in present]
    if not missing:
        return False
    block: list[str] = []
    if _QUARANTINE_COMMENT not in present:
        block.append(_QUARANTINE_COMMENT)
    block += missing
    head = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    gi.write_text(head + "\n".join(block) + "\n", encoding="utf-8")
    return True


def _backup(root: Path, rel: str, quarantine: Path) -> None:
    src = root / rel
    if not src.exists():
        return
    if src.is_symlink():
        return                            # never dereference a symlinked target into quarantine
    dest = quarantine / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        # symlinks=True recreates inner symlinks as links instead of copying their
        # (possibly out-of-tree) targets' contents into the quarantine.
        shutil.copytree(src, dest, dirs_exist_ok=True, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def quarantine_residual(root: Path, findings, quarantine: Path) -> list["Change"]:
    """Quarantine (back up + remove) every distinct file still flagged after a
    strip/apply pass — the fail-safe so a partially-cleaned file is never left behind.
    Returns the Changes performed."""
    done: list[Change] = []
    for rel in sorted({f.path for f in findings}):
        target = root / rel
        if not target.exists():
            continue
        _backup(root, rel, quarantine)
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        done.append(Change("quarantine", rel, "residual after remediation"))
    return done


def apply(root: Path, changes: list[Change], quarantine: Path) -> list[Change]:
    """Apply changes in-place under `root`, backing up originals to `quarantine`.

    Idempotent: a change whose target is already gone/clean is skipped.
    """
    applied: list[Change] = []
    for c in changes:
        target = root / c.path
        if c.action == "quarantine":
            if target.exists():
                _backup(root, c.path, quarantine)
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
                applied.append(c)
        elif c.action in ("strip-gitignore", "strip-settings"):
            if not target.exists():
                continue
            original = target.read_text(encoding="utf-8", errors="replace")
            if c.action == "strip-gitignore":
                new = strip_gitignore_text(original)
            else:
                new = strip_settings_autorun(original)
            if new != original:
                _backup(root, c.path, quarantine)
                target.write_text(new, encoding="utf-8")
                applied.append(c)
    return applied


# ── code-loader remediation: git recovery, or deferred manual review ─────────────
# A code-loader payload is polymorphic and embedded in arbitrary code, so it cannot be
# reliably excised by a textual transform — that is exactly what corrupted valid files.
# The source of truth for "what this file should be" is git history, so we either RECOVER
# the file's most recent committed version that scans clean, or — when no safe recovery
# exists — defer to a human with a specific reason + recommended action. Never a heuristic
# edit, so a fix can never leave a syntactically broken file. The manual-review reason
# constants live in models.py (the shared domain-constants home).


@dataclass(frozen=True)
class Recovery:
    """A reliable fix: restore `path` to its last clean committed version. `diff` is a
    redaction-aware preview (payload never printed raw); `clean_text` is what gets written."""
    path: str
    clean_rev: str
    label: str          # e.g. 'a1b2c3d ("chore: tailwind v4", 2026-05-12)'
    diff: str
    clean_text: str


@dataclass(frozen=True)
class Manual:
    """A finding auto-fix can't safely act on — surfaced with WHY and the recommended action."""
    path: str
    signature_id: str
    reason: str
    action: str
    line: int | None = None


def codeloader_content_sig(all_signatures):
    """Compile the code-loader CONTENT fingerprints into check(text) -> id|None — the
    yardstick for deciding whether a (possibly historical) version of a file is clean."""
    return build_content_sig(all_signatures)


def _ext(path: str) -> str:
    i = path.rfind(".")
    return path[i:].lower() if i != -1 else ""


def _has_loader(text: str, content_sig) -> bool:
    """True if `text` carries a known LOADER content fingerprint. This — NOT a whole-file
    obfuscation verdict — is the yardstick for every recovery decision. analyze_file()'s
    packed/base64 verdict false-positives on legitimate inlined assets and minified lines, so
    letting it mark a version 'infected' (or a line 'payload') would DESTROY real code. Recovery
    therefore keys ONLY on the precise loader literals (the confirmed signatures)."""
    return bool(text) and bool(content_sig(text))


def _safe_to_recover(work: str, clean: str, content_sig) -> bool:
    """True ONLY when restoring `clean` provably loses no legitimate code: the SOLE diff is
    ADDED whole lines, each one independently a loader literal (blank lines allowed), with NO
    existing clean line modified or deleted. A payload sharing a physical line with legit code,
    or interleaved with legit lines, is NOT provably separable → returns False → caller defers
    to manual. Deliberately conservative: it never sweeps up co-located legitimate text."""
    w, c = work.splitlines(), clean.splitlines()
    saw_payload = False
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=c, b=w, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag != "insert":              # a clean line was modified/deleted → not provably safe
            return False
        for ln in w[j1:j2]:              # EACH added line must itself be a loader literal (or blank)
            if not ln.strip():
                continue
            if not content_sig(ln):
                return False             # an added line that isn't payload = legit code → unsafe
            saw_payload = True
    return saw_payload                    # ≥1 real payload line, and every add is payload/blank


def _short(s: str, n: int = 100) -> str:
    s = s.rstrip("\n")
    return s if len(s) <= n else s[:n] + "…"


def _redact(body: str) -> str:
    """Redact a payload line to a digest — never print raw malware to a terminal/report."""
    h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:8]
    return f"[obfuscated payload · {len(body)} chars · sha256 {h}…]"


def _recovery_diff(work: str, clean: str, content_sig, context: int = 1) -> str:
    """Compact, redaction-aware preview of what recovery removes. Recovery only ever drops
    whole loader-literal lines (see _safe_to_recover), so each removed payload line is redacted
    to a digest while the surrounding clean lines are shown verbatim."""
    out: list[str] = []
    for ln in difflib.unified_diff(work.splitlines(), clean.splitlines(), lineterm="", n=context):
        if ln[:3] in ("---", "+++") or ln.startswith("@@"):
            continue
        if ln.startswith("-"):
            body = ln[1:]
            out.append("    - " + (_redact(body) if content_sig(body) else _short(body)))
        elif ln.startswith("+"):
            out.append("    + " + _short(ln[1:]))
        else:
            out.append("      " + _short(ln[1:]))
    return "\n".join(out)


def classify_recovery(repo, finding, content_sig):
    """Decide how to remediate ONE (confirmed) code-loader finding: a Recovery (git restore)
    when it is PROVABLY safe (a clean committed version exists and the only delta is appended
    loader lines), else a Manual with a specific reason + recommended action. Never edits."""
    root = Path(repo)
    path, ext = finding.path, _ext(finding.path)
    line = getattr(finding, "line", None)
    sig = finding.signature_id
    target = root / path
    work = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""

    if not gitutil.is_git_repo(repo):
        return Manual(path, sig, NO_VCS,
                      "Not a git repository — no clean version to recover. Review and remove "
                      "the payload manually, or delete the file.", line)
    if not gitutil.tracked(repo, path):
        return Manual(path, sig, UNTRACKED,
                      "Not tracked in git — no committed clean version to recover. Review and "
                      "remove the payload, or delete the file.", line)

    clean = None
    for sha in gitutil.file_commits(repo, path):
        c = gitutil.file_at(repo, sha, path)
        if c and not _has_loader(c, content_sig):   # first version with NO loader literal = clean
            clean = (sha, c)
            break

    if clean is None:
        if analyze_file(work, ext):       # packed/obfuscated → looks born-infected
            return Manual(path, sig, BORN_INFECTED,
                          "No clean version in git history and the content is packed/obfuscated "
                          "— likely born infected. Review and, if confirmed, remove/quarantine it.", line)
        return Manual(path, sig, INTRINSIC_MATCH,
                      "No clean version in history, but it is a plain literal — likely intentional "
                      f"(test/research data). If so, allowlist `{sig}` for `{path}`.", line)

    sha, clean_text = clean
    if _safe_to_recover(work, clean_text, content_sig):
        meta = gitutil.commit_meta(repo, sha)
        label = f'{sha[:7]} ("{_short(meta.get("subject", ""), 40)}", {meta.get("date", "")[:10]})'
        return Recovery(path, sha, label, _recovery_diff(work, clean_text, content_sig), clean_text)
    return Manual(path, sig, LEGIT_CHANGES,
                  f"A clean version exists ({sha[:7]}) but the payload shares a line with, or is "
                  "interleaved with, other code — auto-recovery could lose legitimate work. Recover "
                  f"it yourself and review the diff: `git checkout {sha[:7]} -- {path}`.", line)


def apply_recovery(repo, rec: Recovery, quarantine: Path, content_sig) -> bool:
    """Restore the file to its clean committed version (after backing up the infected one).
    Verify-or-revert: the restored file MUST carry no loader literal, else the original is put
    back. Because we write a real committed blob, the file is never left syntactically corrupt."""
    root = Path(repo)
    target = root / rec.path
    if not target.exists() or _has_loader(rec.clean_text, content_sig):
        return False                      # never write a version that still carries a loader
    _backup(root, rec.path, quarantine)
    target.write_text(rec.clean_text, encoding="utf-8")
    if _has_loader(target.read_text(encoding="utf-8", errors="replace"), content_sig):
        backup = quarantine / rec.path    # verify failed → revert to the original
        if backup.exists():
            shutil.copy2(backup, target)
        return False
    return True

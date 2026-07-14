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
import re
import shutil
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from stayawake.core import git as gitutil
from stayawake.bots.security.matchers.base import load_jsonc, build_content_sig
from stayawake.bots.security.models import (
    HEURISTIC, QUARANTINE_DIR,
    BORN_INFECTED, INTRINSIC_MATCH, LEGIT_CHANGES, UNTRACKED, NO_VCS, INSPECT_FAILED,
)
from stayawake.bots.security.obfuscation import (
    analyze_file, _has_exec_sink, _shannon, _ENTROPY_ABS, _MAX_PROSE_SPACE_FRAC,
)

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


def _carries_payload(text: str, content_sig) -> bool:
    """True if `text` still carries the worm — a known LOADER literal OR a dynamic-exec sink
    (eval / Function / atob / fromCharCode / constructor / the require-hijack global assignment).
    This is the yardstick for
    choosing a clean recovery target and for the post-restore verify.

    Why literal-OR-exec-sink, not just the literal: a confirmed finding's history can hold an
    EARLIER obfuscation stage where the literal isn't present yet but an `eval(atob(...))`
    loader already is (#1053). Keying on the literal alone would mark that stage 'clean' and
    restore a live payload. Why NOT the full analyze_file() packed/base64 verdict: that
    false-positives on legitimately inlined base64 assets / minified lines, and a FP here
    (marking a clean version 'infected') would push recovery onto an older revision — so we
    stop at the exec sink, which every executing payload must reach but a static asset never
    does. A base64-at-rest payload with no sink is caught by the scanner as a (heuristic)
    obfuscation finding and routed to manual review, never to recovery."""
    return bool(text) and (bool(content_sig(text)) or _has_exec_sink(text))


# A payload-blob line is long, dense (almost no whitespace) and high-entropy — the shape of
# a packed loader. A *legit* statement that merely contains a loader token — a real DEL-char
# fromCharCode call, a function carrying the worm's shuffler name, or a line that splices the
# require-hijack global assignment in front of real code — is short and readable and fails this
# gate. That distinction is the whole point: content_sig() is a SUBSTRING match, so it can't tell
# a packed payload from legit code that shares a byte sequence with one. Size+density+entropy can.
_MIN_PAYLOAD_LINE = 120


def _is_packed_line(line: str) -> bool:
    s = line.strip()
    if len(s) < _MIN_PAYLOAD_LINE:
        return False
    space_frac = sum(1 for ch in s if ch == " " or ch == "\t") / len(s)
    return _shannon(s) >= _ENTROPY_ABS and space_frac <= _MAX_PROSE_SPACE_FRAC


def _is_concealment(ch: str) -> bool:
    """True for a character used only to pad/hide a seam: ASCII whitespace plus every Unicode
    control/format (C*), line/paragraph separator (Zl/Zp) and space separator (Zs)."""
    if ch == " " or ch == "\t":
        return True
    cat = unicodedata.category(ch)
    return cat[0] == "C" or cat in ("Zl", "Zp", "Zs")


def _strip_concealment(s: str) -> str:
    """Drop leading and trailing concealment runs, keeping the core intact."""
    i, j = 0, len(s)
    while i < j and _is_concealment(s[i]):
        i += 1
    while j > i and _is_concealment(s[j - 1]):
        j -= 1
    return s[i:j]


# A base64/hex-ish run — the shape of a packed payload's encoded data. Used to bound a blob's
# EXTENT so trailing legit code abutting it isn't absorbed. Bounded char class → linear scan.
_BLOB_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _stmt_is_payload(stmt: str, content_sig) -> bool:
    """True when one `;`-delimited statement of a packed line is provably payload — nothing a
    developer would keep: concealment-only, a whole loader statement carrying a fingerprint
    (`content_sig` on the FULL statement), or a pure encoded blob (nothing readable remains after
    removing concealment + maximal base64/hex runs). A readable, non-fingerprinted statement like
    `module.exports=runServer` is legit code → NOT payload."""
    s = _strip_concealment(stmt)
    if not s:
        return True
    if content_sig(s):
        return True
    return _strip_concealment(_BLOB_RUN.sub("", s)) == ""


def _line_is_pure_payload(ln: str, content_sig) -> bool:
    """True ONLY when an added line is provably payload END-TO-END, safe to drop on recovery. It
    must be a dense packed blob (`_is_packed_line`) carrying a loader fingerprint (`content_sig`),
    AND every `;`-statement of it must itself be provably payload (`_stmt_is_payload`).

    The per-statement gate is what closes the mixed-line hole (#1190): span-aggregate density is
    NOT enough — a legit statement concatenated with an appended blob (`module.exports=runServer;
    <blob>`) rides on the blob's average density + a substring fingerprint match and would be
    dropped whole. Requiring each statement to be individually payload defers that instead.

    KNOWN RESIDUAL (same irreducible class as #1189, mitigated by the quarantine backup): this
    still can't separate a legit statement that *mimics* a loader token (a real DEL-char char-code
    handler, a function carrying the worm's decoder name) or minified legit code that reads as a
    base64 run, from the worm's own connective code — no byte rule can, on a shared line. It
    strictly REDUCES the exposure (it only ever DEFERS more, never drops more than the prior
    density-only check); it does not eliminate the class. See #1190."""
    if not (_is_packed_line(ln) and content_sig(ln)):
        return False
    return all(_stmt_is_payload(stmt, content_sig) for stmt in ln.split(";"))


def _safe_to_recover(work: str, clean: str, content_sig) -> bool:
    """True ONLY when restoring `clean` provably loses no legitimate code. Every requirement
    is a guard the adversarial passes proved necessary:

      * the SOLE diff is ADDED lines — no clean line modified or deleted (a modified line
        could carry interleaved legit edits we can't separate), AND
      * EVERY added non-blank line is BOTH a dense packed-payload line (`_is_packed_line`)
        AND carries a loader literal (`content_sig`).

    An added line is only dropped when it is provably payload END-TO-END (`_line_is_pure_payload`:
    dense + fingerprinted AND every `;`-statement individually payload). Requiring `content_sig`
    alone dropped legit lines byte-identical to a fingerprint (a real DEL-char fromCharCode call)
    and lines that spliced a loader token in front of real code (substring match); `_is_packed_line`
    alone would drop a legitimately-inlined base64 asset; and density-of-the-whole-line alone let a
    legit statement concatenated with an appended blob (`module.exports=runServer;<blob>`) ride
    along and be dropped (#1190). The per-statement gate closes that. Conservative by design: a
    payload split across short bootstrap lines, or any line with a readable non-payload statement,
    defers to manual rather than risk co-located real code."""
    w, c = work.splitlines(), clean.splitlines()
    saw_payload = False
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=c, b=w, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if tag != "insert":              # a clean line was modified/deleted → not provably safe
            return False
        for ln in w[j1:j2]:
            if not ln.strip():
                continue
            if not _line_is_pure_payload(ln, content_sig):
                return False             # not provably payload end-to-end → could be legit → unsafe
            saw_payload = True
    return saw_payload                    # ≥1 packed payload line, and every add is payload/blank


def _is_subsequence(sub: str, whole: str) -> bool:
    """True if every character of `sub` appears in `whole` in order (a greedy O(len(whole))
    scan). The independent 'no fabricated byte' check: recovery only ever REMOVES payload lines,
    so the clean text it writes must be a subsequence of the working file — a clean_text
    carrying any byte not present in-order in the infected file would be fabricated content."""
    it = iter(whole)
    return all(ch in it for ch in sub)


def _short(s: str, n: int = 100) -> str:
    s = s.rstrip("\n")
    return s if len(s) <= n else s[:n] + "…"


def _redact(body: str) -> str:
    """Redact a payload line to a digest — never print raw malware to a terminal/report."""
    h = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:8]
    return f"[obfuscated payload · {len(body)} chars · sha256 {h}…]"


def _recovery_diff(work: str, clean: str, content_sig, context: int = 1) -> str:
    """Compact, redaction-aware preview of what recovery removes. Recovery only ever drops
    whole packed payload lines that carry a loader literal (see _safe_to_recover), so each
    removed line matches content_sig and is redacted to a digest, while the surrounding clean
    lines are shown verbatim — the payload is never printed raw to a terminal or report."""
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

    # The history walk touches git for every commit that changed the file. Any failure here
    # (a corrupt object, an unreadable blob, an OS error) must NOT crash the caller — that
    # would abort remediation for this repo and, in the org sweep, every repo after it. On
    # failure we defer this one finding to manual review and carry on.
    try:
        clean = None
        # first_parent=True: the recovery source is a trust decision. An evil merge can make a
        # "clean-looking" blob reachable only through its malicious second parent; walking the
        # mainline (first-parent) chain only ever selects a version that actually landed on the
        # default branch, then `_carries_payload` re-validates it.
        for sha in gitutil.file_commits(repo, path, first_parent=True):
            c = gitutil.file_at(repo, sha, path)
            if c and not _carries_payload(c, content_sig):   # first version with no payload = clean
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
                      f"Payload shares a line with real code — can't auto-separate it safely. Delete "
                      f"just the payload run from that line, keeping the rest. Note `git checkout "
                      f"{sha[:7]} -- {path}` reverts the ENTIRE file to {sha[:7]} (diff it first so you "
                      f"don't lose other edits made since then).", line)
    except Exception:  # noqa: BLE001 — never let one file's history quirk abort the sweep
        return Manual(path, sig, INSPECT_FAILED,
                      "Could not read this file's git history to find a clean version. Inspect it "
                      f"manually and recover from a known-good commit: `git log -- {path}`.", line)


def apply_recovery(repo, rec: Recovery, quarantine: Path, content_sig) -> bool:
    """Restore the file to its clean committed version (after backing up the infected one).
    Because we write a real committed blob, the file is never left syntactically corrupt.

    Positive post-conditions (verify-or-refuse/revert, proven independently of the planner so a
    stale or mismatched `clean_text` can never slip through):

      * BEFORE writing, re-prove against the file on disk NOW that `clean_text` is exactly 'the
        working file with only payload removed' — `_safe_to_recover(current, clean_text)` (no
        dropped legit byte) AND `_is_subsequence(clean_text, current)` (no fabricated byte).
      * AFTER writing, the restored file MUST carry neither a loader literal nor a dynamic-exec
        sink (`_carries_payload`) and must match `clean_text` byte-for-byte, else the original
        is put back."""
    root = Path(repo)
    target = root / rec.path
    if not target.exists() or _carries_payload(rec.clean_text, content_sig):
        return False                      # never write a version that still carries the payload
    current = target.read_text(encoding="utf-8", errors="replace")
    # No legit byte dropped (delta is provably payload-only) and no fabricated byte (clean_text
    # is a subsequence of what's on disk). Either failing means clean_text is not 'current minus
    # payload' → refuse rather than risk reverting legitimate work.
    if not _safe_to_recover(current, rec.clean_text, content_sig):
        return False
    if not _is_subsequence(rec.clean_text, current):
        return False
    _backup(root, rec.path, quarantine)
    target.write_text(rec.clean_text, encoding="utf-8")
    restored = target.read_text(encoding="utf-8", errors="replace")
    if restored != rec.clean_text or _carries_payload(restored, content_sig):
        backup = quarantine / rec.path    # verify failed → revert to the original
        if backup.exists():
            shutil.copy2(backup, target)
        return False
    return True

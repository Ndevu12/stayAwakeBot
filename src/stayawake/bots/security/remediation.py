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

from stayawake.lib import git as gitutil
from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.matchers.base import load_jsonc, build_content_sig
from stayawake.bots.security.models import (
    HEURISTIC, QUARANTINE_DIR,
    BORN_INFECTED, INTRINSIC_MATCH, LEGIT_CHANGES, UNTRACKED, NO_VCS, INSPECT_FAILED,
)
from stayawake.bots.security.obfuscation import (
    analyze_file, _has_exec_sink, _shannon, _ENTROPY_ABS, _MAX_PROSE_SPACE_FRAC,
)

# remediation id → internal action. NOTE: the code-loader family (`strip-appended-payload`)
# is deliberately ABSENT here — those findings are NEVER fixed by an UNBOUNDED textual transform
# (that is what corrupted valid files: a substring/regex edit can't reliably excise a polymorphic
# payload). They go through git RECOVERY (restore the last clean committed version), else the ONE
# narrowly-gated surgical case — excising a payload hidden behind a concealment SEAM on a line of
# real code (`_seam_strip`: a provable separator, a packed+confirmed suffix, a non-packed result,
# re-proven at apply time, original quarantined) — else manual review. See classify_recovery().
# The actions below are the reliable, structure-safe ones: whole-file quarantine, line/JSON-key removal.
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
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)          # a symlinked dir → unlink the link, don't rmtree it
                else:
                    target.unlink()
                applied.append(c)
        elif c.action in ("strip-gitignore", "strip-settings"):
            if not target.exists():
                continue
            if not is_safe_write_target(target, root):
                # NEVER read/strip/rewrite THROUGH a planted symlink or outside the worktree (#1218):
                # `write_text` would follow the link into a sink and `_backup` skips symlinks, so the
                # backup/verify net is dead. A symlinked/escaping finding defers to manual.
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
    """A reliable fix: `clean_text` is what gets written. Normally that is the file's last clean
    committed version (a git restore); when `excised` is True it is instead the WORKING file with a
    concealment-hidden same-line payload surgically cut out (see `_seam_strip`) — every other byte
    preserved, so no legit edit is lost. `diff` is a redaction-aware preview (payload never printed
    raw). `excised` recoveries carry an extra apply-time gate (the result must not itself be packed).
    `clean_rev` is the source commit for a restore, or a marker for an excision."""
    path: str
    clean_rev: str
    label: str          # e.g. 'a1b2c3d ("chore: tailwind v4", 2026-05-12)'
    diff: str
    clean_text: str
    excised: bool = False


@dataclass(frozen=True)
class Manual:
    """A finding auto-fix can't safely act on — surfaced with WHY and the recommended action."""
    path: str
    signature_id: str
    reason: str
    action: str
    line: int | None = None


@dataclass(frozen=True)
class Suggested:
    """A COMPUTED concealment-seam excision that `_seam_strip` proved structurally safe — five
    self-contained gates hold (an unambiguous ≥16-char concealment boundary, a payload-free result,
    a result that isn't itself packed, NO detectable exec sink in the KEPT code, and only-removal /
    no fabricated byte) — but there is no clean committed ancestor to corroborate it against a
    scanner-INVISIBLE injection in the kept code (the file has no VCS / is untracked / is born
    infected / was legitimately edited since infection, so no whole-file trusted version exists).

    That missing corroboration is the ONE thing the git-match adds over the five gates, and it is
    exactly what a human reviewer + the quarantine backup close (see `_seam_strip`'s own note). So a
    Suggested is NOT trusted like a `Recovery`: it is still applied — `apply_suggested` writes the
    strip — but ONLY into the review branch as a SEPARATE, clearly-labeled commit that the operator
    must eyeball before merging (never auto-merged, and the run stays needs-review until they do).
    The PR review is the trust anchor; the tool never declares the host clean on its own. `diff` is
    the redaction-aware preview (payload shown only as a digest); `excised_text` the strip that gets
    written; `reason` the code for why it isn't git-corroborated; `action` the operator guidance."""
    path: str
    signature_id: str
    reason: str
    action: str
    diff: str
    excised_text: str
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


# A concealment SEAM: a run of this many consecutive concealment chars mid-line. Hand-authored
# code never puts real code, 16+ hiding chars, then MORE code — so a seam is a provable boundary
# between legit code and an appended payload, which is exactly what the general same-line case
# (#1185) lacks. The worm uses hundreds; 16 is far above any legit indentation/alignment and far
# below the worm's runs, so the exact value is not load-bearing (the multi-condition gate below is).
_MIN_CONCEALMENT_SEAM = 16


def _concealment_seam(line: str, content_sig) -> str | None:
    """If `line` hides a payload behind a whitespace-concealment seam —
    `<clean prefix><concealment run ≥ _MIN_CONCEALMENT_SEAM><packed confirmed-payload suffix>` —
    return the CLEAN PREFIX to keep (payload excised). Else None.

    This is the ONE same-line subclass that is provably separable, and every clause is a guard:
      * a substantial CONCEALMENT run is the separator the general same-line case lacks — the split
        point is unambiguous, not a byte-boundary guess;
      * the PREFIX must be non-blank and carry no payload (`_carries_payload`) — we keep it verbatim,
        so it must already be clean;
      * the SUFFIX must be a dense packed blob (`_is_packed_line`) that carries a CONFIRMED loader
        LITERAL (`content_sig`, NOT the broader `_carries_payload`) — requiring the specific worm
        fingerprint, not a generic dynamic-exec sink, is what stops a legit dense line that merely
        USES `atob`/`eval`/`Function` (e.g. a hand-aligned inlined-asset decoder) from being excised
        as if it were payload (adversarial catch — the exec-sink gate dropped real code).
    The residual (same irreducible class as #1189/#1190): a genuinely packed suffix that carries an
    actual worm literal yet is legit minified code would be excised — bounded by the caller's
    `analyze_file` 'result is normal, not packed' gate, the re-scan-to-confirm, and the quarantine."""
    n, i = len(line), 0
    while i < n:
        if not _is_concealment(line[i]):
            i += 1
            continue
        j = i
        while j < n and _is_concealment(line[j]):
            j += 1
        if j - i >= _MIN_CONCEALMENT_SEAM:      # the first real seam is the boundary
            prefix, suffix = line[:i], line[j:]
            if (prefix.strip() and not _carries_payload(prefix, content_sig)
                    and _is_packed_line(suffix) and content_sig(suffix)):
                return prefix
            return None                          # the seam didn't validate → no safe split
        i = j
    return None


# The worm's require-SHIM: an ESM file has no CommonJS `require`, so before a `require`-based
# payload it prepends `import { createRequire } from 'module'; const require = createRequire(
# import.meta.url);`. Matched ONLY at the very start of the file (the worm prepends it). Kept
# tolerant of quote/`node:module`/spacing variants but anchored on the two exact statements.
_WORM_SHIM = re.compile(
    r"^\s*import\s*\{\s*createRequire\s*\}\s*from\s*['\"](?:node:)?module['\"]\s*;?[ \t]*\r?\n"
    r"(?:[ \t]*\r?\n)*"
    r"[ \t]*const\s+require\s*=\s*createRequire\s*\(\s*import\.meta\.url\s*\)\s*;?[ \t]*\r?\n"
    r"(?:[ \t]*\r?\n)*"
)


def _worm_shim_block(text: str) -> str | None:
    """The leading require-shim block the worm prepends (see `_WORM_SHIM`), or None. Returns the
    exact leading text (including its trailing blank lines) so it can be removed verbatim."""
    m = _WORM_SHIM.match(text)
    return m.group(0) if m else None


def _shim_is_dead(rest: str) -> bool:
    """True when the require-shim is UNUSED by `rest` (the file minus the shim, payload already
    excised) — no reference to `require`/`createRequire` remains. Removing an unused binding is a
    semantic no-op, so this is the only condition under which excising the shim is provably safe;
    a config that legitimately calls `require(...)` keeps its shim. Conservative (a substring match
    in a comment/string counts as 'used' → keep the shim) — we only ever remove a provably-dead one."""
    return "require" not in rest and "createRequire" not in rest


def _safe_to_recover(work: str, clean: str, content_sig) -> bool:
    """True ONLY when restoring `clean` (a whole clean COMMITTED version) provably loses no
    legitimate code. This is the git-RESTORE proof; the surgical-excision path re-proves itself by
    re-running `_seam_strip`, so this stays deliberately narrow. Every requirement is a guard the
    adversarial passes proved necessary:

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
    defers to manual (the concealment-seam same-line case is handled by the excision path instead)."""
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


def _seam_strip(work: str, ext: str, content_sig) -> str | None:
    """Build the payload-EXCISED version of `work`: every line hiding a payload behind a
    concealment seam (`_concealment_seam`) is cut back to its clean prefix; EVERY OTHER BYTE is
    preserved — so, unlike a git restore of an older revision, this can never drop a legit edit
    made since infection. Returns the stripped text, or None when there is nothing to cut or the
    result isn't provably safe. Gates (each independently necessary):
      * ≥1 seam was excised, AND
      * the result carries NO payload (`_carries_payload` — the loader is gone), AND
      * the result does NOT itself read as packed/obfuscated (`analyze_file`) — this rejects a
        genuinely minified/packed file (where the excised suffix could be legit dense content) and
        confines the mechanism to hand-authored source/config the worm appended to, AND
      * the result is a SUBSEQUENCE of the working file — we only ever removed bytes, never
        fabricated any.
    When a payload seam is excised, a now-DEAD require-shim the worm prepended is removed too
    (`_worm_shim_block` + `_shim_is_dead`) — a semantic no-op that restores the original byte-for-
    byte; a shim a config actually uses is kept. Deterministic, so apply_recovery re-proves the
    excision by simply re-running this on the on-disk file and requiring the same result; the
    original is quarantined first, so a mis-cut is recoverable."""
    changed = False
    out: list[str] = []
    for raw in work.splitlines(keepends=True):
        body = raw.rstrip("\r\n")
        eol = raw[len(body):]
        prefix = _concealment_seam(body, content_sig)
        if prefix is not None:
            out.append(prefix + eol)      # keep the clean prefix + original line ending
            changed = True
        else:
            out.append(raw)
    if not changed:
        return None                        # no concealment-seam payload here → not our pattern
    stripped = "".join(out)
    # With the payload gone, drop the worm's require-shim IFF nothing left uses `require` — an
    # unused binding, so removing it can't change behaviour (a config that calls require keeps it).
    shim = _worm_shim_block(stripped)
    if shim is not None and _shim_is_dead(stripped[len(shim):]):
        stripped = stripped[len(shim):]
    if _carries_payload(stripped, content_sig):
        return None                        # excision didn't fully remove the loader → not safe
    if _has_exec_sink(stripped, strict=True):
        # We KEEP the prefix and every other line verbatim; a dynamic-exec sink surviving in that
        # kept code — including a reflective `['constructor'](` the normal detector carves out as a
        # benign clone — could be a separate RCE the excision would auto-"clean" past manual review.
        # Refuse: only auto-clean when what remains has no *detectable* exec sink (adversarial catch).
        # NOTE: this is NOT a general RCE guard — it shares the whole scanner's token detection
        # (`_has_exec_sink`), which now catches the common reflective forms (a double-constructor
        # call, a computed-key call, vm run-in-this-context, a Reflect-of-eval) but STILL can't see a
        # split-token or aliased sink, a bare dangerous require whose exec is built at runtime, or a
        # dynamic import. That residual is the pre-existing scanner blind spot, not new here; the PR
        # this fix lands in is human-reviewed, and the original is quarantined.
        return None
    if analyze_file(stripped, ext):        # result still looks packed → not a clean hand-authored file
        return None
    if not _is_subsequence(stripped, work):
        return None                        # fabricated a byte → refuse (defensive; can't happen here)
    return stripped


def _try_suggest(work, ext, content_sig, fallback: "Manual"):
    """Escalate a DEFERRED finding to a computed `Suggested` fix when `_seam_strip` proves a safe
    concealment-seam excision. `_seam_strip`'s five gates are self-contained (they need no git
    ancestor), so this works for the cases that have no whole-file trusted version — no-VCS /
    untracked / born-infected / edited-since. Else return the given `Manual` unchanged (no clean
    seam, or a detectable exec sink survives in the kept code → genuinely inseparable).

    This never weakens auto-apply: a `Suggested` is NEVER written automatically — only a git-
    corroborated `Recovery` is (`apply_recovery`). The human reviewing the computed strip is the
    trust anchor for the ONE residual the git-match would otherwise cover (a scanner-invisible
    injection in the kept code)."""
    excised = _seam_strip(work, ext, content_sig)
    if excised is None:
        return fallback
    return _build_suggested(work, excised, content_sig,
                            fallback.path, fallback.signature_id, fallback.reason, fallback.line)


def _build_suggested(work, excised, content_sig, path, sig, reason, line) -> "Suggested":
    """Wrap an already-computed `_seam_strip` result as a `Suggested` fix (one home for the operator
    guidance + redacted diff)."""
    action = ("saw applied a computed payload-only strip to the review branch: it cuts the "
              "concealment-seam payload and keeps every other byte, and the kept code carries no "
              "payload or detectable exec sink. It is NOT git-corroborated (no clean committed "
              "version to compare against), so review that the kept code is untampered before "
              "merging — the original is quarantined and this change is not auto-merged.")
    return Suggested(path, sig, reason, action, _recovery_diff(work, excised, content_sig), excised, line)


def classify_recovery(repo, finding, content_sig):
    """Decide how to remediate ONE (confirmed) code-loader finding — always to a CLEAN COMMITTED
    version, so the result is trusted history rather than anything we synthesized. Two proofs that
    restoring the last clean first-parent version is safe:

      1. `_safe_to_recover` — the delta is a provably payload-only append (the ordinary shape), or
      2. a concealment-seam EXCISION of the working file REPRODUCES that clean version byte-for-byte
         (`_seam_strip(work) == clean_text`) — the worm's config shape (a payload hidden after a
         whitespace seam on a real line, plus a prepended require-shim) isn't a clean append, so (1)
         defers it; but if excising the seam + a now-dead shim yields EXACTLY the committed clean
         file, restoring it loses nothing and keeps nothing INJECTED — anything the worm added to
         the kept code (a stray edit, or an RCE the scanner can't see) would make the excised result
         DIFFER from the ancestor and is therefore refused. This is what makes the excision safe
         without a complete exec-sink detector. (It does trust committed history to the same degree
         a plain `git checkout` does: a scanner-invisible payload ALREADY committed to the mainline
         clean version would be restored as-is — the same irreducible residual the restore path has,
         reachable only by an attacker who already controls the repo's commits.)

    Else defer to Manual (with a specific reason). A clean committed ancestor is REQUIRED for both
    paths, so no-history / born-infected / untracked findings defer. Never edits a file except by
    writing a re-proven result through apply_recovery."""
    root = Path(repo)
    path, ext = finding.path, _ext(finding.path)
    line = getattr(finding, "line", None)
    sig = finding.signature_id
    target = root / path
    work = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""

    if not gitutil.is_git_repo(repo):
        return _try_suggest(work, ext, content_sig, Manual(
            path, sig, NO_VCS,
            "Not a git repository — no clean version to recover. Review and remove "
            "the payload manually, or delete the file.", line))
    if not gitutil.tracked(repo, path):
        return _try_suggest(work, ext, content_sig, Manual(
            path, sig, UNTRACKED,
            "Not tracked in git — no committed clean version to recover. Review and "
            "remove the payload, or delete the file.", line))

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
                return _try_suggest(work, ext, content_sig, Manual(
                    path, sig, BORN_INFECTED,
                    "No clean version in git history and the content is packed/obfuscated "
                    "— likely born infected. Review and, if confirmed, remove/quarantine it.", line))
            return Manual(path, sig, INTRINSIC_MATCH,
                          "No clean version in history, but it is a plain literal — likely intentional "
                          f"(test/research data). If so, allowlist `{sig}` for `{path}`.", line)

        sha, clean_text = clean
        meta = gitutil.commit_meta(repo, sha)
        label = f'{sha[:7]} ("{_short(meta.get("subject", ""), 40)}", {meta.get("date", "")[:10]})'
        if _safe_to_recover(work, clean_text, content_sig):
            return Recovery(path, sha, label, _recovery_diff(work, clean_text, content_sig), clean_text)
        # Excision, corroborated by the clean ancestor: auto-apply ONLY when the payload-stripped
        # working file equals `clean_text` EXACTLY (matches trusted history → safe against even a
        # scanner-invisible injection). When `_seam_strip` yields a valid excision that DOESN'T match
        # the ancestor — a legit edit was made since infection — auto-apply is unsafe (the edit isn't
        # in trusted history), but the strip is still structurally proven, so offer it as a computed
        # Suggested fix for the operator to review rather than a bare hand-hunt checklist (#1209).
        excised = _seam_strip(work, ext, content_sig)
        if excised == clean_text:
            return Recovery(path, sha, label, _recovery_diff(work, clean_text, content_sig),
                            clean_text, excised=True)
        if excised is not None:
            return _build_suggested(work, excised, content_sig, path, sig, LEGIT_CHANGES, line)
        # No computable seam at all → genuinely inseparable; defer to a manual investigation.
        return Manual(path, sig, LEGIT_CHANGES,
                      f"Payload shares a line with real code and the payload-stripped file doesn't "
                      f"match a clean commit, and no safe concealment seam was found — can't auto-"
                      f"separate it. Delete just the payload run from that line, keeping the rest. Note "
                      f"`git checkout {sha[:7]} -- {path}` reverts the ENTIRE file to {sha[:7]} (diff it "
                      f"first so you don't lose other edits made since then).", line)
    except Exception:  # noqa: BLE001 — never let one file's history quirk abort the sweep
        return Manual(path, sig, INSPECT_FAILED,
                      "Could not read this file's git history to find a clean version. Inspect it "
                      f"manually and recover from a known-good commit: `git log -- {path}`.", line)


def _backup_write_verify(root: Path, rel: str, new_text: str, quarantine: Path, content_sig) -> bool:
    """The shared write TAIL of every remediation (git RESTORE, git-corroborated EXCISION, and the
    computed #1209 strip): back up the current file to `quarantine`, write `new_text`, then
    verify-or-revert — the written file must read back byte-identical AND carry neither a loader
    literal nor an exec sink (`_carries_payload`), else the original is restored. One home for the
    backup + verify + revert net so it is identical for every write path (never downgraded)."""
    target = root / rel
    _backup(root, rel, quarantine)
    target.write_text(new_text, encoding="utf-8")
    restored = target.read_text(encoding="utf-8", errors="replace")
    if restored != new_text or _carries_payload(restored, content_sig):
        backup = quarantine / rel         # verify failed → revert to the original
        if backup.exists():
            shutil.copy2(backup, target)
        return False
    return True


def _apply_seam_excision(root: Path, rel: str, expected: str, quarantine: Path, content_sig) -> bool:
    """Write a concealment-seam excision, re-proving `expected` against the bytes on disk NOW:
    non-empty, a safe write target (NEVER through a symlink or outside the worktree — the shared
    #1218 guard, since `write_text` follows a link and `_backup` skips symlinks, which would leave
    the quarantine + verify net dead), the file exists, the result carries no payload, and — the
    load-bearing check — re-running the deterministic `_seam_strip` on the CURRENT file reproduces
    `expected` EXACTLY. That single equality re-checks every gate (each seam still validates, the
    shim is still dead, the result carries no payload and is not packed, subsequence) against the
    live bytes; if the file changed since classify, the strip differs and we refuse. Then the
    shared backup → write → verify-or-revert tail.

    Shared by a GIT-CORROBORATED `Recovery(excised=True)` and a COMPUTED `Suggested` (#1209): the
    WRITE safety is byte-for-byte identical; they differ ONLY in provenance (whether a clean ancestor
    corroborated `expected`), which the caller reflects in a separate commit / PR section, never in
    the bytes or the proof."""
    target = root / rel
    if not expected or not is_safe_write_target(target, root):
        return False
    if not target.exists() or _carries_payload(expected, content_sig):
        return False
    current = target.read_text(encoding="utf-8", errors="replace")
    if _seam_strip(current, _ext(rel), content_sig) != expected:
        return False                      # the canonical strip no longer reproduces it → refuse
    return _backup_write_verify(root, rel, expected, quarantine, content_sig)


def apply_recovery(repo, rec: Recovery, quarantine: Path, content_sig) -> bool:
    """Write `rec.clean_text` (after backing up the infected file), re-proving safety against the
    bytes on disk NOW — proven independently of the planner, so a stale/mismatched `clean_text`
    can never slip through — and reverting if the write doesn't verify.

    The pre-proof depends on how `clean_text` was derived:
      * a surgical EXCISION (`rec.excised`): delegated to `_apply_seam_excision` — re-run the
        deterministic `_seam_strip` on the CURRENT file; it must reproduce `clean_text` exactly.
      * a git RESTORE (`rec.excised` is False): the delta must be provably payload-only
        (`_safe_to_recover`) AND `clean_text` a subsequence of the file (`_is_subsequence`, no
        fabricated byte).
    AFTER writing (shared tail), the restored file must match byte-for-byte and carry neither a
    loader literal nor an exec sink, else the original is put back."""
    root = Path(repo)
    if rec.excised:
        return _apply_seam_excision(root, rec.path, rec.clean_text, quarantine, content_sig)
    target = root / rec.path
    if not rec.clean_text or not is_safe_write_target(target, root):
        # Refuse an empty result, and NEVER write through a symlink or outside the worktree (#1204,
        # now the shared #1218 guard): `write_text` follows the link (could clobber a file outside the
        # worktree) and `_backup` skips symlinks, so the quarantine + verify-or-revert net would be
        # dead. The containment check also closes a symlinked ANCESTOR dir or a `..`. Defers to manual.
        return False
    if not target.exists() or _carries_payload(rec.clean_text, content_sig):
        return False                      # never write a version that still carries the payload
    current = target.read_text(encoding="utf-8", errors="replace")
    # No legit byte dropped (delta provably payload-only) and no fabricated byte. Either failing
    # means clean_text is not 'current minus payload' → refuse rather than risk reverting legit work.
    if not _safe_to_recover(current, rec.clean_text, content_sig):
        return False
    if not _is_subsequence(rec.clean_text, current):
        return False
    return _backup_write_verify(root, rec.path, rec.clean_text, quarantine, content_sig)


def apply_suggested(repo, sug: "Suggested", quarantine: Path, content_sig) -> bool:
    """Apply a COMPUTED (non-git-corroborated) concealment-seam strip — the #1209 Tier-2 write.
    Byte-for-byte the SAME safety as an excised `Recovery` (re-prove `_seam_strip` on the live file,
    then backup → write → verify-or-revert, all via the shared `_apply_seam_excision`). The ONLY
    difference is that no clean ancestor corroborated it, so the CALLER lands it as a separate,
    review-required commit and keeps the run needs-review — the operator's PR review is the trust
    anchor for the one residual the git-match would otherwise close (a scanner-invisible injection
    in the kept code). Never auto-merged; never presented as a corroborated fix."""
    return _apply_seam_excision(Path(repo), sug.path, sug.excised_text, quarantine, content_sig)

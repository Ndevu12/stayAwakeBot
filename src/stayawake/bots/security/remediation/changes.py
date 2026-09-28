#!/usr/bin/env python3
"""Map findings to structure-safe changes and apply them."""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils.pathsafe import is_safe_write_target
from stayawake.bots.security.harden import jsonc
from stayawake.bots.security.jsonc import load_jsonc
from stayawake.bots.security.models import CONFIRMED, ROLLBACK_DIR, SAW_DIR
from stayawake.bots.security.remediation.footprint import REMOVE_FILE
from stayawake.bots.security.remediation.oracle import (ABSENT, CARRIES, CHANGED, REFUSED,
                                                        UNREADABLE)

_ACTIONS = {
    REMOVE_FILE: "remove",
    "remove-foreign-vscode": "vscode",
    "strip-gitignore-markers": "strip-gitignore",
}
_GITIGNORE_MARKER_PATTERNS = None

_ROLLBACK_COMMENT = "# Remediation rollback copies (kept local, never committed)"
_ROLLBACK_PATTERNS = (SAW_DIR + "/",)
_RAW_BYTE = re.compile("[\udc80-\udcff]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_STAND_IN_POINTS = range(0xF0000, 0x110000)


def is_auto_fixable(finding) -> bool:
    """True when a confirmed finding has a known automatic remediation."""
    if getattr(finding, "confidence", None) != CONFIRMED:
        return False
    return getattr(finding, "remediation", "manual") in _ACTIONS


def rollback_path(root: Path) -> Path:
    return root / ROLLBACK_DIR


@dataclass(frozen=True)
class Change:
    action: str
    path: str
    detail: str = ""


def repair_for(finding) -> Change | None:
    """The change that repairs one confirmed finding, or None when it has no automatic repair.
    Takes the finding. Returns the change."""
    if not is_auto_fixable(finding):
        return None
    action = _ACTIONS[getattr(finding, "remediation", "manual")]
    path = finding.path
    if not path or Path(path) in (Path("."), Path("..")):
        return None
    if action == "vscode":
        if path.endswith("tasks.json"):
            return Change("remove", path, "VS Code auto-run task harness")
        if path.endswith("settings.json"):
            return Change("strip-settings", path, "remove allowAutomaticTasks/tasks")
        return None
    return Change(action, path, finding.description[:60])


def plan(findings) -> list[Change]:
    """Map findings to a deduped list of changes (pure — no filesystem access)."""
    changes: dict[tuple[str, str], Change] = {}
    for f in findings:
        c = repair_for(f)
        if c is not None:
            changes[(c.action, c.path)] = c
    return list(changes.values())


def text_repair(action: str):
    """`repair(text) -> repaired | None` for a change made by editing a file's text, None when the
    text needs no repair. Takes the change's action. Returns the function, or None when the action
    does not edit text. A settings repair also offers `proves(before, after)`: whether every other
    setting survives the rewrite unchanged."""
    edit = {"strip-settings": strip_settings_autorun,
            "strip-gitignore": strip_gitignore_text}.get(action)
    if edit is None:
        return None

    def repair(text: str) -> str | None:
        if not text:
            return None
        repaired = edit(text)
        return None if repaired == text else repaired
    if action == "strip-settings":
        repair.proves = _keeps_the_rest
    return repair


def _gitignore_marker_patterns():
    """The git-marker patterns for `.gitignore`, compiled once from the live signature DB."""
    global _GITIGNORE_MARKER_PATTERNS
    if _GITIGNORE_MARKER_PATTERNS is None:
        from stayawake.bots.security import signatures as _sigs
        from stayawake.bots.security.remediation import footprint
        flat = [s for group in _sigs.load_signatures().values() for s in group]
        _GITIGNORE_MARKER_PATTERNS = footprint._marker_patterns(".gitignore", flat)
    return _GITIGNORE_MARKER_PATTERNS


def strip_gitignore_text(text: str) -> str:
    """`text` with every worm-marker line the signatures name removed; unchanged if none match."""
    from stayawake.bots.security.remediation import footprint
    stripped = footprint.line_marker_strip(text, _gitignore_marker_patterns())
    return text if stripped is None else stripped


def strip_settings_autorun(text: str) -> str:
    """`text` with the automatic-task setting and the task list taken out, and nothing else about
    the file changed.

    Takes the file's text. Returns it unchanged when neither is there. When they cannot be taken
    out where they sit with every other top-level member intact, the file is written back whole
    without them, and its comments and layout are lost.
    """
    original = text
    done = jsonc.remove_key(text, "task.allowAutomaticTasks")
    text = done[0] if done else text
    done = jsonc.remove_member(text, "tasks")
    text = done[0] if done else text
    if text != original and _keeps_the_rest(original, text):
        return text
    return _rewritten_without_autorun(original)


def _rewritten_without_autorun(text: str) -> str:
    """`text` parsed and written back without the automatic-task setting and the task list. A byte
    that is not UTF-8 is written back as the same byte and an escaped surrogate as the same escape.
    Takes the file's text. Returns it unchanged when it does not parse to an object holding either,
    or holds a number JSON cannot write back."""
    data = load_jsonc(text)
    if not _holds_autorun(data):
        return text
    stand_ins = _stand_ins_for_raw_bytes(text, data)
    if stand_ins:
        data = load_jsonc(text.translate(stand_ins))
        if not _holds_autorun(data):
            return text
    data.pop("task.allowAutomaticTasks", None)
    data.pop("tasks", None)
    try:
        if stand_ins is None:
            return json.dumps(data, indent=2, allow_nan=False) + "\n"
        written = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    except ValueError:
        return text
    written = _SURROGATE.sub(lambda found: "\\u%04x" % ord(found.group()), written)
    return written.translate({ord(stand_in): chr(raw) for raw, stand_in in stand_ins.items()})


def _holds_autorun(data) -> bool:
    """Whether parsed settings are an object holding the automatic-task setting or the task list."""
    return isinstance(data, dict) and bool({"task.allowAutomaticTasks", "tasks"} & data.keys())


def _stand_ins_for_raw_bytes(text: str, data) -> dict[int, str] | None:
    """A translation table giving each character of `text` that holds a byte that is not UTF-8 its
    own private-use character, one found nowhere in `text` or in the strings `data` holds.

    Takes the text and the value it parses to. Returns the table, empty when `text` holds no such
    byte, or None when too few unused characters are left.
    """
    raw = sorted(set(_RAW_BYTE.findall(text)))
    if not raw:
        return {}
    taken = set(text)
    for string in _strings_in(data):
        taken.update(string)
    free = (chr(point) for point in _STAND_IN_POINTS if chr(point) not in taken)
    table = {ord(character): stand_in for character, stand_in in zip(raw, free)}
    return table if len(table) == len(raw) else None


def _strings_in(value):
    """Every key and every string `value` holds, at any depth."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _keeps_the_rest(before: str, after: str) -> bool:
    """Whether an edited settings file still parses and holds every other top-level member unchanged.
    Takes the text before and after. Returns True when it does."""
    if after == before:
        return True
    old, new = load_jsonc(before), load_jsonc(after)
    if not isinstance(old, dict) or not isinstance(new, dict):
        return False
    taken = {"task.allowAutomaticTasks", "tasks"}
    return {k: v for k, v in old.items() if k not in taken} == new


def ensure_ignored(root: Path) -> bool:
    """Append the rollback-store ignore patterns to `root/.gitignore`. True if the file changed."""
    gi = root / ".gitignore"
    if gi.is_symlink():
        return False
    text = gi.read_text(encoding="utf-8", errors="replace") if gi.exists() else ""
    present = {l.strip() for l in text.splitlines()}
    missing = [p for p in _ROLLBACK_PATTERNS if p not in present]
    if not missing:
        return False
    block: list[str] = []
    if _ROLLBACK_COMMENT not in present:
        block.append(_ROLLBACK_COMMENT)
    block += missing
    head = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    gi.write_text(head + "\n".join(block) + "\n", encoding="utf-8")
    return True


def _dest_ready(rollback: Path, dest: Path) -> bool:
    try:
        if dest.is_symlink() or dest.exists():
            return False
        try:
            lexical = dest.relative_to(rollback)
        except ValueError:
            return False
        if lexical == Path(".") or ".." in lexical.parts:
            return False
        q = rollback.resolve()
        resolved = dest.resolve()
        if resolved == q or not resolved.is_relative_to(q):
            return False
        p = dest.parent
        while True:
            if p.is_symlink():
                return False
            pr = p.resolve()
            if not pr.is_relative_to(q):
                return False
            if pr == q:
                return True
            if p.parent == p:
                return False
            p = p.parent
    except (OSError, RuntimeError, ValueError):
        return False


def _backup(root: Path, rel: str, rollback: Path | None) -> None:
    if rollback is None:
        return
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        return
    src = root / rel
    if not src.exists():
        return
    if src.is_symlink():
        return
    dest = rollback / rel
    if not _dest_ready(rollback, dest):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not _dest_ready(rollback, dest):
        return
    if src.is_dir():
        shutil.copytree(src, dest, symlinks=True)
    else:
        shutil.copy2(src, dest, follow_symlinks=False)


def _erase(target: Path) -> None:
    """Take a file off the disk. Takes the path.

    A file more than one name points at has its bytes emptied first; when that cannot be done the
    name is left too, and the error says so.
    """
    if not target.is_symlink() and target.stat().st_nlink > 1:
        try:
            target.chmod(target.stat().st_mode | 0o200)
        except OSError:
            pass
        with open(target, "wb"):
            pass
        if target.stat().st_size != 0:
            raise OSError(f"{target} could not be emptied")
    target.unlink()


def _erase_through(root: Path, link: Path, condemned=None) -> None:
    """Take a link off the disk, and the file it points at when that file is this repository's and
    carries a payload at its own path.

    Takes the repository root, the link and `condemned(path) -> str`; without it the file pointed
    at stays, and so does any file saw may not write.
    """
    try:
        pointed = link.resolve()
    except (OSError, RuntimeError):
        pointed = None
    if (pointed is not None and condemned is not None and pointed.is_file()
            and is_safe_write_target(pointed, root)):
        try:
            own_path = pointed.relative_to(root.resolve()).as_posix()
        except ValueError:
            own_path = None
        if own_path is not None and condemned(own_path) == CARRIES:
            _erase(pointed)
    link.unlink()


def _skipped(on_skip, path: str, reason: str) -> None:
    """Tell the caller a change was not applied. Takes the callback, the path and the reason."""
    if on_skip is not None:
        on_skip(path, reason)


def _delete_stays_in(root: Path, target: Path) -> bool:
    try:
        base = root.resolve()
        if target.is_symlink():
            return target.parent.resolve().is_relative_to(base)
        if not is_safe_write_target(target, root):
            return False
        return target.resolve() != base
    except (OSError, RuntimeError, ValueError):
        return False


def remove_residual(root: Path, findings, rollback: Path) -> list["Change"]:
    """Back up and remove each remaining flagged path."""
    done: list[Change] = []
    for rel in sorted({f.path for f in findings}):
        target = root / rel
        if not target.exists() or not _delete_stays_in(root, target):
            continue
        _backup(root, rel, rollback)
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        done.append(Change("remove", rel, "residual after remediation"))
    return done


def apply(root: Path, changes: list[Change], rollback: Path | None = None, *,
          condemned=None, on_skip=None) -> list[Change]:
    """Apply changes in-place under `root`, backing up originals to `rollback`.

    Takes the tree, the changes, a rollback store or None, optionally `condemned(path) -> str`,
    and optionally `on_skip(path, reason)`. Returns the changes that were applied.

    Idempotent: a change whose target is already gone/clean is skipped.
    """
    applied: list[Change] = []
    for c in changes:
        target = root / c.path
        if c.action == "remove":
            verdict = condemned(c.path) if condemned is not None else CARRIES
            if verdict not in (CARRIES, CHANGED):
                _skipped(on_skip, c.path, verdict)
                continue
            if not target.exists() and not target.is_symlink():
                _skipped(on_skip, c.path, ABSENT)
                continue
            if not _delete_stays_in(root, target):
                _skipped(on_skip, c.path, REFUSED)
                continue
            _backup(root, c.path, rollback)
            try:
                if target.is_dir() and not target.is_symlink():
                    shutil.rmtree(target)
                elif target.is_symlink():
                    _erase_through(root, target, condemned)
                else:
                    _erase(target)
            except OSError:
                _skipped(on_skip, c.path, REFUSED)
                continue
            applied.append(c)
        elif c.action in ("strip-gitignore", "strip-settings"):
            if not target.exists():
                _skipped(on_skip, c.path, ABSENT)
                continue
            if not is_safe_write_target(target, root):
                _skipped(on_skip, c.path, REFUSED)
                continue
            try:
                if target.stat().st_nlink > 1:
                    _skipped(on_skip, c.path, REFUSED)
                    continue
                original = target.read_bytes().decode("utf-8", "surrogateescape")
            except OSError:
                _skipped(on_skip, c.path, UNREADABLE)
                continue
            if c.action == "strip-gitignore":
                new = strip_gitignore_text(original)
            else:
                new = strip_settings_autorun(original)
            if new == original:
                _skipped(on_skip, c.path, REFUSED)
                continue
            _backup(root, c.path, rollback)
            try:
                target.write_bytes(new.encode("utf-8", "surrogateescape"))
            except OSError:
                _skipped(on_skip, c.path, REFUSED)
                continue
            if condemned is not None and condemned(c.path) == CARRIES:
                _skipped(on_skip, c.path, REFUSED)
                continue
            applied.append(c)
    return applied

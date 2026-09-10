#!/usr/bin/env python3
"""Correct an editor setting that lets a folder run code without being asked.

These are the safest changes this tool can make: one file, owned by the person running the
command, and a value the audit already prints.

What is corrected is deliberately narrow. A setting whose answer is a decision rather than a
default has no known-correct value, so it stays reported: this writes values, it does not make
decisions. Which is which is not decided here — `hygiene.editor` declares it, and this reads that
declaration. No key is ever removed, here or by the undo, so a key that was added stays and is
reported rather than deleted.
"""
from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.harden import jsonc
from stayawake.bots.security.jsonc import load_jsonc
from stayawake.bots.security.hygiene import editor, editors
from stayawake.utils import atomicwrite, env


@dataclass(frozen=True)
class Planned:
    """A correction with the exact edit it would make, before anything is written.

    `path` is where the value lives in the parsed settings, key by key. A dotted string cannot say
    that: these keys contain dots themselves.
    """

    issue_id: str
    edit: jsonc.Edit
    path: tuple[str, ...] = ()

    def described(self) -> str:
        if self.edit.adds:
            return f'  add     "{self.edit.key}": {self.edit.value}'
        return f'  change  "{self.edit.key}": {self.edit.was} -> {self.edit.value}'


ALREADY, CANNOT_WRITE, A_DECISION = "already", "cannot-write", "a-decision"


@dataclass(frozen=True)
class Skipped:
    """A finding this will not answer, and why — never silently dropped."""

    issue_id: str
    kind: str
    reason: str


_CORRECTION_BY_ID = {issue_id: setting for issue_id, setting in editor.SETTING_FOR.items()
                     if setting.correct is not None}

_TURNS_OFF_ENTRIES = {issue_id for issue_id, setting in editor.SETTING_FOR.items()
                      if setting.turns_off_entries}

_WHY_NOT_WRITTEN: dict[str, str] = {}


def plan(text: str, issue_ids) -> tuple[str, list[Planned], list[Skipped]]:
    """Every edit the findings in `issue_ids` ask for, applied to a copy of `text`.

    Returns the corrected text alongside what was planned and what was not. Nothing is written
    here: the caller decides whether to keep the result.
    """
    planned: list[Planned] = []
    skipped: list[Skipped] = []
    for issue_id in sorted(issue_ids):
        if issue_id in _TURNS_OFF_ENTRIES:
            text, done, missed = _turn_off_dangerous(text, issue_id)
            planned += done
            skipped += missed
            continue
        if issue_id in _WHY_NOT_WRITTEN:
            skipped.append(Skipped(issue_id, A_DECISION, _WHY_NOT_WRITTEN[issue_id]))
            continue
        setting = _CORRECTION_BY_ID.get(issue_id)
        if setting is None:
            continue
        if jsonc.value_at(text, setting.key) == setting.correct:
            skipped.append(Skipped(issue_id, ALREADY, "already set to that value when it was read"))
            continue
        result = jsonc.set_value(text, setting.key, setting.correct)
        if result is None:
            skipped.append(Skipped(issue_id, CANNOT_WRITE,
                                   f'"{setting.key}" is not somewhere this can write to '
                                   "without guessing"))
            continue
        text, edit = result
        planned.append(Planned(issue_id, edit, (setting.key,)))
    return text, planned, skipped


def _turn_off_dangerous(text: str, issue_id: str) -> tuple[str, list[Planned], list[Skipped]]:
    """Turn off every auto-approved command the check names, one entry at a time.

    The check is asked which entries those are rather than the finding's sentence being read back
    — the sentence is a rendering of the answer, not the answer. Nothing is removed and nothing is
    added: an entry already there is set to false, so an undo can put it back exactly.
    """
    key = editor.AUTO_APPROVE.key
    planned: list[Planned] = []
    skipped: list[Skipped] = []
    if editor.blanket_autoapprove(text):
        result = jsonc.set_value(text, key, "false")
        if result is None:
            return text, [], [Skipped(issue_id, CANNOT_WRITE,
                                      f'"{key}" is not somewhere this can write to without guessing')]
        text, edit = result
        return text, [Planned(issue_id, edit, (key,))], []
    named = editor.catchall_autoapprove_entries(text) + editor.risky_autoapprove_entries(text)
    if not named:
        return text, [], [Skipped(issue_id, ALREADY,
                                  "no auto-approved command was named when it was read")]
    for entry in named:
        result = jsonc.set_member(text, key, entry, "false")
        if result is not None:
            text, edit = result
            planned.append(Planned(issue_id, edit, (key, entry)))
            continue
        nested = jsonc.set_member(text, entry, "approve", "false")
        if nested is None:
            skipped.append(Skipped(issue_id, CANNOT_WRITE,
                                   f'"{entry}" is not somewhere this can write to without guessing'))
            continue
        text, edit = nested
        planned.append(Planned(issue_id, edit, (key, entry, "approve")))
    return text, planned, skipped


def answerable(issue_ids) -> set[str]:
    """The findings this can act on. Everything else stays reported."""
    return {i for i in issue_ids if i in _CORRECTION_BY_ID or i in _TURNS_OFF_ENTRIES}


def reported_only(issue_ids) -> set[str]:
    """Findings this could reach and deliberately does not write."""
    return {i for i in issue_ids if i in _WHY_NOT_WRITTEN}


def diff(before: str, after: str, path: Path) -> str:
    """The change, as the person running this will see it before agreeing to it."""
    import difflib
    lines = difflib.unified_diff(before.splitlines(keepends=True),
                                 after.splitlines(keepends=True),
                                 fromfile=str(path), tofile=f"{path} (proposed)")
    return "".join(lines).rstrip()


CORRECTED, ALREADY_CORRECT, NOT_WRITTEN, NOT_RECORDED = (
    "corrected", "already-correct", "not-written", "corrected-not-recorded")


@dataclass(frozen=True)
class EditorOutcome:
    """What one pass did to one editor's settings."""

    name: str
    path: Path
    state: str
    detail: str = ""


@dataclass
class Correcting:
    """What settling this machine's editors did, for a caller that reports it in its own words."""

    outcomes: list[EditorOutcome] = field(default_factory=list)
    problem: str | None = None

    @property
    def settled(self) -> bool:
        """True only when every editor here holds the values this knows are correct."""
        return self.problem is None and not [o for o in self.outcomes if o.state == NOT_WRITTEN]

    @property
    def changed(self) -> bool:
        return any(o.state in (CORRECTED, NOT_RECORDED) for o in self.outcomes)


def record_path() -> Path:
    """Where saw records what it changed, so a later run can put it back."""
    return Path(env.xdg_state_home()) / "saw" / "editor-changes.json"


def _remember(entries: list[dict], path: Path | None = None) -> bool:
    """Add `entries` to the undo record. True if it was written.

    Only saw's own keys and the literal that was there before them are kept. The settings file is
    never copied: it is the operator's, and it holds what they put in it.
    """
    where = path or record_path()
    held, readable = _remembered(where)
    if not readable:
        return False
    for entry in entries:
        if entry not in held:
            held.append(entry)
    return atomicwrite.replace(where, json.dumps({"version": 1, "entries": held}))


def _remembered(path: Path | None = None) -> tuple[list[dict], bool]:
    """What saw has changed and not yet put back, and whether that answer is trustworthy."""
    where = path or record_path()
    try:
        data = json.loads(where.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], True
    except (OSError, ValueError):
        return [], False
    entries = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], False
    return [e for e in entries if isinstance(e, dict)], True


def _lands_where_it_was_aimed(before: str, after: str, planned: list[Planned]) -> bool:
    """Whether `after` is `before` with exactly the planned settings changed, and nothing else."""
    try:
        was, now = load_jsonc(before), load_jsonc(after)
    except Exception:
        return False
    if not isinstance(was, dict) or not isinstance(now, dict):
        return False
    heads = set()
    for step in planned:
        if not step.path:
            return False
        try:
            wanted = json.loads(step.edit.value)
        except ValueError:
            return False
        holder = now
        for name in step.path[:-1]:
            if not isinstance(holder, dict) or name not in holder:
                return False
            holder = holder[name]
        if not isinstance(holder, dict) or holder.get(step.path[-1]) != wanted:
            return False
        heads.add(step.path[0])
    moved = {k for k in set(was) | set(now) if was.get(k) != now.get(k)}
    return moved == heads


def _read(path: Path) -> str:
    """The file exactly as it is on disk, newlines and all."""
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def _mode_of(path: Path) -> int:
    """The file's own permissions, so correcting a setting never widens or narrows them."""
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return 0o600


def settle(find=editors.installed, write=None, record: Path | None = None,
           remember=None) -> Correcting:
    """Put the known-correct value in every editor on this machine that does not hold it.

    Returns one outcome per editor. A setting whose answer is a decision is never written; it stays
    in the audit for the operator.
    """
    write = write or atomicwrite.replace
    remember = _remember if remember is None else remember
    found = find()
    out = Correcting()
    for editor_here in found.editors:
        try:
            text = _read(editor_here.settings)
        except (OSError, ValueError):     # ValueError: not UTF-8. One blind file, not the pass.
            out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings, NOT_WRITTEN,
                                              "its settings could not be read"))
            continue
        ids = {i.id for i in editor.grade_settings(text, editor_here.name, editor_here.settings)}
        corrected, planned, skipped = plan(text, answerable(ids))
        refused = [s for s in skipped if s.kind == CANNOT_WRITE]
        if refused:
            out.outcomes.append(EditorOutcome(
                editor_here.name, editor_here.settings, NOT_WRITTEN,
                "; ".join(s.reason for s in refused)))
            continue
        if not planned:
            out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings,
                                              ALREADY_CORRECT))
            continue
        if not _lands_where_it_was_aimed(text, corrected, planned):
            out.outcomes.append(EditorOutcome(
                editor_here.name, editor_here.settings, NOT_WRITTEN,
                "the corrected settings did not read back as exactly that change"))
            continue
        try:                              # nobody saved over it between the read and the write
            if _read(editor_here.settings) != text:
                raise OSError
        except (OSError, ValueError):
            out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings, NOT_WRITTEN,
                                              "its settings changed while this was reading them"))
            continue
        if not write(editor_here.settings, corrected, mode=_mode_of(editor_here.settings)):
            out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings, NOT_WRITTEN,
                                              "the corrected settings could not be written"))
            continue
        keys = ", ".join(p.edit.key for p in planned)
        if not remember([{"path": str(editor_here.settings), "key": p.edit.key,
                          "at": list(p.path), "was": p.edit.was} for p in planned], record):
            out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings, NOT_RECORDED,
                                              keys))
            continue
        out.outcomes.append(EditorOutcome(editor_here.name, editor_here.settings, CORRECTED, keys))
    return out


@dataclass
class TakingBack:
    """What putting the editor settings back did."""

    restored: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    unreadable_record: bool = False

    @property
    def done(self) -> bool:
        """True only when nothing saw changed is still changed.

        A key it ADDED is still there, so `kept` counts against this exactly as `failed` does.
        """
        return not self.failed and not self.kept and not self.unreadable_record


def _put_back(text: str, at: list[str], was: str) -> str | None:
    """`text` with the value at `at` set back to `was`, or None when that cannot be done exactly.

    The same walk the write used. A member of a table is not reachable by the key of the table,
    so the path is what the record keeps rather than a name with dots in it.
    """
    if len(at) == 1:
        result = jsonc.set_value(text, at[0], was)
    elif len(at) == 2:
        result = jsonc.set_member(text, at[0], at[1], was)
    elif len(at) == 3:
        result = jsonc.set_member(text, at[1], at[2], was)
    else:
        return None
    return None if result is None else result[0]


def take_back(record: Path | None = None, write=None) -> TakingBack:
    """Put back every editor setting saw changed that had a value before it.

    A key saw ADDED is kept and reported, never deleted: this module does not remove keys, and a
    setting that is absent is the state the audit reports as a finding.
    """
    write = write or atomicwrite.replace
    write = write or atomicwrite.replace
    where = record or record_path()
    out = TakingBack()
    entries, readable = _remembered(where)
    if not readable:
        out.unreadable_record = True
        return out
    left: list[dict] = []
    for entry in entries:
        path, key, was = entry.get("path"), entry.get("key"), entry.get("was")
        if not isinstance(path, str) or not isinstance(key, str):
            continue
        at = entry.get("at")
        at = [str(name) for name in at] if isinstance(at, list) and at else [key]
        if was is None:
            # Kept in the record as well as reported: the key is still in the file, so a later run
            # must be able to say so rather than find nothing and report a clean undo.
            out.kept.append(f"{path}: {key}")
            left.append(entry)
            continue
        try:
            text = _read(Path(path))
        except (OSError, ValueError):
            out.failed.append(f"{path}: {key}")
            left.append(entry)
            continue
        result = _put_back(text, at, was)
        if result is None or not write(Path(path), result, mode=_mode_of(Path(path))):
            out.failed.append(f"{path}: {key}")
            left.append(entry)
            continue
        out.restored.append(f"{path}: {key}")
    if not atomicwrite.replace(where, json.dumps({"version": 1, "entries": left})):
        out.unreadable_record = True
    return out

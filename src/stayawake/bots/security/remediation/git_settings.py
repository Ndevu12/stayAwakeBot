#!/usr/bin/env python3
"""Take out of a checkout the git settings and configured hooks that carry a known payload.

A setting goes as that one value. A hook configured in git's settings goes key by key, and only when
every entry of it that git reads for the repository is in the checkout and every command it names
carries a known payload and was reported. Each is judged again as it is acted on. Anything else
confirmed is left and named; no file is removed here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.matchers import git_exec_surface as grading
from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.signatures import every_signature
from stayawake.lib.git import operator_config
from stayawake.lib.git.exec_surface import (ConfigEntry, ExecSurface, list_config_file,
                                            read_config, read_exec_surface)
from stayawake.lib.git.run import OPERATOR_CONFIG, run
from stayawake.utils import pathsafe

NOT_A_KNOWN_PAYLOAD = "is not a known payload on its own — review it"
NOT_READ = "could not be read in full, so it was left"
NOT_TAKEN_OUT = "could not be taken out"
A_HOOKS_DIRECTORY_FILE = ("is a file in the hooks directory, which saw fix does not remove — remove "
                          "it yourself")


@dataclass
class SettingsRemoval:
    """What a run took out of a checkout's git settings, and what it left.

    `stripped`, `absent` and `unread` name checkout-relative files as the live checkout's result
    does; `left_reasons` holds one sentence per confirmed setting or hook left in place and
    `left_paths` the files that hold them; `confirmed_hook_left` is True when a configured hook a
    confirmed finding names is still in place.
    """

    stripped: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    unread: list[str] = field(default_factory=list)
    left_reasons: list[str] = field(default_factory=list)
    left_paths: list[str] = field(default_factory=list)
    confirmed_hook_left: bool = False

    def record_left(self, path: str, subject: str, why: str) -> None:
        """Record a confirmed setting or hook left in place. Takes its file, what it is and why."""
        self.left_reasons.append(f"{subject} in {path} {why}")
        self.left_paths.append(path)


def take_out_payload_settings(root: Path, findings, signatures, opts) -> SettingsRemoval:
    """Take out every git setting and configured hook a confirmed finding names that carries a
    known payload. Takes the checkout, the findings, the by-matcher signatures and the scan options.
    Returns what was taken out and what was left."""
    reported = {(f.path, f.evidence) for f in findings
                if getattr(f, "signature_id", None) == grading.PAYLOAD_SIGNATURE
                and getattr(f, "confidence", None) == CONFIRMED}
    removal = SettingsRemoval()
    if not reported:
        return removal
    root = Path(root)
    surface = read_exec_surface(root)
    if surface is None:
        removal.unread += sorted({path for path, _ in reported})
        return removal
    known_payload = grading.payload_check_for(every_signature(signatures))
    matched, hooks_handled = set(), set()
    for judgement in grading.judge(surface, known_payload,
                                   getattr(opts, "max_file_bytes", 2_000_000)):
        finding_key = (grading.shown_path(judgement.where, root), grading.evidence_of(judgement))
        if judgement.tier != CONFIRMED or finding_key not in reported:
            continue
        matched.add(finding_key)
        shown = finding_key[0]
        if judgement.hook is not None:
            removal.record_left(shown, f"the {judgement.subject} hook", A_HOOKS_DIRECTORY_FILE)
            continue
        entry = judgement.command.entry
        hook = _configured_hook_name(entry.key)
        if hook is None:
            _take_out_setting_value(root, entry, shown, known_payload, removal)
        elif hook not in hooks_handled:
            hooks_handled.add(hook)
            _take_out_configured_hook(root, surface, hook, shown, reported, known_payload, removal)
    removal.absent += sorted({path for path, _ in reported - matched})
    return removal


def _take_out_setting_value(root: Path, entry: ConfigEntry, shown: str, known_payload,
                            removal: SettingsRemoval) -> None:
    """Take one value of a setting out of the file it is set in, when the value itself carries a
    known payload. Takes the checkout, the entry, its file as the finding names it, the payload
    check and the record."""
    if not known_payload(entry.value or ""):
        removal.record_left(shown, entry.key, NOT_A_KNOWN_PAYLOAD)
        return
    source = Path(entry.source)
    if not _editable_in_checkout(root, source):
        removal.record_left(shown, entry.key, f"is set in {grading.shown_path(source, root)}, "
                                              "outside your checkout — remove it yourself")
        return
    _remove_value(source, entry.key, entry.value)
    pairs, unreadable = list_config_file(source)
    if unreadable is not None or (entry.key, entry.value) in pairs:
        removal.record_left(shown, entry.key, NOT_TAKEN_OUT)
        if unreadable is not None:
            removal.unread.append(grading.shown_path(source, root))
        return
    removal.stripped.append(grading.shown_path(source, root))


def _take_out_configured_hook(root: Path, surface: ExecSurface, hook: str, shown: str, reported,
                              known_payload, removal: SettingsRemoval) -> None:
    """Take a hook configured in git's settings out key by key, when every entry of it git reads for
    the repository is in the checkout and every command it names carries a known payload and was
    reported. Takes the checkout, the surface, the hook's name, its file as the finding names it,
    the reported findings, the payload check and the record."""
    subject = f"hook.{hook}"
    entries, unexamined = _entries_git_reads(surface)
    definition = [e for e in entries if _configured_hook_name(e.key) == hook]
    commands = [e for e in definition if e.key.lower().endswith(".command")]
    if unexamined:
        removal.record_left(shown, subject, NOT_READ)
        removal.unread.append(shown)
        removal.confirmed_hook_left = True
        return
    if not commands or not all(
            known_payload(e.value or "")
            and (grading.shown_path(Path(e.source), root), f"{e.key} = {e.value}") in reported
            for e in commands):
        removal.record_left(shown, subject, NOT_A_KNOWN_PAYLOAD)
        removal.confirmed_hook_left = True
        return
    outside = sorted({grading.shown_path(Path(e.source), root) for e in definition
                      if not _editable_in_checkout(root, Path(e.source))})
    if outside:
        removal.record_left(shown, subject, f"is also set in {', '.join(outside)}, outside your "
                                            "checkout — remove it yourself")
        removal.confirmed_hook_left = True
        return
    files = list(dict.fromkeys(Path(e.source) for e in definition))
    for config in files:
        for key in dict.fromkeys(e.key for e in definition if Path(e.source) == config):
            _remove_key(config, key)
        pairs, unreadable = list_config_file(config)
        if unreadable is not None or any(_configured_hook_name(k) == hook for k, _ in pairs):
            removal.record_left(grading.shown_path(config, root), subject, NOT_TAKEN_OUT)
            if unreadable is not None:
                removal.unread.append(grading.shown_path(config, root))
            removal.confirmed_hook_left = True
            return
    removal.stripped += [grading.shown_path(f, root) for f in files]


def _entries_git_reads(surface: ExecSurface) -> tuple[list[ConfigEntry], list[str]]:
    """Collect every configuration entry git reads for any worktree of the repository and for the
    operator: what the surface read, and the operator's system and global configuration with every
    file it includes. Takes the surface. Returns the entries and what could not be read."""
    probe = ExecSurface(surface.work_tree)
    entries = list(surface.entries)
    operator_files = operator_config.config_files()
    if operator_files is None:
        probe.unexamined.append("the operator's git configuration could not be listed")
    for config in operator_files or ():
        entries += read_config(config, probe)
    return entries, [*surface.unexamined, *probe.unexamined]


def _configured_hook_name(key: str) -> str | None:
    """Read the name of the configured hook a `hook.<name>.<variable>` key belongs to. Takes the
    key. Returns the name, or None when the key is not a configured hook's."""
    if key[:5].lower() != "hook.":
        return None
    name, dot, _variable = key[5:].rpartition(".")
    return name if dot else None


def _editable_in_checkout(root: Path, path: Path) -> bool:
    """Tell whether saw may change a file: a regular file inside the checkout, reached without a
    link. Takes the checkout and the file. Returns the answer."""
    return pathsafe.is_safe_write_target(path, root) and pathsafe.is_regular_file(path)


def _remove_value(config: Path, key: str, value: str | None) -> bool:
    """Take one value of a key out of a configuration file with git's own writer. Takes the file,
    the key and the value. Returns whether git took it out."""
    if value is None:
        return False
    res = run(None, ["config", "--file", str(config), "--fixed-value", "--unset-all", key, value],
              context=OPERATOR_CONFIG)
    return res is not None and res.returncode == 0


def _remove_key(config: Path, key: str) -> bool:
    """Take every value of a key out of a configuration file with git's own writer. Takes the file
    and the key. Returns whether git took them out."""
    res = run(None, ["config", "--file", str(config), "--unset-all", key], context=OPERATOR_CONFIG)
    return res is not None and res.returncode == 0

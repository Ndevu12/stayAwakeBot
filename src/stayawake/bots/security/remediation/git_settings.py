#!/usr/bin/env python3
"""Take out of a checkout the git settings and configured hooks that carry a known payload.

A setting goes as that one value. A hook configured in git's settings goes key by key, and only when
every entry of it that git reads for the repository is in the checkout and every command it names
carries a known payload and was reported. Each is judged again as it is acted on. Anything else
confirmed is left and named; no file is removed here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from stayawake.bots.security.matchers import git_exec_surface as grading
from stayawake.bots.security.models import CONFIRMED
from stayawake.bots.security.signatures import every_signature
from stayawake.lib.git import operator_config
from stayawake.lib.git.exec_surface import (HOOK_NAMES, ConfigEntry, ExecSurface, file_identity,
                                            list_config_file, read_exec_surface, repository_views)
from stayawake.lib.git.run import OPERATOR_CONFIG, run
from stayawake.lib.git.what_git_reads import repository_settings
from stayawake.utils import pathsafe

NOT_A_KNOWN_PAYLOAD = "is not a known payload on its own — review it"
NOT_READ = "could not be read in full, so it was left"
NOT_TAKEN_OUT = "could not be taken out"
A_HOOKS_DIRECTORY_FILE = ("is a file in the hooks directory, which saw fix does not remove — remove "
                          "it yourself")
NAMED_AFTER_AN_EVENT = "is named after a hook event, so saw fix does not change it — remove it yourself"
IN_A_SUBMODULE = "is in a submodule's settings, which saw fix does not change — remove it yourself"
NOT_READ_HERE = "is in a file git does not read for this repository, so saw fix leaves it — review it"
A_REQUIRED_FILTER = ("belongs to a filter git requires, so taking it out would stop git — remove the "
                     "filter yourself")


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
    every = every_signature(signatures)
    known_payload = grading.payload_check_for(every, holding_anywhere=True)
    matched, hooks_handled = set(), set()
    for judgement in grading.judge(surface, grading.payload_check_for(every),
                                   getattr(opts, "max_file_bytes", 2_000_000)):
        finding_key = (grading.shown_path(judgement.where, root), grading.evidence_of(judgement))
        if judgement.tier != CONFIRMED or finding_key not in reported or finding_key in matched:
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
            _take_out_configured_hook(root, surface, entry, shown, reported, known_payload, removal)
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
    driver = _filter_driver(entry.key)
    if driver is not None and _filter_is_required(root, driver):
        removal.record_left(shown, entry.key, A_REQUIRED_FILTER)
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


def _take_out_configured_hook(root: Path, surface: ExecSurface, judged: ConfigEntry, shown: str,
                              reported, known_payload, removal: SettingsRemoval) -> None:
    """Take a hook configured in git's settings out key by key, events first, when every entry of it in
    the files git reads for the repository's views and for the operator is in the checkout, none of
    those files is also read by a submodule, and every command it names carries a known payload and
    was reported. Takes the checkout, the surface, the entry the finding names, its file as the
    finding names it, the reported findings, the payload check and the record."""
    hook = _configured_hook_name(judged.key)
    subject = f"hook.{hook}"
    removal.confirmed_hook_left = True
    if hook.lower() in HOOK_NAMES:
        removal.record_left(shown, subject, NAMED_AFTER_AN_EVENT)
        return
    repository_files = _files_git_reads(repository_views(root))
    submodule_files = _files_git_reads(_submodule_places(surface))
    operator_files = operator_config.config_files()
    if repository_files is None or submodule_files is None or operator_files is None:
        removal.record_left(shown, subject, NOT_READ)
        removal.unread.append(shown)
        return
    read_by_submodules = {file_identity(f) for f in submodule_files}
    if file_identity(Path(judged.source)) not in {file_identity(f) for f in repository_files}:
        removal.record_left(shown, subject, IN_A_SUBMODULE if file_identity(Path(judged.source))
                            in read_by_submodules else NOT_READ_HERE)
        return
    entries, unreadable = _entries_in(dict.fromkeys([*repository_files, *operator_files]))
    if unreadable:
        removal.record_left(shown, subject, NOT_READ)
        removal.unread.append(shown)
        return
    spelled = {file_identity(Path(c.entry.source)): grading.shown_path(Path(c.entry.source), root)
               for c in surface.commands}

    def shown_as_reported(source) -> str:
        return spelled.get(file_identity(Path(source)), grading.shown_path(Path(source), root))
    definition = [e for e in entries if _configured_hook_name(e.key) == hook]
    commands = [e for e in definition if e.key.lower().endswith(".command")]
    if any(file_identity(Path(e.source)) in read_by_submodules for e in definition):
        removal.record_left(shown, subject, IN_A_SUBMODULE)
        return
    if not commands or not all(known_payload(e.value or "") for e in commands):
        removal.record_left(shown, subject, NOT_A_KNOWN_PAYLOAD)
        return
    unreported = sorted({shown_as_reported(e.source) for e in commands
                         if (shown_as_reported(e.source), f"{e.key} = {e.value}") not in reported})
    if unreported:
        removal.record_left(shown, subject, f"also runs a command set in {', '.join(unreported)} that "
                                            "this run did not report — review it")
        return
    outside = sorted({grading.shown_path(Path(e.source), root) for e in definition
                      if not _editable_in_checkout(root, Path(e.source))})
    if outside:
        removal.record_left(shown, subject, f"is also set in {', '.join(outside)}, outside your "
                                            "checkout — remove it yourself")
        return
    files = list(dict.fromkeys(Path(e.source) for e in definition))
    for in_this_pass in (_is_event_key, lambda k: not _is_event_key(k) and not _is_command_key(k),
                         _is_command_key):
        for config in files:
            for key in dict.fromkeys(e.key for e in definition
                                     if Path(e.source) == config and in_this_pass(e.key)):
                _remove_key(config, key)
        still_set, unreadable = _hook_keys_left(files, hook, in_this_pass)
        if still_set or unreadable:
            changed = [grading.shown_path(f, root) for f in files if f not in still_set + unreadable]
            why = NOT_TAKEN_OUT + (f" in full; saw changed {', '.join(changed)}" if changed else "")
            removal.record_left(shown, subject, why)
            removal.unread += [grading.shown_path(f, root) for f in unreadable]
            return
    removal.confirmed_hook_left = False
    removal.stripped += [grading.shown_path(f, root) for f in files]


def _submodule_places(surface: ExecSurface) -> list[Path]:
    """List where git runs for each submodule the surface read. Takes the surface. Returns each
    submodule's working tree, or its git directory when it has none."""
    own = {file_identity(d) for d in (surface.git_dir, surface.common_dir) if d is not None}
    return [surface.work_trees.get(d, d) for d in surface.git_dirs if file_identity(d) not in own]


def _files_git_reads(places: list[Path]) -> list[Path] | None:
    """Ask git which settings files it reads at each place, in the repository's own scopes. Takes the
    places. Returns the files, each once, or None when git did not answer for every place."""
    found: dict = {}
    for place in places:
        answer = repository_settings(place)
        if answer is None:
            return None
        for path in answer.files:
            found.setdefault(file_identity(path), path)
    return list(found.values())


def _entries_in(files) -> tuple[list[ConfigEntry], list[Path]]:
    """Read the entries of settings files, each on its own, without following its includes. Takes the
    files. Returns their entries in order and the files that could not be read."""
    entries: list[ConfigEntry] = []
    unreadable: list[Path] = []
    for config in files:
        pairs, why = list_config_file(Path(config))
        if why is not None:
            unreadable.append(Path(config))
        entries += [ConfigEntry(key, value, Path(os.path.realpath(config))) for key, value in pairs]
    return entries, unreadable


def _filter_driver(key: str) -> str | None:
    """Read the filter driver a `filter.<driver>.clean|smudge|process` key belongs to. Takes the key.
    Returns the driver, or None when the key is not one of a filter's commands."""
    if key[:7].lower() != "filter.":
        return None
    driver, dot, variable = key[7:].rpartition(".")
    return driver if dot and variable.lower() in ("clean", "smudge", "process") else None


def _filter_is_required(root: Path, driver: str) -> bool:
    """Ask git whether a filter driver is required in a checkout. Takes the checkout and the driver.
    Returns the answer, True when git could not say."""
    res = run(root, ["config", "--type=bool", "--get", f"filter.{driver}.required"])
    if res is None or res.returncode not in (0, 1):
        return True
    return res.stdout.strip() == "true"


def _hook_keys_left(files: list[Path], hook: str, in_this_pass) -> tuple[list[Path], list[Path]]:
    """Read files back for keys of a configured hook. Takes the files, the hook's name and which of
    its keys to look for. Returns the files still holding one and the files that could not be read."""
    still_set, unreadable = [], []
    for config in files:
        pairs, why = list_config_file(config)
        if why is not None:
            unreadable.append(config)
        elif any(_configured_hook_name(k) == hook and in_this_pass(k) for k, _ in pairs):
            still_set.append(config)
    return still_set, unreadable


def _is_event_key(key: str) -> bool:
    """Tell whether a configured hook's key names an event it runs on. Takes the key."""
    return key.lower().endswith(".event")


def _is_command_key(key: str) -> bool:
    """Tell whether a configured hook's key names the command it runs. Takes the key."""
    return key.lower().endswith(".command")


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

#!/usr/bin/env python3
"""Git execution-surface matcher: grades what git would run for a repository — configured
commands, hooks and configuration includes — and reports each at the tier it warrants."""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from stayawake.bots.security import hookscript
from stayawake.bots.security.hygiene.mechanism import (FETCH_OR_DECODE_THEN_RUN, _other_writable,
                                                       _under_scratch)
from stayawake.bots.security.matchers import command_shape
from stayawake.bots.security.matchers.base import Matcher, build_any_payload_check
from stayawake.bots.security.models import (CONFIRMED, HEURISTIC, INFORMATIONAL, Finding,
                                            Severity)
from stayawake.bots.security.obfuscation import analyze_file
from stayawake.lib.git import exec_keys
from stayawake.lib.git.exec_surface import Command, ExecSurface, Hook, read_exec_surface
from stayawake.utils import pathsafe

PAYLOAD_SIGNATURE = "git-exec-payload"
SUSPICIOUS_SIGNATURE = "git-exec-suspicious"
RUNS_SIGNATURE = "git-exec-runs"
_TIER_SIGNATURE = {CONFIRMED: PAYLOAD_SIGNATURE, HEURISTIC: SUSPICIOUS_SIGNATURE,
                   INFORMATIONAL: RUNS_SIGNATURE}

_MAX_POINTED_FILES = 8
_MAX_PROGRAM_TOKENS = 2
_EXT_ALWAYS = frozenset({"always"})

_OPTS = r"(?:-[\w:=.-]{1,40}\s{1,8}){0,4}"
_INLINE_INTERPRETER_CODE = re.compile(
    r"(?<![\w.-])(?:"
    rf"(?:node|nodejs|bun)(?:\.exe)?\s{{1,8}}{_OPTS}(?:-e|--eval|-p|--print)(?![\w-])"
    r"|deno\s{1,8}eval\b"
    rf"|python[0-9.]{{0,5}}(?:\.exe)?\s{{1,8}}{_OPTS}-c(?![\w-])"
    rf"|(?:perl|ruby)\s{{1,8}}{_OPTS}-[a-zA-Z]{{0,4}}[eE](?![\w-])"
    rf"|php\s{{1,8}}{_OPTS}-r(?![\w-])"
    rf"|osascript\s{{1,8}}{_OPTS}-e(?![\w-])"
    rf"|(?:sh|bash|zsh|dash|ksh)\s{{1,8}}{_OPTS}-[a-zA-Z]{{0,4}}c(?![\w-])"
    rf"|(?:pwsh|powershell)(?:\.exe)?\s{{1,8}}{_OPTS}-(?:c|command|e|ec|encodedcommand)(?![\w-])"
    r")", re.IGNORECASE)
_DECODE_THEN_EVAL = re.compile(
    r"\b(?:eval|exec|Function|execSync|runInThisContext)\s{0,8}\(\s{0,8}[^;)\n]{0,64}?"
    r"\b(?:atob|Buffer\.from|b64decode|fromCharCode|decompress|fromhex|unhexlify)\b")
_FETCHED = (r"(?:urlopen|urlretrieve|requests\.get|https?\.get|fetch|DownloadString|DownloadFile"
            r"|Invoke-WebRequest|Invoke-RestMethod|recv|file_get_contents|curl|wget)")
_EVALUATOR = r"(?:eval|exec|Function|IEX|Invoke-Expression|execSync|runInThisContext)"
_FETCH_THEN_EVAL = re.compile(
    rf"\b{_EVALUATOR}\b[^\n]{{0,256}}?\b{_FETCHED}\b|\b{_FETCHED}\b[^\n]{{0,256}}?\b{_EVALUATOR}\b",
    re.IGNORECASE)
_SUBSTITUTED_FETCH = re.compile(
    r"\b(?:sh|bash|zsh|dash|ksh)\s{1,8}-[a-zA-Z]{0,4}c\s{1,8}[\"']?\$\(\s{0,8}(?:curl|wget)\b",
    re.IGNORECASE)
_SPLIT_QUOTES = re.compile(r"''|\"\"|\\(?=\w)")
_SCRIPT_SHEBANG = re.compile(r"^#!.{0,200}?\b(?:node|nodejs|bun|deno)\b")


@dataclass(frozen=True)
class Judgement:
    """How one thing git runs is graded, and what a remediation would remove."""

    tier: str
    where: Path
    subject: str
    reason: str
    value: str | None = None
    command: Command | None = None
    hook: Hook | None = None
    payload_files: tuple[Path, ...] = ()


def _tokens(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _within(path: Path, roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _program_paths(text: str, work_tree: Path) -> list[Path]:
    """Name the program and the script a command line runs. Takes the command and the directory
    git runs it from. Returns those that are written as paths."""
    found = []
    for token in _tokens(text):
        if token.startswith("-") or "=" in token.split("/", 1)[0]:
            continue
        if "/" in token or token.startswith("~"):
            expanded = os.path.expanduser(token)
            found.append(Path(os.path.normpath(expanded if os.path.isabs(expanded)
                                               else work_tree / expanded)))
        else:
            found.append(None)
        if len(found) >= _MAX_PROGRAM_TOKENS:
            break
    return [p for p in found if p is not None]


def _pointed_files(text: str, surface: ExecSurface) -> list[Path]:
    """Find the files a command line names inside the repository, its git directories or the
    home directory. Takes the command and the surface. Returns their resolved paths."""
    roots = [Path(os.path.realpath(p)) for p in
             [surface.work_tree, *surface.git_dirs, Path.home()]]
    found: list[Path] = []
    for token in _tokens(text):
        for part in token.split("="):
            if not part or part.startswith("-"):
                continue
            if "/" not in part and "." not in part and not (surface.work_tree / part).is_file():
                continue
            expanded = os.path.expanduser(part)
            candidate = Path(expanded if os.path.isabs(expanded) else surface.work_tree / expanded)
            real = Path(os.path.realpath(candidate))
            if _within(real, roots) and pathsafe.is_regular_file(real) and real not in found:
                found.append(real)
        if len(found) >= _MAX_POINTED_FILES:
            break
    return found


def _in_git_dir_outside_hooks(path: Path, surface: ExecSurface) -> bool:
    real = Path(os.path.realpath(path))
    for git_dir in surface.git_dirs:
        root = Path(os.path.realpath(git_dir))
        if _within(real, [root]) and not _within(real, [root / "hooks"]):
            return True
    return False


def _unsafe_location(path: Path, surface: ExecSurface) -> str | None:
    """Say why a program or directory sits somewhere others can plant code. Takes the path and the
    surface. Returns the reason, or None."""
    inside = _within(Path(os.path.realpath(path)),
                     [Path(os.path.realpath(p)) for p in [surface.work_tree, *surface.git_dirs]])
    if _under_scratch(path) and not inside:
        return "under a shared scratch directory"
    if _other_writable(path) or _other_writable(path.parent):
        return "in a world-writable directory"
    if _in_git_dir_outside_hooks(path, surface):
        return "inside the git directory, outside its hooks"
    return None


class _Grader:
    """Grade one surface against the confirmed payload fingerprints."""

    def __init__(self, surface: ExecSurface, payload_check, max_bytes: int):
        self.surface = surface
        self.payload_check = payload_check
        self.max_bytes = max_bytes

    def _payload_in_file(self, path: Path) -> str | None:
        try:
            if path.stat().st_size > self.max_bytes:
                return None
        except OSError:
            return None
        text = pathsafe.read_regular_text(path)
        return self.payload_check(text) if text else None

    def _fetches_or_decodes(self, path: Path) -> bool:
        """Whether a program file downloads or decodes code and runs it, by the standard a hook is
        judged by. Takes the file. Returns False when it cannot be read or is not text."""
        try:
            if path.stat().st_size > self.max_bytes:
                return False
        except OSError:
            return False
        text = pathsafe.read_regular_text(path) or ""
        if "\0" in text:
            return False
        return any(FETCH_OR_DECODE_THEN_RUN.search(_SPLIT_QUOTES.sub("", line))
                   for line in text.splitlines() if not line.lstrip().startswith("#"))

    def command(self, c: Command) -> Judgement | None:
        key, where, value = c.entry.key, c.entry.source, c.entry.value
        rule, text = c.rule, c.command
        if rule.runs == exec_keys.ENABLES_TRANSPORT:
            if (value or "").strip().lower() in _EXT_ALWAYS:
                return Judgement(HEURISTIC, where, key, "switches on a transport that runs a "
                                 "command line", value, c)
            return None
        if rule.runs == exec_keys.HOOKS_DIRECTORY:
            if not value:
                return None
            directory = Path(os.path.normpath(os.path.expanduser(value) if os.path.isabs(
                os.path.expanduser(value)) else self.surface.work_tree / value))
            why = _unsafe_location(directory, self.surface)
            if why:
                return Judgement(HEURISTIC, where, key, f"runs hooks from a directory {why}",
                                 value, c)
            return Judgement(INFORMATIONAL, where, key, "runs hooks from this directory",
                             value, c)
        if not text:
            return None
        hit = self.payload_check(text)
        if hit:
            return Judgement(CONFIRMED, where, key, f"its command matches {hit}", value, c)
        carriers = []
        for path in _pointed_files(text, self.surface):
            found = self._payload_in_file(path) or (
                "a program that downloads or decodes code and runs it" if rule.fires_on_its_own
                and self._fetches_or_decodes(path) else None)
            if found:
                carriers.append((path, found))
        if carriers:
            return Judgement(CONFIRMED, where, key,
                             f"runs a file that matches {carriers[0][1]}", value, c,
                             payload_files=tuple(p for p, _ in carriers))
        joined = _SPLIT_QUOTES.sub("", text)
        fetch_or_decode = bool(FETCH_OR_DECODE_THEN_RUN.search(joined)
                               or _DECODE_THEN_EVAL.search(joined)
                               or _FETCH_THEN_EVAL.search(joined)
                               or _SUBSTITUTED_FETCH.search(joined))
        if rule.fires_on_its_own and (fetch_or_decode
                                      or command_shape.feeds_a_download_to_a_runner(text)):
            return Judgement(CONFIRMED, where, key, "git runs it on its own and it downloads or "
                             "decodes code and runs it", value, c)
        reasons = []
        if fetch_or_decode:
            reasons.append("downloads or decodes code and runs it")
        if rule.runs == exec_keys.EXT_TRANSPORT:
            reasons.append("rewrites a remote address into a command line")
        if rule.fires_on_its_own:
            reasons += [f"git runs it on its own and {why}" for why in command_shape.not_plain(text)]
            if not reasons:
                reasons.append("git runs a program this repository names, on its own")
        elif not key.lower().startswith("alias.") and _INLINE_INTERPRETER_CODE.search(joined):
            reasons.append("hands code to an interpreter inline")
        for program in _program_paths(text, self.surface.work_tree):
            why = _unsafe_location(program, self.surface)
            if why:
                reasons.append(f"runs a program {why}")
                break
        if reasons:
            return Judgement(HEURISTIC, where, key, "; ".join(reasons), value, c)
        return Judgement(INFORMATIONAL, where, key, "git runs this command", value, c)

    def hook(self, hook: Hook) -> Judgement | None:
        try:
            if hook.path.stat().st_size > self.max_bytes:
                return Judgement(HEURISTIC, hook.path, hook.name, "hook is too large to read",
                                 hook=hook)
        except OSError:
            return None
        text = pathsafe.read_regular_text(hook.path)
        if text is None:
            return None
        hit = self.payload_check(text)
        if hit:
            return Judgement(CONFIRMED, hook.path, hook.name, f"hook matches {hit}", hook=hook,
                             payload_files=(hook.path,))
        live = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        if hook.runs and any(FETCH_OR_DECODE_THEN_RUN.search(line) for line in live):
            return Judgement(CONFIRMED, hook.path, hook.name,
                             "hook downloads or decodes code and runs it", hook=hook,
                             payload_files=(hook.path,))
        if not hook.runs:
            return None
        if hookscript.claims_ours(text):
            if hookscript.is_pristine(text):
                return None
            return Judgement(HEURISTIC, hook.path, hook.name, "saw's own hook has been altered",
                             hook=hook)
        if _SCRIPT_SHEBANG.search(text):
            verdict = analyze_file(text, ".js")
            if verdict:
                return Judgement(HEURISTIC, hook.path, hook.name,
                                 f"hook is obfuscated ({verdict.reason})", hook=hook)
        return Judgement(INFORMATIONAL, hook.path, hook.name, "git runs this hook", hook=hook)

    def includes(self) -> list[Judgement]:
        found = []
        for include in self.surface.includes:
            why = _unsafe_location(include.target, self.surface)
            if why and not _in_git_dir_outside_hooks(include.target, self.surface):
                found.append(Judgement(HEURISTIC, include.source, "include",
                                       f"pulls configuration from a file {why}",
                                       str(include.target)))
        return found


def judge(surface: ExecSurface, payload_check, max_bytes: int) -> list[Judgement]:
    """Grade everything on a surface. Takes the surface, a `check(text) -> signature id | None`
    over the confirmed payload fingerprints, and the largest file to read. Returns one judgement
    per graded entry, in surface order."""
    grader = _Grader(surface, payload_check, max_bytes)
    out = [j for j in map(grader.command, surface.commands) if j is not None]
    out += [j for j in map(grader.hook, surface.hooks) if j is not None]
    return out + grader.includes()


def payload_check_for(signatures) -> object:
    """Build the confirmed-payload check the grading uses. Takes every signature. Returns it."""
    return build_any_payload_check([s for s in signatures if s.get("matcher") == "content"])


def _shown(path: Path, root: Path) -> str:
    try:
        return str(Path(os.path.abspath(path)).relative_to(os.path.abspath(root)))
    except ValueError:
        return str(path).replace(str(Path.home()), "~", 1)


class GitExecSurfaceMatcher(Matcher):
    handles = "git-exec-surface"

    def scan(self, target, signatures, all_signatures=None):
        by_id = {s["id"]: s for s in signatures}
        if (getattr(target, "source", "") != "local" or getattr(target, "names_one_file", False)
                or getattr(target, "within", None) or not by_id):
            return []
        surface = read_exec_surface(target.root)
        if surface is None:
            return []
        target.read_errors.extend(f"git configuration {why}" for why in surface.unexamined)
        max_bytes = getattr(target.opts, "max_file_bytes", 2_000_000)
        findings = []
        for j in judge(surface, payload_check_for(all_signatures or signatures), max_bytes):
            sig = by_id.get(_TIER_SIGNATURE[j.tier])
            if sig is None:
                continue
            evidence = f"{j.subject} = {j.value}" if j.value is not None else j.subject
            findings.append(Finding(
                signature_id=sig["id"], category=sig["category"],
                severity=Severity.parse(sig["severity"]), path=_shown(j.where, target.root),
                description=f"{sig['description']} {j.reason[:1].upper()}{j.reason[1:]}.",
                remediation=sig.get("remediation", "manual"), evidence=evidence,
                vector=sig["category"],
                payload_paths=tuple(_shown(p, target.root) for p in j.payload_files)))
        return findings

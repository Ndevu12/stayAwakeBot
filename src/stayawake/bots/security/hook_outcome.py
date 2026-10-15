#!/usr/bin/env python3
"""What `saw hook` did at each place, and the lines that tell the person what it means for them."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import textsafe

IN_PLACE = "in place"
NOTED = "noted"
UPDATED = "updated"
RESTORED = "restored"
REPAIRED = "repaired"
SET_ASIDE = "set aside"
PRESERVED = "preserved"
LEFT = "left"
CHAINED = "chained"
UNVERIFIED = "could not verify"
UNREAD = "could not read"
SETTLED = frozenset({IN_PLACE, NOTED, UPDATED, RESTORED, REPAIRED, SET_ASIDE, PRESERVED, LEFT, CHAINED})

WRITTEN = "written"
OUT_OF_DATE = "out of date"
PUT_BACK = "put back"
CHANGED = "changed"
NOT_SAWS = "not saw's"
BROKEN_LINK = "broken link"
YOURS_RUNS_AFTER = "yours runs after saw's"
REPOSITORYS_OWN = "the repository's own"
YOUR_PUSH_HOOK_KEPT = "your push hook kept"
RUNS_FROM_ELSEWHERE = "runs hooks from elsewhere"
HOOKS_FOLDER_UNKNOWN = "hooks folder unknown"
NOT_PUT_IN_PLACE = "not put in place"
SAVED_COPY_IN_THE_WAY = "saved copy in the way"
RECORD_NOT_WRITTEN = "record not written"
SETTINGS_NOT_SET = "settings not set"
SETTINGS_SWITCHED_OFF = "settings switched off"
HOOKS_FOLDER_REFUSED = "hooks folder refused"
STILL_IN_SETTINGS = "still in settings"


@dataclass(frozen=True)
class Action:
    """One thing `saw hook` did, or could not do, at one place: its state, the place, what kind of
    thing it was, the repository it was in, and the reason a folder git uses was refused."""
    state: str
    path: Path
    kind: str = ""
    repository: Path | None = None
    reason: str = ""


def _shown(paths: list[Path]) -> str:
    home = os.path.expanduser("~")
    shown = []
    for path in paths:
        plain = textsafe.plain(str(path), limit=4096)
        shown.append("~" + plain[len(home):] if plain == home or plain.startswith(home + os.sep) else plain)
    return ", ".join(shown)


def _where(repositories: list[Path], into: str) -> str:
    return f" {into} {_shown(repositories)}" if repositories else ""


def lines(actions: list[Action], *, again: str, removing: bool = False) -> list[tuple[str, str]]:
    """Say what was done and what is left, one line for each kind, naming only the repositories and
    folders the person acts on. Takes the actions, the command that tries again, and whether saw's
    hooks were being removed. Returns each line with its level: ok, warn or dim."""
    in_repositories: dict[str, list[Path]] = {}
    elsewhere: set[str] = set()
    refused: list[Action] = []
    still_set: list[str] = []
    for a in actions:
        if a.kind == HOOKS_FOLDER_REFUSED:
            refused.append(a)
        elif a.kind == STILL_IN_SETTINGS:
            still_set.append(str(a.path))
        elif a.repository is None:
            elsewhere.add(a.kind)
        else:
            repos = in_repositories.setdefault(a.kind, [])
            if not any(str(a.repository) == str(r) for r in repos):
                repos.append(a.repository)
    out: list[tuple[str, str]] = []

    def say(kind: str, text, level: str) -> None:
        for repos in ([[]] if kind in elsewhere else []) + ([in_repositories[kind]] if kind in in_repositories else []):
            line = (text(repos) if callable(text) else text, level)
            if line not in out:
                out.append(line)

    say(CHANGED, "One of saw's hooks had been changed; the changed copy was moved aside and kept. "
                 "Run `saw audit` to check this machine.", "warn")
    say(NOT_SAWS, "Something that was not saw's stood where saw's hooks run; it was moved aside and "
                  "kept. Run `saw audit` to check this machine.", "warn")
    say(NOT_PUT_IN_PLACE, lambda repos: (
        f"Not all of saw's hooks could be removed{_where(repos, 'from')}. Run `{again}` to try again."
        if removing else
        f"Not all of saw's hooks could be put in place{_where(repos, 'in')}. Run `{again}` to try again."),
        "warn")
    say(HOOKS_FOLDER_UNKNOWN, lambda repos: (
        f"git reports an error in {_shown(repos)}, so saw's hooks were not "
        f"{'removed from' if removing else 'put'} there. Once git works there again, run `{again}`."), "warn")
    say(SAVED_COPY_IN_THE_WAY, lambda repos: (
        f"In {_shown(repos) or 'a repository'}, one of your hooks also has a saved copy ending in .local, "
        "so saw's hooks were not added. Keep one of the two, then run `saw hook install` again."), "warn")
    say(RECORD_NOT_WRITTEN, f"What was installed was not recorded. Run `{again}` again so "
                            "`saw hook repair` and `saw hook uninstall` can find it.", "warn")
    if still_set:
        commands = " and ".join(f"`git config --global --remove-section {name}`" for name in still_set)
        out.append((f"saw's scan is still set in your git settings. Remove it with {commands}.", "warn"))
    say(BROKEN_LINK, "A link that led nowhere stood where one of saw's hooks goes; it was moved aside "
                     "and kept.", "dim")
    say(OUT_OF_DATE, "saw's hooks were brought up to date.", "dim")
    say(PUT_BACK, "saw's hooks that were missing were put back.", "dim")
    say(YOURS_RUNS_AFTER, "Your own hooks keep running, after saw's.", "dim")
    say(REPOSITORYS_OWN, lambda repos: (
        f"Hooks of their own in {_shown(repos)} were left as they are." if repos
        else "Hooks that are not saw's were left as they are."), "dim")
    say(YOUR_PUSH_HOOK_KEPT, lambda repos: (
        f"Your own push hook was kept as it is{_where(repos, 'in')}, so saw does not check pushes there."),
        "dim")
    say(RUNS_FROM_ELSEWHERE, lambda repos: (
        f"saw's hooks were not {'removed from' if removing else 'put in'} {_shown(repos)}: git runs "
        "their hooks from another folder."), "dim")
    say(SETTINGS_NOT_SET, "saw's scan could not be set in your git settings, so it runs only where "
                          "saw's hooks are in place.", "dim")
    say(SETTINGS_SWITCHED_OFF, "saw's scan is switched off in your git settings, so it was left off.", "dim")
    for a in refused:
        out.append((f"saw's hooks were not put in {_shown([a.path])}, the folder git runs every "
                    f"repository's hooks from: it {a.reason}.", "dim"))
    return out

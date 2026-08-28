#!/usr/bin/env python3
"""Self-hosted GitHub Actions runner persistence — the worm's most durable, rotation-surviving foothold."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from .models import HygieneIssue, _WIPER_NOTE

#
# Shai-Hulud 2.0 / Mini registers the compromised host as a self-hosted GitHub Actions
# runner (reported name SHA1HULUD) so attacker workflows keep executing on the host —
# surviving credential rotation and CI re-provisioning (T1543/T1546). Detection: an installed
# runner dir with a `.runner` config, and/or a registered `actions.runner.*` service. (The
# rotation-wiper OS service, gh-token-monitor, is a SEPARATE persistence artifact owned by
# check_persistence() below.) Every probe degrades to a no-op when a tool/path is absent.

_RUNNER_DIR_CANDIDATES = (
    Path.home() / "actions-runner",
    Path.home() / "runner",
    Path("/opt/actions-runner"),
    Path("/actions-runner"),
)


def user_runner_dirs() -> tuple[Path, ...]:
    """The HOME-relative self-hosted-runner install dirs — the user-owned subset of the candidates
    scanned above. Single source of truth for the persistence-coverage probe: a dir we read
    to detect a runner foothold is one we must be able to read to certify the host clean. The
    system paths (/opt, /) are best-effort, so their unreadability is N/A (a system install needs
    root, outside the npm-worm model)."""
    home = Path.home()
    return tuple(d for d in _RUNNER_DIR_CANDIDATES if d == home or home in d.parents)


def _installed_runner_dir() -> Path | None:
    for d in _RUNNER_DIR_CANDIDATES:
        try:
            if (d / ".runner").is_file():
                return d
        except OSError:
            continue
    return None


def _is_runner_label(name: str) -> bool:
    return name.startswith("actions.runner.")


def _label_shaped(field: str) -> bool:
    """What a service label looks like to both managers: dotted, alphabetic, and not a path. Each
    clause replaced a value the read column actually held once that column had moved."""
    if "." not in field or field.startswith(".") or field.endswith("."):
        return False
    if any(bad in field for bad in ("/", "\\", "=")):
        return False
    return any(part.isalpha() for part in field.replace("-", "_").split("."))


_LAUNCHCTL = ["launchctl", "list"]
_SYSTEMCTL_SCOPES = (["--system"], ["--user"])
_SYSTEMCTL_VERBS = ("list-units", "list-unit-files")


def _run_tool(cmd: list[str]) -> str | None:
    """The tool's stdout, or None when it is absent or refuses. One helper, and `errors="replace"`
    so a byte a locale cannot decode is not the difference between an answer and silence."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _launchctl_fields(out: str) -> list[str]:
    """The field of each `launchctl list` row that the label is expected to occupy. The extractor
    and its discriminator both read THIS, so neither can drift into reading a different column."""
    return [parts[-1] for parts in (ln.split() for ln in out.splitlines()[1:]) if parts]


def _systemctl_fields(out: str) -> list[str]:
    return [parts[0] for parts in (ln.split() for ln in out.splitlines()) if parts]


def _service_listings() -> list[tuple[str, list[str], Callable[[str], list[str]]]]:
    """(name, argv, field selector) for EVERY listing the check reads.

    The check and its discriminator walk this one list, so a scope the check depends on cannot end
    up unchecked."""
    listings: list[tuple[str, list[str], Callable[[str], list[str]]]] = [
        ("launchctl", _LAUNCHCTL, _launchctl_fields)]
    for scope in _SYSTEMCTL_SCOPES:
        for verb in _SYSTEMCTL_VERBS:
            listings.append((f"systemctl {scope[0].lstrip('-')} {verb}",
                             ["systemctl", *scope, verb, "--type=service", "--all",
                              "--no-legend", "--plain"], _systemctl_fields))
    return listings


def _runner_services() -> list[str]:
    """Best-effort list of registered self-hosted-runner service labels on this host.

    Reads launchd (macOS) and systemd (Linux) — the latter in BOTH system and user scope and
    via `list-unit-files` too, so an installed-but-not-started unit is seen, not just running
    ones. Absent tools / missing session buses degrade to a no-op. Order-preserving de-dup."""
    found: list[str] = []
    for _name, cmd, fields in _service_listings():
        out = _run_tool(cmd)
        if out is not None:
            found += [f for f in fields(out) if _is_runner_label(f)]
    return list(dict.fromkeys(found))            # de-dup, preserve order


def services_predicate() -> str | None:
    """Prove the label extractor is still reading the column labels are in.

    It reads the SAME listings through the SAME field selection the check uses: a discriminator that
    re-derives the parse drifts from it, and the drift shows up as a miss or a false alarm.

    Two things are deliberately NOT blocks: a host with no service manager, where a service-
    registered runner cannot exist, and one listing that answers with no rows, which an idle user
    manager legitimately does."""
    answered = 0
    with_rows = 0
    for name, cmd, fields in _service_listings():
        out = _run_tool(cmd)
        if out is None:
            continue
        answered += 1
        rows = fields(out)
        if not rows:
            continue
        with_rows += 1
        if sum(_label_shaped(f) for f in rows) * 2 <= len(rows):
            return (f"This host's `{name}` output is not in a form this check can read, so a "
                    "runner registered as a service would not have been seen.")
    if answered and not with_rows:
        return ("The service managers on this host answered with nothing to read, so a runner "
                "registered as a service would not have been seen.")
    return None


def check_runner_persistence() -> list[HygieneIssue]:
    """Detect a self-hosted runner install/registration on this host.

    SAFETY: the remediation must NOT tell the user to rotate credentials first — rotating
    while the runner persistence is still live can trip the reported home-dir wiper.
    Advise isolate → runner offline + registration/service removed → rebuild → THEN rotate."""
    runner_dir = _installed_runner_dir()
    runner_services = _runner_services()

    if runner_dir is None and not runner_services:
        return []
    where = []
    if runner_dir is not None:
        where.append(f"install at {runner_dir} (.runner config present)")
    if runner_services:
        where.append(f"registered service(s): {', '.join(sorted(runner_services))}")
    return [HygieneIssue(
        id="self-hosted-runner-persistence",
        severity="warning",
        title="Self-hosted GitHub Actions runner registered on this host",
        # Conditional framing — a legitimately-operated runner is not itself malicious; we
        # flag it because an UNEXPECTED one is the worm's persistence (reported name SHA1HULUD).
        detail="A self-hosted runner is installed/registered — " + "; ".join(where)
               + ". If you did not set this up, it runs attacker workflows and survives credential "
               "rotation (reported runner name SHA1HULUD).",
        remediation="Do NOT rotate credentials first. Isolate the host, remove the registration "
                    "(./config.sh remove) and service, rebuild from a known-clean image, then "
                    f"rotate LAST: {_WIPER_NOTE}.",
    )]

#!/usr/bin/env python3
"""Credential-exposure hygiene: a cached GitHub token in the OS keychain (macOS Keychain / Linux
libsecret-gnome-keyring / Windows Credential Manager) or a plaintext `~/.git-credentials`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from stayawake.utils import textsafe
from .models import HygieneIssue, _WIPER_NOTE

CREDENTIAL_HYGIENE_DOC = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/"
                          "docs/explanation/credential-hygiene.md")


@dataclass(frozen=True)
class KeychainStore:
    """The OS credential store that holds a cached github.com credential on a given platform — its
    human name (for the finding's prose) and the platform-correct removal command. The store is
    encrypted and recommended on every platform; only the name and the delete verb differ."""
    name: str
    delete_command: str


_MACOS_STORE = KeychainStore(
    "the macOS login Keychain",
    "security delete-internet-password -s github.com        # remove the cached entry")
_LINUX_STORE = KeychainStore(
    "the system secret store (libsecret / gnome-keyring)",
    "secret-tool clear server github.com                    # remove it from libsecret/gnome-keyring")
_WINDOWS_STORE = KeychainStore(
    "Windows Credential Manager",
    "cmdkey /delete:git:https://github.com                  # remove it from Windows Credential Manager")

_SYSTEM_CONFIG_PREFIXES = ("/library/developer/commandlinetools/",
                           "/applications/xcode.app/", "/usr/local/git/")
_SYSTEM_CONFIG_EXACT = ("/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig")


def _run(cmd: list[str], *, input_text: str | None = None, timeout: int = 10,
         capture: bool = True) -> subprocess.CompletedProcess | None:
    """Read-only subprocess helper. Returns None (never raises) when the tool is missing / errors /
    times out, so every probe degrades gracefully on a machine that lacks git, `security`, or gh.

    `capture=False` DISCARDS the child's stdout/stderr to /dev/null and exposes only the exit code —
    used for a probe whose tool would print a live SECRET (libsecret's `secret-tool`), so the token is
    written to the child's null sink and never enters saw's memory. saw reads presence, never
    the secret, on every platform."""
    try:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if not capture:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  text=True, timeout=timeout, input=input_text, env=env)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, env=env)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None


_IMPOSSIBLE_KEYCHAIN_HOST = "saw-selftest-no-such-host.invalid"


def keychain_predicate() -> str | None:
    """Ask the keychain for something that cannot be there, and require it to say no.

    Presence is read from an exit code, so a tool that is not answering the question returns the same
    "no" a clean host does. A query for a name that cannot exist must fail; if it succeeds, the
    answers do not separate present from absent.

    What this does and does not separate, and why, is recorded on `saw#250`."""
    if sys.platform != "darwin":
        return None
    r = _run(["security", "find-internet-password", "-s", _IMPOSSIBLE_KEYCHAIN_HOST])
    if r is None:
        return ("`security` did not run, so the keychain was not read and nothing found here says "
                "a credential is absent from it.")
    if r.returncode == 0:
        return ("This host's credential store did not answer as expected, so the keychain was not "
                "read.")
    return None


def _macos_keychain_has_github() -> bool:
    """True if a github.com internet password is cached in the macOS Keychain."""
    r = _run(["security", "find-internet-password", "-s", "github.com"])
    return r is not None and r.returncode == 0


def _linux_secret_has_github() -> bool:
    """True if libsecret / gnome-keyring holds a github.com credential (via `secret-tool`).

    Both of libsecret's query verbs LOAD the secret (there is no metadata-only CLI like macOS's
    `find-internet-password`), so we run `secret-tool lookup` with its output **discarded to the child's
    /dev/null** (`capture=False`) and read presence from the EXIT CODE alone (0 = found). The token is
    materialized only inside the secret-tool child and never enters saw's memory — keeping the
    'saw never reads a live secret' invariant on Linux too. No-op (False) when secret-tool is absent."""
    r = _run(["secret-tool", "lookup", "server", "github.com"], capture=False)
    return r is not None and r.returncode == 0


def _windows_credential_has_github() -> bool:
    """True if Windows Credential Manager holds a github.com git credential, via `cmdkey /list`. Reads
    only the target label (never the secret); False when the target is absent (`* NONE *`)."""
    r = _run(["cmdkey", "/list:git:https://github.com"])
    if r is None or r.returncode != 0:
        return False
    out = (r.stdout or "").lower()
    return "github.com" in out and "none" not in out


def _detect_cached_credential() -> KeychainStore | None:
    """The OS credential store holding a cached github.com credential on THIS platform, or None —
    macOS Keychain / Linux libsecret / Windows Credential Manager. Each probe is read-only,
    never reads the secret value, and degrades to None when the platform's tool is absent (so an audit
    on a host without the store's CLI simply reports nothing, rather than erroring)."""
    if sys.platform == "darwin":
        return _MACOS_STORE if _macos_keychain_has_github() else None
    if sys.platform.startswith("linux"):
        return _LINUX_STORE if _linux_secret_has_github() else None
    if sys.platform in ("win32", "cygwin"):
        return _WINDOWS_STORE if _windows_credential_has_github() else None
    return None


def _git_credentials_file_with_github() -> Path | None:
    """Path to a plaintext ~/.git-credentials holding a github.com entry, else None."""
    p = Path.home() / ".git-credentials"
    try:
        if p.is_file() and "github.com" in p.read_text(encoding="utf-8", errors="ignore"):
            return p
    except OSError:
        pass
    return None


def _credential_helper_origins() -> list[tuple[str, str]]:
    """(origin, value) pairs for the active `credential.helper` config, via
    `git config --show-origin --get-all`. Origin looks like `file:/path/to/gitconfig`; value is the
    helper (e.g. `osxkeychain`, or empty when a config resets the list). [] when git is absent."""
    r = _run(["git", "config", "--show-origin", "--get-all", "credential.helper"])
    if r is None or r.returncode != 0:
        return []
    pairs: list[tuple[str, str]] = []
    for line in r.stdout.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        origin, _, value = line.partition("\t")
        pairs.append((origin.strip(), value.strip()))
    return pairs


def _origin_path(origin: str) -> str:
    """The filesystem path from a `git config --show-origin` label like `file:/path/to/gitconfig`."""
    return origin.split(":", 1)[1] if origin.lower().startswith("file:") else origin


def _is_system_config(origin: str) -> bool:
    p = _origin_path(origin).lower()
    return p in _SYSTEM_CONFIG_EXACT or any(p.startswith(pre) for pre in _SYSTEM_CONFIG_PREFIXES)


def _system_default_helper_origin(origins: list[tuple[str, str]]) -> str | None:
    """If the active helper is set ONLY by a read-only system default (no user/global override),
    return that config's path — the case where `--unset` no-ops and you need `--add ... ""`. Else None."""
    non_empty = [(o, v) for o, v in origins if v]
    if not non_empty or not all(_is_system_config(o) for o, _ in non_empty):
        return None
    return _origin_path(non_empty[0][0])


def _https_token_status() -> bool | None:
    """Read-only 'is HTTPS auth actually IN USE here?' probe. Tri-state on purpose:
      * True  — a credential helper actively FILLS a github.com token (HTTPS is in use → deleting it
                logs you out; we must NEVER offer a delete).
      * False — git ran and NO helper served a token (`git credential fill` errors on 'could not read
                Username' under GIT_TERMINAL_PROMPT=0) → the token looks unused, a removal candidate.
      * None  — we couldn't probe (git missing / keychain locked / timeout) → unknown, so stay cautious
                and never assert the token is unused.
    Distinguishing None from False matters: a probe FAILURE must not masquerade as 'not in use' and
    invite a deletion."""
    r = _run(["git", "credential", "fill"], input_text="protocol=https\nhost=github.com\n\n")
    if r is None:
        return None
    return r.returncode == 0 and "password=" in (r.stdout or "")


def _ssh_key_present() -> bool:
    """True if a private SSH key exists in ~/.ssh (an `id_*` file that isn't a `.pub`) — evidence the
    machine can authenticate to GitHub over SSH, so a cached HTTPS token may be an unused leftover."""
    ssh_dir = Path.home() / ".ssh"
    try:
        for f in ssh_dir.iterdir():
            if f.is_file() and f.name.startswith("id_") and not f.name.endswith(".pub"):
                return True
    except OSError:
        pass
    return False


def _gh_configured() -> bool:
    """True if the gh CLI is wired as git's credential helper, or is logged in TO github.com — another
    working auth path. Scoped to github.com (`--hostname`) so a gh login to a *different* host (e.g. a
    GitHub Enterprise server) isn't mistaken for a github.com path. Value match is tight to avoid a
    false positive on an unrelated helper command that merely ends in `gh`."""
    for _origin, value in _credential_helper_origins():
        v = value.strip()
        if v == "gh" or v.startswith("!gh ") or v.endswith("/gh") or "/gh " in v or "gh auth" in v:
            return True
    r = _run(["gh", "auth", "status", "--hostname", "github.com"])
    return r is not None and r.returncode == 0


def _keychain_finding(store: KeychainStore) -> HygieneIssue:
    """Build the (info-level) cached-credential finding for `store` (the platform's OS keychain) —
    property-framed, multi-path-aware, and config-source-aware, informing rather than prescribing a
    delete (see module docstring /). Only the store name + removal command vary by platform;
    all the messaging and the lockout-safe gating are shared."""
    origins = _credential_helper_origins()
    served = _https_token_status()
    ssh, gh = _ssh_key_present(), _gh_configured()
    system_origin = _system_default_helper_origin(origins)

    alts = [name for name, present in (("an SSH key", ssh), ("the gh CLI", gh)) if present]
    alt_phrase = " and ".join(alts) if alts else None

    detail = [
        # NORMAL is stated because this is an `info` item on a healthy machine — without it the
        # reader treats a correctly-stored credential as a finding. Why storage location is not the
        # risk, and what a bearer token is, are docs material; the fix names the action.
        f"A github.com token is cached in {store.name} — normal, not a misconfiguration. What "
        "matters is its lifetime and scope.",
    ]
    if served is True:
        # The lockout guard. Stays, short: deleting this token logs the developer out of GitHub.
        detail.append("A helper is serving it, so HTTPS auth is IN USE — deleting it logs you out.")
    elif served is False:
        base = "No helper is serving it, so it looks unused."
        if alt_phrase:
            base += (f" This machine also has {alt_phrase}, but confirm you do not use HTTPS auth "
                     "before removing it.")
        else:
            base += " Confirm you do not rely on HTTPS auth before removing it."
        detail.append(base)
    else:  # None — probe couldn't run
        detail.append("Could not tell whether HTTPS auth is in use — verify before changing anything.")
    # SCOPE stays: without it a reader thinks removing this touches their gh CLI token and SSH keys.
    detail.append(f"The git-HTTPS entry in {store.name} only — your gh CLI token and SSH keys are "
                  "separate.")

    if served is True:
        remediation = ("Do not delete it — that logs you out. Harden in place: short-lived and "
                       "least-scope, or a hardware-backed SSH key. To retire HTTPS, set up SSH "
                       "first, verify it works, then remove.")
        command = None
    else:
        reset = ""
        if system_origin:
            reset = ('git config --global --add credential.helper ""   '
                     f'# reset the read-only system default ({textsafe.plain(system_origin, 200)})\n')
        command = (
            "ssh -T git@github.com   # STEP 1: confirm an ALTERNATE path authenticates — STOP if it doesn't\n"
            "git config --show-origin --get-all credential.helper   # find the REAL source\n"
            + reset +
            store.delete_command + "\n"
            "printf 'protocol=https\\nhost=github.com\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill"
            "   # VERIFY: an error on 'could not read Username' means nothing caches it anymore"
        )
        remediation = ("Only if you don't rely on HTTPS auth: remove the cached token the VERIFIED way. "
                       "First confirm an alternate path (SSH / gh) actually authenticates, then resolve "
                       "the real config source (an inherited system default needs "
                       "`--add credential.helper \"\"`, not a no-op `--unset`), delete, and re-probe to "
                       "confirm caching stopped. Full walkthrough in the details link.")

    return HygieneIssue(
        id="cached-github-keychain",
        severity="info",
        title=f"GitHub token cached in {store.name} — review its lifetime/scope",
        detail=" ".join(detail),
        remediation=remediation,
        command=command,
        reference=CREDENTIAL_HYGIENE_DOC,
    )


def check_credentials() -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    store = _detect_cached_credential()
    if store is not None:
        issues.append(_keychain_finding(store))
    cred_file = _git_credentials_file_with_github()
    if cred_file is not None:
        issues.append(HygieneIssue(
            id="git-credentials-plaintext",
            severity="warning",
            title="Plaintext GitHub credential in ~/.git-credentials",
            # Scope matters and stays: this is the git-HTTPS store only. Why plaintext is worse than
            # the Keychain does not — the title and the word PLAINTEXT already carry it.
            detail=f"{cred_file} stores a github.com credential in PLAINTEXT "
                   "(credential.helper=store) — any process running as you can read it. The "
                   "git-HTTPS store only; your gh token and SSH keys are separate.",
            remediation="Switch to a keychain helper or SSH, then delete the file. Rotate the token "
                        f"LAST, after isolating the host: {_WIPER_NOTE}.",
            command="git config --global credential.helper osxkeychain   # or: gh auth setup-git\n"
                    "rm ~/.git-credentials                                # after the helper is switched",
            reference=CREDENTIAL_HYGIENE_DOC,
        ))
    return issues

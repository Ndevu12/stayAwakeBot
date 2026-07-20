#!/usr/bin/env python3
"""Credential-exposure hygiene: a cached GitHub token in the OS keychain (macOS Keychain / Linux
libsecret-gnome-keyring / Windows Credential Manager) or a plaintext `~/.git-credentials`.

Threat-model note (#1237): a token *cached in the encrypted login Keychain is normal* — the Keychain
is the recommended store, and a credential must live somewhere to be usable. What actually determines
risk is the token's LIFETIME, SCOPE, and whether a bearer token can be COPIED by a process running as
you — not where it is stored. And developers legitimately keep several auth methods at once (SSH,
HTTPS+PAT, gh), often forced by the environment, so the tool must NEVER tell a user to collapse to one
or to "just delete" a path they may rely on. So the Keychain finding here:

  * is graded `info` (a review item), not `warning` — it's the WORST case only if properties are bad,
    which we deliberately do not read (saw never reads/transmits a live secret);
  * frames risk by PROPERTY, names the specific store, and says what a delete does NOT touch;
  * probes read-only whether a helper is actively SERVING the token (in use) vs it merely sitting
    there (a removal candidate), and never proposes deleting a sole working auth path first;
  * resolves the REAL config source (`git config --show-origin`) so its removal command is correct
    (an inherited read-only system default needs `--add credential.helper ""`, not a no-op `--unset`).

A PLAINTEXT `~/.git-credentials` (credential.helper=store) is a different animal — an actual
misconfiguration (a secret on disk in the clear), so it stays a `warning`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .models import HygieneIssue, _WIPER_NOTE

# Where the finding's `→ details:` link points — the full, non-destructive walkthrough.
CREDENTIAL_HYGIENE_DOC = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/"
                          "docs/CREDENTIAL_HYGIENE.md")


@dataclass(frozen=True)
class KeychainStore:
    """The OS credential store that holds a cached github.com credential on a given platform — its
    human name (for the finding's prose) and the platform-correct removal command (#1260). The store is
    encrypted and recommended on every platform; only the name and the delete verb differ."""
    name: str
    delete_command: str


# One store per platform. macOS Keychain / Linux libsecret (gnome-keyring) / Windows Credential Manager
# are all encrypted, recommended stores — a cached token is normal on each; the finding messaging is
# shared and only these two fields vary.
_MACOS_STORE = KeychainStore(
    "the macOS login Keychain",
    "security delete-internet-password -s github.com        # remove the cached entry")
_LINUX_STORE = KeychainStore(
    "the system secret store (libsecret / gnome-keyring)",
    "secret-tool clear server github.com                    # remove it from libsecret/gnome-keyring")
_WINDOWS_STORE = KeychainStore(
    "Windows Credential Manager",
    "cmdkey /delete:git:https://github.com                  # remove it from Windows Credential Manager")

# git config paths that are READ-ONLY system defaults — a helper inherited from one of these can't be
# `--unset` (that silently no-ops); it must be reset with `--add credential.helper ""` at global scope.
# The macOS Command Line Tools ship exactly such a default, which is what trips people up (#1237).
# ANCHORED to absolute-path prefixes/exact paths (not loose substrings): a user's `~/Library/...` or
# `~/dotfiles/etc/gitconfig` must NOT be misread as a read-only system config.
_SYSTEM_CONFIG_PREFIXES = ("/library/developer/commandlinetools/",
                           "/applications/xcode.app/", "/usr/local/git/")
_SYSTEM_CONFIG_EXACT = ("/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig")


def _run(cmd: list[str], *, input_text: str | None = None, timeout: int = 10,
         capture: bool = True) -> subprocess.CompletedProcess | None:
    """Read-only subprocess helper. Returns None (never raises) when the tool is missing / errors /
    times out, so every probe degrades gracefully on a machine that lacks git, `security`, or gh.

    `capture=False` DISCARDS the child's stdout/stderr to /dev/null and exposes only the exit code —
    used for a probe whose tool would print a live SECRET (libsecret's `secret-tool`), so the token is
    written to the child's null sink and never enters saw's memory (#1260). saw reads presence, never
    the secret, on every platform."""
    try:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}   # never block on an interactive prompt
        if not capture:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  text=True, timeout=timeout, input=input_text, env=env)
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, env=env)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
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
    only the target label (never the secret); False when the target is absent (`* NONE *`) (#1260)."""
    r = _run(["cmdkey", "/list:git:https://github.com"])
    if r is None or r.returncode != 0:
        return False
    out = (r.stdout or "").lower()
    return "github.com" in out and "none" not in out


def _detect_cached_credential() -> KeychainStore | None:
    """The OS credential store holding a cached github.com credential on THIS platform, or None —
    macOS Keychain / Linux libsecret / Windows Credential Manager (#1260). Each probe is read-only,
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
        origin, _, value = line.partition("\t")             # git separates origin and value by a TAB
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
    """Read-only 'is HTTPS auth actually IN USE here?' probe (#1237). Tri-state on purpose:
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
    delete (see module docstring / #1237). Only the store name + removal command vary by platform;
    all the messaging and the lockout-safe gating are shared (#1260)."""
    origins = _credential_helper_origins()
    served = _https_token_status()                      # True (in use) | False (unused) | None (unknown)
    ssh, gh = _ssh_key_present(), _gh_configured()
    system_origin = _system_default_helper_origin(origins)

    # NOTE: ssh/gh only ENRICH the prose — they never gate the destructive command. We can't verify
    # offline that a present SSH key or a gh login actually authenticates to github.com (a stale key,
    # or a gh login to a different host, would lie), so the safety decision keys off `served` and the
    # command's own `ssh -T` pre-check, NOT these heuristics (#1237 lockout hardening).
    alts = [name for name, present in (("an SSH key", ssh), ("the gh CLI", gh)) if present]
    alt_phrase = " and ".join(alts) if alts else None

    detail = [
        f"A github.com token is cached in {store.name} — the recommended, encrypted store. That "
        "on its own is NORMAL, not a misconfiguration: a credential has to live somewhere to be usable.",
        "What actually determines risk is the token's lifetime, scope, and that a bearer token can be "
        "COPIED by a process running as you — not where it's stored. If this is a non-expiring, "
        "broadly-scoped personal access token, shorten its lifetime and cut its scope (or move to a "
        "hardware-backed SSH key, which a worm can use but cannot copy).",
    ]
    if served is True:
        detail.append("A credential helper is actively serving this token here, so HTTPS auth is IN "
                      "USE — deleting it logs you out. Harden it in place (shorten lifetime, cut scope, "
                      "or move to a hardware-backed key) rather than removing it.")
    elif served is False:
        base = ("No helper is actively serving an HTTPS token here, so the cached token looks unused — "
                "a removal candidate.")
        if alt_phrase:
            base += (f" This machine also has {alt_phrase}. If you DO use HTTPS auth for some projects, "
                     "keep it; another path existing doesn't by itself make it redundant.")
        else:
            base += " But confirm you don't rely on HTTPS auth before removing it."
        detail.append(base)
    else:  # None — probe couldn't run
        detail.append("Couldn't determine whether HTTPS auth is in use here (git or the keychain wasn't "
                      "reachable) — verify before changing anything.")
    detail.append(f"This is the git-HTTPS entry in {store.name} only. Your gh CLI token and your SSH "
                  "keys are SEPARATE stores — removing this leaves them untouched.")

    if served is True:
        # HTTPS is IN USE here — deleting logs you out, full stop. Never offer a delete command; the
        # only right move is to harden the credential in place (this also removes the old contradiction
        # where the prose said "don't delete" while a delete command sat right below it).
        remediation = ("HTTPS auth is in use here, so don't delete this token (that logs you out). "
                       "Harden it in place: make it short-lived and least-scope, or move to a "
                       "hardware-backed SSH key. If you'd rather retire HTTPS entirely, stand up SSH or "
                       "`gh auth setup-git` FIRST, verify it authenticates, and only then remove it — "
                       "see the details link.")
        command = None
    else:
        # served is False (unused) or None (unknown). Deletion MAY be safe — but never ASSUME it: the
        # command leads with an `ssh -T` check that must authenticate first, so even a wrong guess
        # (a false 'unused', a stale key) can't cause a silent lockout — the user stops if step 1 fails.
        reset = ""
        if system_origin:
            reset = ('git config --global --add credential.helper ""   '
                     f'# reset the read-only system default ({system_origin})\n')
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
            detail=f"{cred_file} stores a github.com credential in PLAINTEXT on disk "
                   "(credential.helper=store). Unlike the encrypted Keychain, this is a genuine "
                   "misconfiguration — any process running as you can read the token straight out of "
                   "the file. This is the git-HTTPS store only; your gh token and SSH keys are separate.",
            remediation="Switch to an OS keychain helper or SSH, then delete the plaintext file. "
                        "Rotate the exposed token LAST — only after isolating the host and "
                        f"neutralizing any persistence (see the incident-response steps): {_WIPER_NOTE}.",
            command="git config --global credential.helper osxkeychain   # or: gh auth setup-git\n"
                    "rm ~/.git-credentials                                # after the helper is switched",
            reference=CREDENTIAL_HYGIENE_DOC,
        ))
    return issues

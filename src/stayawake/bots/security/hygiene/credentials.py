#!/usr/bin/env python3
"""Credential-exposure hygiene: a cached GitHub token in the OS keychain (macOS Keychain / Linux
libsecret-gnome-keyring / Windows Credential Manager) or a plaintext `~/.git-credentials`.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import unquote

from stayawake.bots.security import hookscript
from stayawake.lib.git.run import OPERATOR_CONFIG, run as git_run
from stayawake.utils import textsafe
from .models import HygieneIssue, _WIPER_NOTE

CREDENTIAL_HYGIENE_DOC = ("https://github.com/Ndevu12/stayAwakeBot/blob/main/"
                          "docs/explanation/credential-hygiene.md")


@dataclass(frozen=True)
class KeychainStore:
    """The OS credential store that holds a cached github.com credential on a given platform: its
    name as the finding says it, the command that removes git's entry, and the git credential helpers
    that read it."""
    name: str
    delete_command: str
    helpers: tuple[str, ...]


_MACOS_STORE = KeychainStore(
    "the macOS login Keychain",
    "security delete-internet-password -s github.com -r htps -t dflt   # remove git's cached entry",
    ("osxkeychain",))
_LINUX_STORE = KeychainStore(
    "the system secret store (libsecret / gnome-keyring)",
    "secret-tool clear server github.com protocol https     # remove git's entry from libsecret/gnome-keyring",
    ("libsecret", "gnome-keyring"))
_WINDOWS_STORE = KeychainStore(
    "Windows Credential Manager",
    "MSYS_NO_PATHCONV=1 cmdkey /delete:git:https://github.com   # remove it from Windows Credential Manager",
    ("manager", "manager-core", "wincred"))
_HELPERS_THAT_READ_NO_STORE = ("store", "cache")
_HELPER_CONFIG = r"^(credential\.(.*\.)?helper|includeif\..+\.path)$"
_REPOSITORY_HELPER_CONFIG = r"^(credential\.(.*\.)?helper|include(if\..+)?\.path)$"
_MACOS_GIT_ITEM = ("-s", "github.com", "-r", "htps", "-t", "dflt")
_KEYCHAIN_ITEM_NOT_FOUND = 44
_SECRET_SERVICE = ("gdbus", "call", "--session", "--dest", "org.freedesktop.secrets")
_SECRET_SERVICE_PATH = "/org/freedesktop/secrets"
_PROPERTY = "org.freedesktop.DBus.Properties.Get"
_GIT_ITEM_ATTRIBUTES = "{'server': 'github.com', 'protocol': 'https'}"
_WINDOWS_GIT_PREFIX = "git:https://"
_WINDOWS_TARGET_USER_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+-@")
_MAX_ENVIRONMENT_ENTRIES = 10_000

_SYSTEM_CONFIG_PREFIXES = ("/library/developer/commandlinetools/",
                           "/applications/xcode.app/", "/usr/local/git/")
_SYSTEM_CONFIG_EXACT = ("/etc/gitconfig", "/usr/local/etc/gitconfig", "/opt/homebrew/etc/gitconfig")

ConfigEntry = tuple[str, str, str | None]


def _run(cmd: list[str], *, input_text: str | None = None, timeout: int = 10,
         capture: bool = True) -> subprocess.CompletedProcess | None:
    """Run a read-only command. Takes its argv, what to feed it, a timeout, and whether to capture
    its output; with `capture=False` the output goes to the null device and only the exit status
    comes back. Returns the finished process, or None when the command could not run or timed out."""
    try:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if not capture:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  text=True, timeout=timeout, input=input_text, env=env)
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
                              input=input_text, env=env)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None


_GIT_TIMEOUT = 10
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


def _macos_keychain_has_github() -> bool | None:
    """Whether the macOS Keychain holds git's github.com entry. Reads attributes only. None when
    `security` did not answer."""
    r = _run(["security", "find-internet-password", *_MACOS_GIT_ITEM])
    if r is None:
        return None
    if r.returncode == 0:
        return True
    return False if r.returncode == _KEYCHAIN_ITEM_NOT_FOUND else None


def _secret_store_on_disk() -> bool:
    """True if this account keeps a gnome-keyring or KWallet store file."""
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    for folder, suffix in (("keyrings", ".keyring"), ("kwalletd", ".kwl")):
        try:
            if any(entry.suffix == suffix for entry in (data / folder).iterdir()):
                return True
        except OSError:
            continue
    return False


def _secret_service(path: str, method: str, *args: str) -> str | None:
    """What the Secret Service answers to `method` on `path`, as gdbus prints it. Takes the object
    path, the method and its arguments. None when it did not answer."""
    r = _run([*_SECRET_SERVICE, "--object-path", path, "--method", method, *args])
    if r is None or r.returncode != 0:
        return None
    return r.stdout or ""


def _object_paths(answer: str) -> list[str]:
    """The object paths in a gdbus answer."""
    return ["/" + part.split("'", 1)[0] for part in answer.split("'/")[1:]]


def _secret_service_searches_locked_items() -> bool:
    """True when the Secret Service is gnome-keyring, which also searches locked collections."""
    r = _run(["gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
              "--object-path", "/org/freedesktop/DBus",
              "--method", "org.freedesktop.DBus.GetConnectionUnixProcessID", "org.freedesktop.secrets"])
    if r is None or r.returncode != 0:
        return False
    answer = r.stdout or ""
    pid = answer.replace(",", " ").replace(")", " ").split()[-1:]
    if not pid or not pid[0].isdigit():
        return False
    try:
        return Path(f"/proc/{pid[0]}/comm").read_text(encoding="utf-8").startswith("gnome-keyring")
    except OSError:
        return False


def _linux_secret_has_github() -> bool | None:
    """Whether the Secret Service holds git's github.com entry. Reads which collections are locked,
    then item names. False when no store answers and none is kept on disk, or when every collection
    that could hold the entry was searched and none does; None when that could not be told."""
    collections = _secret_service(_SECRET_SERVICE_PATH, _PROPERTY,
                                  "org.freedesktop.Secret.Service", "Collections")
    if collections is None:
        return None if _secret_store_on_disk() else False
    locked: list[bool] = []
    for path in _object_paths(collections):
        answer = _secret_service(path, _PROPERTY, "org.freedesktop.Secret.Collection", "Locked")
        if answer is None:
            return None
        locked.append("true" in answer)
    searches_locked = _secret_service_searches_locked_items()
    if not locked:
        return False if searches_locked else None
    if all(locked) and not searches_locked:
        return None
    found = _secret_service(_SECRET_SERVICE_PATH, "org.freedesktop.Secret.Service.SearchItems",
                            _GIT_ITEM_ATTRIBUTES)
    if found is None:
        return None
    if "'/" in found:
        return True
    return None if any(locked) and not searches_locked else False


def _windows_credential_has_github() -> list[str] | None:
    """The Windows Credential Manager targets git keeps for github.com, `git:https://github.com` and
    `git:https://<user>@github.com`, from `cmdkey /list`, which prints target names only. None when
    cmdkey did not answer."""
    r = _run(["cmdkey", "/list"])
    if r is None or r.returncode != 0:
        return None
    targets: list[str] = []
    for line in (r.stdout or "").splitlines():
        at = line.find(_WINDOWS_GIT_PREFIX)
        if at < 0:
            continue
        target = line[at:].strip()
        if target[len(_WINDOWS_GIT_PREFIX):].rpartition("@")[2].lower() == "github.com" \
                and target not in targets:
            targets.append(target)
    return targets


def _windows_removal(targets: list[str]) -> str:
    """The Git Bash commands that remove `targets` from Windows Credential Manager. When a target's
    user name holds a character a command cannot carry, the commands name no target and say to take
    each one from `cmdkey /list`."""
    users = [target[len(_WINDOWS_GIT_PREFIX):].rpartition("@")[0] for target in targets]
    if all(set(user) <= _WINDOWS_TARGET_USER_CHARACTERS for user in users):
        return "\n".join(f"MSYS_NO_PATHCONV=1 cmdkey /delete:{target}   # remove it from Windows "
                         "Credential Manager" for target in targets)
    return ("MSYS_NO_PATHCONV=1 cmdkey /list   # find each git:https://...github.com target\n"
            "MSYS_NO_PATHCONV=1 cmdkey /delete:<target>   # remove each one it lists")


def _detect_cached_credential() -> tuple[KeychainStore, bool | None] | None:
    """This platform's credential store and whether it holds git's github.com entry, that answer
    None when the store could not be read. None on a platform with no store saw reads."""
    if sys.platform == "darwin":
        return _MACOS_STORE, _macos_keychain_has_github()
    if sys.platform.startswith("linux"):
        return _LINUX_STORE, _linux_secret_has_github()
    if sys.platform in ("win32", "cygwin"):
        targets = _windows_credential_has_github()
        if not targets:
            return _WINDOWS_STORE, None if targets is None else False
        return replace(_WINDOWS_STORE, delete_command=_windows_removal(targets)), True
    return None


def _git_credentials_path() -> Path:
    return Path.home() / ".git-credentials"


def _git_credentials_file_with_github() -> bool | None:
    """Whether ~/.git-credentials names github.com, searched without saw reading the file. False
    when there is no such file; None when it could not be searched."""
    path = _git_credentials_path()
    try:
        if not path.is_file():
            return False
        with open(path, "rb"):
            pass
    except OSError:
        return None
    search = (["findstr", "/M", "/C:github.com", str(path)] if sys.platform in ("win32", "cygwin")
              else ["grep", "-q", "-F", "github.com", str(path)])
    r = _run(search, capture=False)
    if r is None or r.returncode not in (0, 1):
        return None
    return r.returncode == 0


def _origin_path(origin: str) -> str:
    """The filesystem path from a `git config --show-origin` label like `file:/path/to/gitconfig`."""
    return origin.split(":", 1)[1] if origin.lower().startswith("file:") else origin


def _is_system_config(origin: str) -> bool:
    p = _origin_path(origin).lower()
    return p in _SYSTEM_CONFIG_EXACT or any(p.startswith(pre) for pre in _SYSTEM_CONFIG_PREFIXES)


def _system_default_helper_origin(origins: list[tuple[str, str]]) -> str | None:
    """The path of the read-only system config that alone sets the active helper, else None. Takes
    (where it was set, value) pairs."""
    non_empty = [(o, v) for o, v in origins if v]
    if not non_empty or not all(_is_system_config(o) for o, _ in non_empty):
        return None
    return _origin_path(non_empty[0][0])


def _helper_name(value: str) -> str | None:
    """The helper a `credential.helper` value runs, as git names it: `osxkeychain` for both
    `osxkeychain` and `/usr/local/bin/git-credential-osxkeychain`. None for a shell snippet or a value
    that does not parse."""
    if value.startswith("!"):
        return None
    try:
        words = shlex.split(value)
    except ValueError:
        return None
    if not words:
        return None
    name = words[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.removesuffix(".exe").removeprefix("git-credential-")


def _scope_reaches_github(scope: str) -> bool:
    """Whether a `credential.<url>` scope applies to https://github.com, as git matches it. Takes the
    `<url>`."""
    host = scope.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    host = unquote(host).lower().removesuffix(".")
    if not host:
        return True
    parts = host.split(".")
    return len(parts) == 2 and all(part in ("*", want) for part, want in zip(parts, ("github", "com")))


def _config_entries(args: list[str]) -> list[ConfigEntry] | None:
    """The entries `git config -z --show-origin <args>` prints, in git's order, as (where it was set,
    key, value); the value is None for a key written without one. Takes the arguments that follow
    `--show-origin`. None when git could not read the config."""
    r = git_run(None, ["config", "-z", "--show-origin", *args],
                timeout=_GIT_TIMEOUT, context=OPERATOR_CONFIG)
    if r is None or r.returncode not in (0, 1):
        return None
    fields = (r.stdout or "").split("\0")
    entries: list[ConfigEntry] = []
    for origin, entry in zip(fields[0::2], fields[1::2]):
        key, has_value, value = entry.partition("\n")
        entries.append((origin, key, value if has_value else None))
    return entries


def _canonical_key(key: str) -> str:
    """`key` as git prints it: section and name in lower case, a subsection as written."""
    section, _, rest = key.partition(".")
    subsection, dot, name = rest.rpartition(".")
    if not dot:
        return f"{section.lower()}.{name.lower()}"
    return f"{section.lower()}.{subsection}.{name.lower()}"


def _names_helper_or_include(key: str) -> bool:
    return ((key.startswith("credential.") and key.endswith(".helper"))
            or key == "include.path" or (key.startswith("includeif.") and key.endswith(".path")))


def _environment_entries() -> list[ConfigEntry] | None:
    """The helper and include entries git takes from the environment, in git's order: those of
    GIT_CONFIG_COUNT with GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n>, then those of
    GIT_CONFIG_PARAMETERS. None when the environment holds config git would refuse."""
    entries: list[ConfigEntry] = []
    count = os.environ.get("GIT_CONFIG_COUNT")
    if count:
        try:
            total = int(count)
        except ValueError:
            return None
        if not 0 <= total <= _MAX_ENVIRONMENT_ENTRIES:
            return None
        for index in range(total):
            key = os.environ.get(f"GIT_CONFIG_KEY_{index}")
            value = os.environ.get(f"GIT_CONFIG_VALUE_{index}")
            if not key or value is None:
                return None
            entries.append(("command line:", _canonical_key(key), value))
    parameters = os.environ.get("GIT_CONFIG_PARAMETERS")
    if parameters:
        try:
            words = shlex.split(parameters)
        except ValueError:
            return None
        for word in words:
            key, has_value, value = word.partition("=")
            entries.append(("command line:", _canonical_key(key), value if has_value else None))
    return [entry for entry in entries if _names_helper_or_include(entry[1])]


def _repository_config_files(repo: Path) -> list[Path] | None:
    """The config files git reads for `repo` itself: its shared `config` and, when that turns on
    `extensions.worktreeConfig`, its worktree's `config.worktree`. None when its git directory or
    its shared config could not be read."""
    dot_git = repo / ".git"
    try:
        if dot_git.is_dir():
            git_dir = dot_git
        elif not dot_git.is_file():
            return None
        else:
            with open(dot_git, encoding="utf-8", errors="replace") as pointer:
                text = pointer.read(4096)
            if not text.startswith("gitdir:"):
                return None
            git_dir = repo / text[len("gitdir:"):].strip()
        common = git_dir
        commondir = git_dir / "commondir"
        if commondir.is_file():
            common = git_dir / commondir.read_text(encoding="utf-8", errors="replace").strip()
        shared = common / "config"
        if not shared.is_file():
            return []
        worktree = git_dir / "config.worktree"
        if not worktree.is_file():
            return [shared]
    except OSError:
        return None
    r = git_run(None, ["config", "--file", str(shared), "--type=bool", "--get",
                       "extensions.worktreeConfig"], timeout=_GIT_TIMEOUT, context=OPERATOR_CONFIG)
    if r is None or r.returncode not in (0, 1):
        return None
    return [shared, worktree] if (r.stdout or "").strip() == "true" else [shared]


def _repository_entries(repo: Path) -> list[ConfigEntry] | None:
    """The helper and include entries `repo`'s own config files set, in git's order. None when one of
    them could not be read."""
    files = _repository_config_files(repo)
    if files is None:
        return None
    entries: list[ConfigEntry] = []
    for path in files:
        found = _config_entries(["--file", str(path), "--get-regexp", _REPOSITORY_HELPER_CONFIG])
        if found is None:
            return None
        entries += found
    return entries


def _github_helpers_in(entries: list[ConfigEntry]) -> tuple[list[tuple[str, str]], bool]:
    """The helpers `entries` set up for https://github.com, as (where it was set, value) in git's
    order, and whether the entries also hold an include or a key with no value, whose reach is
    unknown. Takes config entries in git's order."""
    helpers: list[tuple[str, str]] = []
    scoped: list[tuple[str, str]] = []
    reach_unknown = False
    for origin, key, value in entries:
        if key == "include.path" or key.startswith("includeif.") or value is None:
            reach_unknown = True
        elif key == "credential.helper":
            helpers = helpers + [(origin, value)] if value else []
        elif (key.startswith("credential.") and value
              and _scope_reaches_github(key[len("credential."):-len(".helper")])):
            scoped.append((origin, value))
    return helpers + scoped, reach_unknown


def _github_helpers(*, in_repositories: bool = False) -> list[tuple[list[tuple[str, str]], bool]] | None:
    """The helpers git sets up for https://github.com outside any repository and, with
    `in_repositories`, inside each repository saw's hooks have seen: one (helpers, reach unknown) per
    place, helpers as (where it was set, value). None when the operator's config could not be read."""
    operator = _config_entries(["--get-regexp", _HELPER_CONFIG])
    if operator is None:
        return None
    environment = _environment_entries()
    environment_unknown = environment is None
    environment = environment or []
    places: list[tuple[list[ConfigEntry], list[ConfigEntry] | None]] = [(operator, [])]
    if in_repositories:
        for repo in hookscript.seeded_repositories():
            places.append((operator, _repository_entries(repo)))
    found: list[tuple[list[tuple[str, str]], bool]] = []
    for files, local in places:
        helpers, reach_unknown = _github_helpers_in(files + (local or []) + environment)
        found.append((helpers, reach_unknown or environment_unknown or local is None))
    return found


def _credential_helper_origins() -> list[tuple[str, str]]:
    """The helpers git sets up for https://github.com outside any repository, as (where it was set,
    value) in git's order. [] when the config could not be read."""
    found = _github_helpers()
    return found[0][0] if found else []


def _https_token_status(store: KeychainStore) -> bool | None:
    """Whether git is set up to read the github.com token cached in `store`, from git's config
    outside any repository and in each repository saw's hooks have seen. Takes the platform's store.

    Returns True when a configured helper reads `store`; False when none does; None when that could
    not be told."""
    found = _github_helpers(in_repositories=True)
    if found is None:
        return None
    names = [_helper_name(value) for helpers, _ in found for _, value in helpers]
    if any(name in store.helpers for name in names):
        return True
    if (any(reach_unknown for _, reach_unknown in found)
            or any(name not in _HELPERS_THAT_READ_NO_STORE for name in names)):
        return None
    return False


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
    """True if the gh CLI is git's credential helper for github.com, read from git's config."""
    for _, value in _credential_helper_origins():
        v = value.strip()
        if v == "gh" or v.startswith("!gh ") or v.endswith("/gh") or "/gh " in v or "gh auth" in v:
            return True
    return False


def _keychain_finding(store: KeychainStore) -> HygieneIssue:
    """The info-level finding for a github.com token cached in `store`, the platform's OS keychain.
    Takes the store. Returns the finding; it names a removal command only when git is not known to
    read the token."""
    origins = _credential_helper_origins()
    served = _https_token_status(store)
    ssh, gh = _ssh_key_present(), _gh_configured()
    system_origin = _system_default_helper_origin(origins)

    alts = [name for name, present in (("an SSH key", ssh), ("the gh CLI", gh)) if present]
    alt_phrase = " and ".join(alts) if alts else None

    detail = [
        f"A github.com token is cached in {store.name} — normal, not a misconfiguration. What "
        "matters is its lifetime and scope.",
    ]
    if served is True:
        detail.append("Git is configured to read it: HTTPS auth is IN USE — deleting it logs you out.")
    elif served is False:
        base = "Git does not read it, so it looks unused."
        if alt_phrase:
            base += (f" This machine also has {alt_phrase}, but confirm you do not use HTTPS auth "
                     "before removing it.")
        else:
            base += " Confirm you do not rely on HTTPS auth before removing it."
        detail.append(base)
    else:
        detail.append("Could not tell whether HTTPS auth is in use — verify before changing anything.")
    detail.append(f"The git-HTTPS entry in {store.name} only — your gh CLI token and SSH keys are "
                  "separate.")

    if served is True:
        remediation = ("Do not delete it — that logs you out. Harden in place: short-lived and "
                       "least-scope. To retire HTTPS, set up SSH first, verify it works, then "
                       "remove.")
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
            "printf 'protocol=https\\nhost=github.com\\n\\n' | GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= GCM_INTERACTIVE=never git credential fill"
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
    """The credential findings for this account: a github.com token cached in the platform's store
    and one kept in plaintext in ~/.git-credentials, and each of the two that could not be read."""
    issues: list[HygieneIssue] = []
    found = _detect_cached_credential()
    if found is not None:
        store, present = found
        if present:
            issues.append(_keychain_finding(store))
        elif present is None:
            issues.append(HygieneIssue(
                id="cached-github-keychain-unread",
                severity="unknown",
                title=f"{store.name[0].upper()}{store.name[1:]} was not read",
                detail="Whether it holds git's github.com token is not known.",
                remediation=f"Run the audit again in a desktop session with {store.name} unlocked.",
                reference=CREDENTIAL_HYGIENE_DOC,
            ))
    plaintext = _git_credentials_file_with_github()
    if plaintext:
        issues.append(HygieneIssue(
            id="git-credentials-plaintext",
            severity="warning",
            title="Plaintext GitHub credential in ~/.git-credentials",
            detail=f"{_git_credentials_path()} stores a github.com credential in PLAINTEXT "
                   "(credential.helper=store) — any process running as you can read it. The "
                   "git-HTTPS store only; your gh token and SSH keys are separate.",
            remediation="Switch to a keychain helper or SSH, then delete the file. Rotate the token "
                        f"LAST, after isolating the host: {_WIPER_NOTE}.",
            command="git config --global credential.helper osxkeychain   # or: gh auth setup-git\n"
                    "rm ~/.git-credentials                                # after the helper is switched",
            reference=CREDENTIAL_HYGIENE_DOC,
        ))
    elif plaintext is None:
        issues.append(HygieneIssue(
            id="git-credentials-unread",
            severity="unknown",
            title="The git credential file was not read",
            detail="Whether it stores a github.com credential is not known.",
            remediation="Run the audit again once your git credential file is readable.",
            reference=CREDENTIAL_HYGIENE_DOC,
        ))
    return issues

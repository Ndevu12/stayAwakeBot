#!/usr/bin/env python3
"""Signing for a history rewrite — prove a signature can be made BEFORE any ref moves.

`saw fix amend` replaces a commit and replays the commits after it, keeping each commit's
ORIGINAL author. Forcing `commit.gpgsign=false` there produced commits attributed to people who
never made them, with the signature that attested that authorship destroyed. A rewrite genuinely
has a new committer, and git separates the two roles, so the truthful record is: **author
preserved, committer the operator, signed by the operator**. Signing is therefore ENABLED, and a
repository that asks for signatures but cannot produce one is a REFUSAL the caller detects up
front — never a silent downgrade to unsigned.

The three states a caller must tell apart, all carried by `SigningStatus`:

    configured=False              signing was never asked for  -> rewrite unsigned, disclose it
    configured=True, available    signing asked for and proven -> rewrite signed
    configured=True, not avail.   asked for, cannot be made    -> `must_refuse`, rewrite nothing
"""
from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.git.run import run, run_ok

PROBE_TIMEOUT = 10

# Handed to the probe so it signs as the real repository would. Enumerated rather than
# `include.path`-ing the repo's own config, which needs no list but drags in
# `extensions.objectformat` — a sha256 repo's config makes a sha1 probe repo unusable. A key
# missing here makes the probe fail, i.e. refuse; it can never yield a false "signing works".
_SIGNING_CONFIG_KEYS = (
    "user.name",
    "user.email",
    "user.signingkey",
    "gpg.format",
    "gpg.program",
    "gpg.openpgp.program",
    "gpg.x509.program",
    "gpg.ssh.program",
    "gpg.ssh.defaultkeycommand",
    "gpg.ssh.allowedsignersfile",
)

# MEASURED on git 2.39.2: `commit-tree` ignores `commit.gpgsign` entirely — a `-c` override alone
# leaves the replacement commit UNSIGNED. `rebase` honours the config, but the explicit flag is
# what makes the outcome independent of where the config was read from. Per command: (on, off).
_SIGN_FLAGS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "commit-tree": (("-S",), ()),
    "commit": (("-S",), ("--no-gpg-sign",)),
    "rebase": (("--gpg-sign",), ("--no-gpg-sign",)),
    "cherry-pick": (("-S",), ("--no-gpg-sign",)),
}

_COMMITTER_VARS = ("GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE")

_PROBE_IDENTITY = {"user.name": "saw signing probe", "user.email": "probe@stayawake.local"}


@dataclass(frozen=True)
class SigningStatus:
    """What this repository's signing configuration can actually do, established by making a
    real throwaway signature — never by reading `commit.gpgsign` and believing it."""

    configured: bool
    available: bool
    reason: str
    signature_format: str

    @property
    def must_refuse(self) -> bool:
        """The hard refusal condition: signatures were asked for and cannot be produced. The
        caller checks this BEFORE the first ref moves; rewriting anyway would replace signed
        history with unsigned commits that keep their original authors."""
        return self.configured and not self.available


def signing_status(repo: str | Path) -> SigningStatus:
    """Whether `repo` is configured to sign AND can prove it, with a reason either way.

    Runs a git subprocess and a real signing attempt, so hold the result and pass it around
    rather than calling this once per commit.
    """
    config = _resolved_signing_config(repo)
    signature_format = config.get("gpg.format") or "openpgp"
    if config.get("commit.gpgsign") != "true":
        return SigningStatus(
            configured=False, available=False, signature_format=signature_format,
            reason="commit signing is not enabled here (commit.gpgsign is not true)")
    failure = _first_probe_failure(config)
    if failure is None:
        return SigningStatus(
            configured=True, available=True, signature_format=signature_format,
            reason=f"a test {signature_format} signature was produced")
    return SigningStatus(
        configured=True, available=False, signature_format=signature_format,
        reason=f"commit.gpgsign is true but no {signature_format} signature "
               f"could be produced: {failure}")


def signing_available(repo: str | Path) -> tuple[bool, str]:
    """`(can this repo produce a signature, why not)` — the two-value form. A caller that has to
    tell "never asked for" apart from "asked for and broken" needs `signing_status` instead:
    only the second is a refusal."""
    status = signing_status(repo)
    return status.available, status.reason


def signing_env(repo: str | Path, base: Mapping[str, str] | None = None) -> dict:
    """The environment for the rewriting command: the committer is the OPERATOR.

    Taken from the repository's own `user.name`/`user.email`, overriding whatever
    `GIT_COMMITTER_*` the ambient environment carries — a git hook and an in-progress rebase both
    export those, which would attribute the rewrite to the commit being replayed. `GIT_AUTHOR_*`
    is deliberately left untouched: preserving the original author is the caller's job.
    """
    env = dict(os.environ if base is None else base)
    for var in _COMMITTER_VARS:
        env.pop(var, None)
    operator_name = _config_value(repo, "user.name")
    operator_email = _config_value(repo, "user.email")
    if operator_name:
        env["GIT_COMMITTER_NAME"] = operator_name
    if operator_email:
        env["GIT_COMMITTER_EMAIL"] = operator_email
    return _refuse_to_prompt(env)


def signing_args(status: SigningStatus) -> tuple[str, ...]:
    """The `-c` overrides to place before the subcommand, pinning the decision so an ambient or
    included config cannot flip it. Not sufficient on its own — see `sign_flags`."""
    return ("-c", f"commit.gpgsign={'true' if status.available else 'false'}")


def sign_flags(status: SigningStatus, command: str) -> tuple[str, ...]:
    """The signing flag `command` itself needs, which is what actually decides the outcome for
    `commit-tree` (it reads no signing config at all). A command with no entry raises rather than
    returning nothing: defaulting to no flag is exactly the silent unsigned rewrite this module
    exists to prevent."""
    if command not in _SIGN_FLAGS:
        raise ValueError(f"no signing flag is known for `git {command}`; add it to _SIGN_FLAGS "
                         f"rather than letting the rewrite fall through to unsigned")
    signed, unsigned = _SIGN_FLAGS[command]
    return signed if status.available else unsigned


def _resolved_signing_config(repo: str | Path) -> dict[str, str]:
    """Every signing key git would resolve for `repo`. `--list` emits system, global, local and
    worktree scopes in that order, so the last value seen for a key is the one git would use —
    `commit.gpgsign` still goes through `--type=bool`, because reimplementing git's spelling of
    truth (`yes`, `on`, `1`, a valueless key) is exactly how a config check drifts from git."""
    resolved: dict[str, str] = {}
    listing = run(repo, ["config", "--list", "-z"], timeout=PROBE_TIMEOUT)
    if listing is not None and listing.returncode == 0:
        for entry in listing.stdout.split("\0"):
            key, _, value = entry.partition("\n")
            if key in _SIGNING_CONFIG_KEYS and value:
                resolved[key] = value
    enabled = _config_value(repo, "commit.gpgsign", as_bool=True)
    if enabled:
        resolved["commit.gpgsign"] = enabled
    key_path = resolved.get("user.signingkey", "")
    if key_path and not os.path.isabs(key_path) and (Path(repo) / key_path).exists():
        # git resolves a signing-key path against its own cwd, which `-C` moves to the probe
        # repository. Left relative, a working key would probe as broken — a false refusal.
        resolved["user.signingkey"] = str((Path(repo) / key_path).resolve())
    return resolved


def _config_value(repo: str | Path, key: str, *, as_bool: bool = False) -> str:
    args = ["config", "--get"] + (["--type=bool"] if as_bool else []) + [key]
    res = run(repo, args, timeout=PROBE_TIMEOUT)
    if res is None or res.returncode != 0:
        return ""
    return res.stdout.strip()


def _first_probe_failure(config: Mapping[str, str]) -> str | None:
    """None when a throwaway repository configured like this one produced a real signature;
    otherwise the reason it could not. Nothing is written to the repository being scanned, and no
    key is ever created — the operator's existing key is used, or the probe fails."""
    probe = Path(tempfile.mkdtemp(prefix="saw-signprobe-"))
    try:
        if not run_ok(None, ["init", "-q", "-b", "main", str(probe)], timeout=PROBE_TIMEOUT):
            return "a probe repository could not be created"
        # `-c` overrides rather than written config: command-line scope is how git layers config
        # anyway, and it drops 12 subprocesses off a probe that measured 1.15s.
        overrides = [arg
                     for key, value in {**_PROBE_IDENTITY, **config}.items()
                     for arg in ("-c", f"{key}={value}")]
        res = run(probe, [*overrides, "commit", "--allow-empty", "-q",
                          "-m", "saw signing probe", "-S"],
                  env=_refuse_to_prompt(dict(os.environ)), timeout=PROBE_TIMEOUT)
        if res is None:
            return f"the signing attempt did not finish within {PROBE_TIMEOUT}s"
        if res.returncode != 0:
            return _first_line(res.stderr) or "the signing attempt failed"
        if not _has_signature_header(probe):
            return "the probe commit was created but carried no signature"
        return None
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _has_signature_header(probe: Path) -> bool:
    """A signature on the object, not merely a zero exit. Only the header block is inspected, so
    a commit *message* mentioning gpgsig cannot stand in for a signature."""
    res = run(probe, ["cat-file", "commit", "HEAD"], timeout=PROBE_TIMEOUT)
    if res is None or res.returncode != 0:
        return False
    headers = res.stdout.split("\n\n", 1)[0]
    return any(line.startswith("gpgsig") for line in headers.splitlines())


def _refuse_to_prompt(env: dict) -> dict:
    """Make a signing attempt fail rather than ask a human anything — applied to the probe and to
    the rewrite alike, so what the probe proved is what the rewrite gets.

    MEASURED with OpenSSH 9.0: a passphrase-protected key under `SSH_ASKPASS_REQUIRE=force` and an
    absent askpass helper fails in 0.04s instead of reading the passphrase off `/dev/tty`. Dropping
    `GPG_TTY` denies gpg its curses pinentry the same way. Neither OpenSSH < 8.4 nor every pinentry
    honours these, so `PROBE_TIMEOUT` remains the backstop.
    """
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["SSH_ASKPASS"] = "/nonexistent/saw-refuses-to-prompt"
    env.pop("GPG_TTY", None)
    return env


def _first_line(text: str) -> str:
    """git puts the cause first (`error: Couldn't load public key ...`) and the consequence last
    (`fatal: failed to write commit object`), so the first line is the one an operator needs."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""

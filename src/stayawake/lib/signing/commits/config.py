#!/usr/bin/env python3
"""Read the signing settings git resolves for a repository."""
from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from stayawake.lib.git import operator_config
from stayawake.lib.git.run import UNTRUSTED, run
from stayawake.lib.signing.commits.probe import PROBE_TIMEOUT


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


_EXECUTED_PROGRAM_KEYS = (
    "gpg.program",
    "gpg.openpgp.program",
    "gpg.x509.program",
    "gpg.ssh.program",
    "gpg.ssh.defaultkeycommand",
)


def resolved_signing_config(repo: str | Path, *, trust_local_programs: bool = True) -> dict[str, str]:
    """Read the signing settings a commit in `repo` is made with; `trust_local_programs` changes
    nothing. Returns them by key."""
    del trust_local_programs
    operator = operator_config.global_config(repo)
    local: dict[str, str] = {}
    listing = run(repo, ["config", "--list", "-z"], timeout=PROBE_TIMEOUT, context=UNTRUSTED)
    if listing is not None and listing.returncode == 0:
        for entry in listing.stdout.split("\0"):
            key, _, value = entry.partition("\n")
            if key in _SIGNING_CONFIG_KEYS and value:
                local[key] = value
    resolved: dict[str, str] = {}
    for key in _SIGNING_CONFIG_KEYS:
        if key in _EXECUTED_PROGRAM_KEYS:
            continue
        value = local.get(key) or operator.get(key)
        if value:
            resolved[key] = value
    resolved.update(_signer_programs(operator))
    enabled = config_value(repo, "commit.gpgsign", as_bool=True)
    if enabled:
        resolved["commit.gpgsign"] = enabled
    key_path = resolved.get("user.signingkey", "")
    if key_path and not os.path.isabs(key_path) and (Path(repo) / key_path).exists():
        # git resolves a signing-key path against its own cwd, which `-C` moves to the probe
        # repository. Left relative, a working key would probe as broken — a false refusal.
        resolved["user.signingkey"] = str((Path(repo) / key_path).resolve())
    return resolved


def _signer_programs(operator: Mapping[str, str]) -> dict[str, str]:
    """Each program key git may run while signing, set to the operator's global value or git's
    default. An empty `gpg.ssh.defaultkeycommand` runs nothing."""
    openpgp = operator.get("gpg.openpgp.program") or operator.get("gpg.program") or "gpg"
    return {"gpg.program": openpgp,
            "gpg.openpgp.program": openpgp,
            "gpg.x509.program": operator.get("gpg.x509.program") or "gpgsm",
            "gpg.ssh.program": operator.get("gpg.ssh.program") or "ssh-keygen",
            "gpg.ssh.defaultkeycommand": operator.get("gpg.ssh.defaultkeycommand", "")}


def config_value(repo: str | Path, key: str, *, as_bool: bool = False) -> str:
    """Read one setting of `repo`. Takes the key and whether it is a boolean. Returns the value git
    uses, or an empty string when none is set."""
    args = ["config", "--get"] + (["--type=bool"] if as_bool else []) + [key]
    res = run(repo, args, timeout=PROBE_TIMEOUT, context=UNTRUSTED)
    if res is not None and res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    if as_bool:
        return operator_config.global_bool(key, repo)
    return operator_config.global_config(repo).get(key, "")

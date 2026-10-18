#!/usr/bin/env python3
"""Find the keys in the operator's ~/.ssh folder that open without a passphrase."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from stayawake.lib.signing.commits.keys.key import SigningKey, public_key_of
from stayawake.lib.signing.commits.probe import PROBE_TIMEOUT, refuse_to_prompt
from stayawake.utils.systembin import system_binary

_SSH_KEYGEN = ("/usr/bin/ssh-keygen", "/bin/ssh-keygen")
_KEY_FILES = ("id_ed25519", "id_ecdsa", "id_rsa")


def keys_in_ssh_folder(home: Path | None = None) -> list[SigningKey]:
    """List the keys in the `.ssh` folder of `home` that open without a passphrase. Takes the home
    folder, the operator's when not given. Returns them, or an empty list when there are none."""
    ssh_keygen = system_binary(_SSH_KEYGEN)
    if ssh_keygen is None:
        return []
    folder = (home or Path.home()) / ".ssh"
    keys = []
    for name in _KEY_FILES:
        private = folder / name
        public_key = _public_half(ssh_keygen, private)
        if public_key:
            keys.append(SigningKey(public_key, str(private), f"~/.ssh/{name}"))
    return keys


def _public_half(ssh_keygen: str, private: Path) -> str | None:
    """Read the public key of the private key file `private`. Returns it, or None when it cannot be
    read without a passphrase."""
    try:
        if not private.is_file():
            return None
        res = subprocess.run([ssh_keygen, "-y", "-P", "", "-f", str(private)], capture_output=True,
                             text=True, check=False, stdin=subprocess.DEVNULL,
                             timeout=PROBE_TIMEOUT, env=refuse_to_prompt(dict(os.environ)))
    except (OSError, subprocess.SubprocessError):
        return None
    return public_key_of(res.stdout) if res.returncode == 0 else None

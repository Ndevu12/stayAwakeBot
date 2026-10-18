#!/usr/bin/env python3
"""Find the keys loaded in the operator's ssh-agent."""
from __future__ import annotations

import os
import subprocess

from stayawake.lib.signing.commits.keys.key import SigningKey, agent_signing_key, public_key_of
from stayawake.lib.signing.commits.probe import PROBE_TIMEOUT, refuse_to_prompt
from stayawake.utils.systembin import system_binary

_SSH_ADD = ("/usr/bin/ssh-add", "/bin/ssh-add")


def keys_in_agent() -> list[SigningKey]:
    """List the software keys the operator's ssh-agent holds. Returns them, or an empty list when no
    agent answers."""
    ssh_add = system_binary(_SSH_ADD)
    if ssh_add is None or not os.environ.get("SSH_AUTH_SOCK"):
        return []
    try:
        res = subprocess.run([ssh_add, "-L"], capture_output=True, text=True, check=False,
                             stdin=subprocess.DEVNULL, timeout=PROBE_TIMEOUT,
                             env=refuse_to_prompt(dict(os.environ)))
    except (OSError, subprocess.SubprocessError):
        return []
    if res.returncode != 0:
        return []
    keys = []
    for line in res.stdout.splitlines():
        public_key = public_key_of(line)
        if public_key and not public_key.startswith("sk-"):
            keys.append(SigningKey(public_key, agent_signing_key(public_key), "your ssh-agent"))
    return keys

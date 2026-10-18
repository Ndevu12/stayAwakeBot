#!/usr/bin/env python3
"""Find the signing keys the operator already has, with no setup.

Sources, tried in order: ssh_agent · ssh_key_files."""
from stayawake.lib.signing.commits.keys.key import SigningKey, agent_signing_key, public_key_of
from stayawake.lib.signing.commits.keys.ssh_agent import keys_in_agent
from stayawake.lib.signing.commits.keys.ssh_key_files import keys_in_ssh_folder

KEY_SOURCES = (keys_in_agent, keys_in_ssh_folder)


def keys_you_have() -> list[SigningKey]:
    """List the signing keys found on this machine. Returns them in the order they are tried."""
    return [key for source in KEY_SOURCES for key in source()]


__all__ = ["SigningKey", "agent_signing_key", "public_key_of", "keys_in_agent",
           "keys_in_ssh_folder", "KEY_SOURCES", "keys_you_have"]

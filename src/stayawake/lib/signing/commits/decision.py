#!/usr/bin/env python3
"""Decide whether a rewrite must sign, and whether it can."""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.signing.commits.config import resolved_signing_config
from stayawake.lib.signing.commits.keys import SigningKey, keys_you_have, public_key_of
from stayawake.lib.signing.commits.probe import first_probe_failure


@dataclass(frozen=True)
class SigningStatus:
    """Whether a rewrite must sign and whether it can, with the settings that sign."""

    required: bool
    available: bool
    reason: str
    signature_format: str
    config: tuple[tuple[str, str], ...] = ()

    @property
    def signature_owed_but_unavailable(self) -> bool:
        """Whether a signature is owed and none can be made."""
        return self.required and not self.available


def signing_status(repo: str | Path, *, history_is_signed: bool = False,
                   trust_local_programs: bool = True,
                   registered_signing_keys: Callable[[], Iterable[str]] | None = None,
                   ) -> SigningStatus:
    """Decide whether a rewrite of `repo` signs. Takes the repository, whether the commits it
    replaces are signed, `trust_local_programs` (which changes nothing) and a reader of the public
    keys GitHub lists as the operator's signing keys. Returns the decision, with the settings that
    sign when a signature can be made."""
    config = resolved_signing_config(repo, trust_local_programs=trust_local_programs)
    signature_format = config.get("gpg.format") or "openpgp"
    carried = tuple(sorted(config.items()))
    asked = config.get("commit.gpgsign") == "true"
    if not (asked or history_is_signed):
        return SigningStatus(
            required=False, available=False, signature_format=signature_format, config=carried,
            reason="nothing here asks for a signature: commit.gpgsign is not true and the commits being "
                   "replaced carry none")
    because = "commit.gpgsign is true" if asked else "the commits being replaced are signed"
    failure = first_probe_failure(config)
    if failure is None:
        return SigningStatus(
            required=True, available=True, signature_format=signature_format, config=carried,
            reason=f"a test {signature_format} signature was produced")
    found = _a_key_you_have(config, registered_signing_keys)
    if found is not None:
        key, settings = found
        return SigningStatus(
            required=True, available=True, signature_format="ssh",
            config=tuple(sorted(settings.items())),
            reason=f"a test ssh signature was produced with the key in {key.found_in}")
    return SigningStatus(
        required=True, available=False, signature_format=signature_format, config=carried,
        reason=f"{because} but no {signature_format} signature could be produced: {failure}")


def _a_key_you_have(config: Mapping[str, str],
                    registered_signing_keys: Callable[[], Iterable[str]] | None,
                    ) -> tuple[SigningKey, dict[str, str]] | None:
    """Find a key on this machine that GitHub lists as the operator's signing key and that signs.
    Takes the resolved signing settings and the reader of GitHub's list. Returns the key and the
    settings that sign with it, or None when there is none."""
    if registered_signing_keys is None:
        return None
    listed = {public_key_of(key) for key in registered_signing_keys() or ()} - {None}
    if not listed:
        return None
    for key in keys_you_have():
        if key.public_key not in listed:
            continue
        settings = {**config, "gpg.format": "ssh", "user.signingkey": key.signing_key}
        if first_probe_failure(settings) is None:
            return key, settings
    return None


def signing_available(repo: str | Path, *, history_is_signed: bool = False) -> tuple[bool, str]:
    """Tell whether a rewrite of `repo` signs. Takes the repository and whether the commits it
    replaces are signed. Returns whether it signs, and why."""
    status = signing_status(repo, history_is_signed=history_is_signed)
    return status.available, status.reason

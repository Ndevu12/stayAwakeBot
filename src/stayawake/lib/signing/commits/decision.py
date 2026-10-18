#!/usr/bin/env python3
"""Decide whether a rewrite must sign, and whether it can."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from stayawake.lib.signing.commits.config import resolved_signing_config
from stayawake.lib.signing.commits.probe import first_probe_failure



@dataclass(frozen=True)
class SigningStatus:
    """What this repository's signing configuration can actually do, established by making a
    real throwaway signature — never by reading `commit.gpgsign` and believing it."""

    required: bool
    available: bool
    reason: str
    signature_format: str
    config: tuple[tuple[str, str], ...] = ()
    """The signing keys git resolved, carried so the rewrite can be given them explicitly. A
    replay runs in a throwaway worktree on its own branch, where an `includeIf "onbranch:"` or a
    per-worktree config resolves differently from where the probe ran — passing what was proven
    makes the rewrite independent of where it executes."""

    @property
    def must_refuse(self) -> bool:
        """The hard refusal condition: signatures are needed here and cannot be produced. The
        caller checks this BEFORE the first ref moves; rewriting anyway would replace signed
        history with unsigned commits that keep their original authors."""
        return self.required and not self.available


def signing_status(repo: str | Path, *, history_is_signed: bool = False,
                   trust_local_programs: bool = True) -> SigningStatus:
    """Whether `repo` needs to sign AND can prove it, with a reason either way.

    `history_is_signed` is the caller's answer to "do the commits I am about to replace carry
    signatures" — pass it and a repository whose config never asked to sign still signs, rather
    than silently stripping what it found. Runs a git subprocess and a real signing attempt, so
    hold the result and pass it around rather than calling this once per commit.

    The signer program is always the operator's global one or git's default, never `repo`'s
    (see `resolved_signing_config`); `trust_local_programs` is accepted and ignored.
    """
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
    return SigningStatus(
        required=True, available=False, signature_format=signature_format, config=carried,
        reason=f"{because} but no {signature_format} signature could be produced: {failure}")


def signing_available(repo: str | Path, *, history_is_signed: bool = False) -> tuple[bool, str]:
    """`(will this rewrite be signed, why not)` — the two-value form.

    False also covers "no signature is needed here", because the probe only runs once something
    asks for one. A caller that has to tell "nothing asked" apart from "asked and broken" needs
    `signing_status`: only the second is a refusal.
    """
    status = signing_status(repo, history_is_signed=history_is_signed)
    return status.available, status.reason

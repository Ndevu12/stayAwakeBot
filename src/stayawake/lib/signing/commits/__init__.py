#!/usr/bin/env python3
"""Sign the commits saw writes, with the operator's own key.

Split per concern: requirement · config · probe · keys · decision · git_command · identity."""
from stayawake.lib.signing.commits.decision import SigningStatus, signing_available, signing_status
from stayawake.lib.signing.commits.git_command import (fix_commit_signing, sign_flags, signing_args,
                                                       signing_env)
from stayawake.lib.signing.commits.identity import committer_identity, signer_pinned
from stayawake.lib.signing.commits.probe import PROBE_TIMEOUT
from stayawake.lib.signing.commits.requirement import any_signed, carries_signature

__all__ = ["SigningStatus", "signing_status", "signing_available", "fix_commit_signing", "sign_flags",
           "signing_args", "signing_env", "committer_identity", "signer_pinned", "PROBE_TIMEOUT",
           "any_signed", "carries_signature"]

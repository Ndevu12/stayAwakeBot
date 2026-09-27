#!/usr/bin/env python3
"""Let a test push to, fetch from and list a remote that is a local directory.

saw accepts only the network transports in `contexts.OPERATOR_TRANSPORTS` for a remote: a local
path would run that repository's own hooks on this host. A test standing a directory in for the
remote widens the policy for its own duration, through the one place saw reads it.
"""
from __future__ import annotations

import unittest
from unittest import mock

from stayawake.lib.git import contexts


def allow_local_remotes(case: unittest.TestCase) -> None:
    """Accept `file` remotes until `case` ends."""
    widened = mock.patch.object(contexts, "OPERATOR_TRANSPORTS",
                                (*contexts.OPERATOR_TRANSPORTS, "file"))
    widened.start()
    case.addCleanup(widened.stop)

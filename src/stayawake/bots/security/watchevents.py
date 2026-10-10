#!/usr/bin/env python3
"""What a watcher pass can find, and the sentence that says each one."""
from __future__ import annotations

ENDED, RETURNED, LEFT, UNNAMED, QUIET = "ended", "returned", "left", "unnamed", "quiet"
NOT_READ, PASS_FAILED, NOT_REMEMBERED = "not-read", "pass-failed", "not-remembered"

_ENDED = "Code running on this machine was stopped."
_RETURNED = "It has been stopped here before and is running again. Take this machine off the network."
_LEFT = "Something running here could not be stopped. Run `saw harden`."
_UNNAMED = "Something is running that this machine cannot identify."
_QUIET = "Nothing on this machine is running code it should not."
_NOT_READ = "Running processes could not be examined, so nothing here covers one."
_PASS_FAILED = "This machine could not check itself. Run `saw watch status`."
_NOT_REMEMBERED = ("This machine could not keep its record of what it stopped, so code that comes "
                   "back may not be recognised. Run `saw audit`.")

SENTENCE_FOR = {ENDED: _ENDED, RETURNED: _RETURNED, LEFT: _LEFT, UNNAMED: _UNNAMED, QUIET: _QUIET,
                NOT_READ: _NOT_READ, PASS_FAILED: _PASS_FAILED, NOT_REMEMBERED: _NOT_REMEMBERED}

#!/usr/bin/env python3
"""The commands worth a prompt before an agent runs them."""
from __future__ import annotations

import re

RISKY = frozenset({"npx", "npm", "pnpm", "yarn", "node", "ssh", "scp", "curl", "wget",
                   "bash", "sh", "zsh", "eval", "sed", "awk", "python", "python3", "rm",
                   "sudo", "chmod", "chown", "dd", "nc", "openssl", "gh"})

ORDER = tuple(sorted(RISKY))

_INSIDE_A_TOOL = re.compile(r"^\s*\w+\(([^)]*)\)\s*$")

_LEADING_ENV = re.compile(r"^\w+=[^\s]*$")


def invoked_by(rule: str) -> str | None:
    """The command a standing approval rule actually lets an agent run, or None."""
    inner = _INSIDE_A_TOOL.match(rule)
    payload = inner.group(1) if inner else rule
    if ":" in payload and not inner:
        payload = payload.split(":", 1)[0]
    for token in payload.replace(":", " ").split():
        if _LEADING_ENV.match(token):
            continue
        name = token.rsplit("/", 1)[-1].strip("\"'")
        return name or None
    return None


def named_in(rule: str) -> list[str]:
    """The risky command `rule` grants, as a list of zero or one."""
    name = invoked_by(rule)
    return [name] if name in RISKY else []


def named_anywhere(text: str) -> list[str]:
    """Every risky command name appearing as a whole word in `text`, in a stable order."""
    words = set(re.findall(r"[A-Za-z0-9_.\-]+", text.lower()))
    return [name for name in ORDER if name in words]

#!/usr/bin/env python3
"""What a finding is and where it was found, in the words saw shows a person."""
from __future__ import annotations

from functools import lru_cache

from stayawake.bots.security.signatures import load_signatures

_WHAT_IT_IS: dict[str, str] = {
    "agent-autorun": "an AI-assistant hook that runs a command",
    "camouflage": "content disguised to hide an infection",
    "code-loader": "hidden code that loads and runs a payload",
    "destructive": "code that deletes your files",
    "evil-merge": "a merge commit that adds code of its own",
    "exfil": "a trace of a known worm",
    "fake-font": "a payload disguised as a font or image",
    "git-exec": "a command git runs for this repository",
    "git-marker": "entries a worm adds to .gitignore",
    "npm-lifecycle": "an install script that runs code",
    "remediation-residue": "files an earlier cleanup left behind",
    "runner-persistence": "a self-hosted CI runner registration",
    "supply-chain-dep": "a known-malicious package",
    "supply-chain-vuln": "a dependency with a known vulnerability",
    "symlink-escape": "a link that points outside the repository",
    "symlink-write-redirect": "a link that points at a sensitive file",
    "vscode-autorun": "an editor task that runs when the folder opens",
    "workflow-autorun": "a CI workflow that can run untrusted code",
}
_ANY_OTHER = "a sign of infection"


def what_it_is(signature_id: str, category: str) -> str:
    """Name what a finding is. Takes its signature and category. Returns the signature's words, or
    the category's when the signature has none."""
    return _shown_as().get(signature_id) or _WHAT_IT_IS.get(category, _ANY_OTHER)


def _shown_as() -> dict[str, str]:
    """Read the words of each packaged signature. Returns them by signature, or none when the
    signatures cannot be read."""
    try:
        return _packaged_words()
    except (OSError, ValueError):
        return {}


@lru_cache(maxsize=1)
def _packaged_words() -> dict[str, str]:
    """Read the words of each packaged signature once. Returns them by signature."""
    return {s["id"]: s["shown_as"] for group in load_signatures().values() for s in group
            if isinstance(s.get("shown_as"), str)}


def described(signature_id: str, category: str, description: str | None) -> str:
    """Say what a finding is, for a report. Takes its signature, category and description. Returns
    the description saw wrote for this finding, or the finding's words when it carries only its
    signature's own description."""
    if description and description != _signature_descriptions().get(signature_id):
        return description
    return what_it_is(signature_id, category)


def _signature_descriptions() -> dict[str, str]:
    """Read the description of each packaged signature. Returns them by signature, or none when
    the signatures cannot be read."""
    try:
        return _packaged_descriptions()
    except (OSError, ValueError):
        return {}


@lru_cache(maxsize=1)
def _packaged_descriptions() -> dict[str, str]:
    """Read the description of each packaged signature once. Returns them by signature."""
    return {s["id"]: s["description"] for group in load_signatures().values() for s in group}


def is_a_commit(path: str | None, commit_sha: str | None) -> bool:
    """Tell whether a finding is a commit. Takes its path and commit. Returns the answer."""
    return bool(commit_sha and path and commit_sha.startswith(path))


def where_it_is(path: str, line: int | None, commit_sha: str | None) -> str:
    """Name where a finding is. Takes its path, line and commit. Returns `path:line`, or the commit
    when the finding is a commit."""
    if is_a_commit(path, commit_sha):
        return f"commit {path}"
    return f"{path}:{line}" if line else path
